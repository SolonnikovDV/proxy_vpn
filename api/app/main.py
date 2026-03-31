import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any, Optional
import json

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel
try:
    import docker
    from docker.errors import DockerException, NotFound
except Exception:  # pragma: no cover - optional runtime dependency
    docker = None
    DockerException = Exception
    NotFound = Exception

from app.config import settings

SESSION_COOKIE = "proxy_vpn_session"
CSRF_COOKIE = "proxy_vpn_csrf"
CSRF_HEADER = "x-csrf-token"
PBKDF2_ITERATIONS = 150_000
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_MINUTES = 10
LOGIN_LOCK_MINUTES = 15
ONLINE_WINDOW_SECONDS = 300
METRICS_SAMPLE_INTERVAL_SECONDS = 10
WG_DUMP_PATH = "/wireguard-config/wg_dump.txt"
XRAY_STATS_PATH = "/xray-config/stats_raw.txt"
XRAY_CONFIG_PATH = "/xray-config/config.json"
XRAY_CLIENT_INFO_PATH = "/xray-config/client-connection.txt"
DEPLOY_HISTORY_PATH = os.getenv("DEPLOY_HISTORY_PATH", "/logs/deploy-history.log")
XRAY_USER_STATS_RE = re.compile(r"user>>>(.+?)>>>traffic>>>(uplink|downlink)")
XRAY_CONTAINER_NAME = "proxy-vpn-xray"
STACK_CONTAINERS = [
    "proxy-vpn-caddy",
    "proxy-vpn-api",
    XRAY_CONTAINER_NAME,
    "proxy-vpn-wireguard",
]
_METRICS_THREAD_LOCK = threading.Lock()
_METRICS_THREAD_STARTED = False


@asynccontextmanager
async def app_lifespan(_: FastAPI):
    startup()
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=app_lifespan,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _db_path() -> str:
    if not settings.database_url.startswith("sqlite:///"):
        raise RuntimeError("Only sqlite database_url is supported in this build.")
    raw = settings.database_url.replace("sqlite:///", "", 1)
    if raw.startswith("/"):
        return raw
    return str((Path(__file__).resolve().parents[2] / raw).resolve())


def _db_connect() -> sqlite3.Connection:
    con = sqlite3.connect(_db_path())
    con.row_factory = sqlite3.Row
    return con


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.app_secret_key, salt="proxy-vpn-session")


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def _verify_password(password: str, hashed: str) -> bool:
    try:
        algo, iters, salt, digest = hashed.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        new_digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iters)).hex()
        return hmac.compare_digest(new_digest, digest)
    except ValueError:
        return False


def _set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=settings.session_max_age_seconds,
        httponly=False,
        samesite="lax",
        secure=False,
        path="/",
    )


def _ensure_csrf(request: Request) -> None:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    header_token = request.headers.get(CSRF_HEADER, "")
    if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")


def _issue_session_cookie(response: Response, request: Request, user: dict[str, Any]) -> None:
    sid = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    expires_at = (_now() + timedelta(seconds=settings.session_max_age_seconds)).isoformat()
    with _db_connect() as con:
        con.execute(
            """
            INSERT INTO sessions (sid, user_id, role, csrf_token, ip, user_agent, revoked, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                sid,
                user["id"],
                user["role"],
                csrf_token,
                _client_ip(request),
                request.headers.get("user-agent", ""),
                _now().isoformat(),
                expires_at,
            ),
        )
        con.execute("UPDATE sessions SET last_seen = ? WHERE sid = ?", (_now().isoformat(), sid))
        con.commit()
    token = _serializer().dumps({"sid": sid, "uid": user["id"], "role": user["role"]})
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    _set_csrf_cookie(response, csrf_token)


def _revoke_session(request: Request) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return
    try:
        payload = _serializer().loads(token, max_age=settings.session_max_age_seconds)
    except BadSignature:
        return
    sid = payload.get("sid")
    if not sid:
        return
    with _db_connect() as con:
        con.execute("UPDATE sessions SET revoked = 1 WHERE sid = ?", (sid,))
        con.commit()


def _read_current_user(request: Request) -> Optional[dict[str, Any]]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        payload = _serializer().loads(token, max_age=settings.session_max_age_seconds)
    except BadSignature:
        return None
    sid = payload.get("sid")
    user_id = payload.get("uid")
    if not sid or not user_id:
        return None
    with _db_connect() as con:
        srow = con.execute(
            """
            SELECT sid, user_id, role, csrf_token, revoked, expires_at
            FROM sessions WHERE sid = ?
            """,
            (sid,),
        ).fetchone()
        if not srow:
            return None
        if srow["revoked"] == 1:
            return None
        if datetime.fromisoformat(srow["expires_at"]) < _now():
            return None
        row = con.execute(
            "SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        con.execute("UPDATE sessions SET last_seen = ? WHERE sid = ?", (_now().isoformat(), sid))
        con.commit()
    if not row or row["is_active"] != 1:
        return None
    user = dict(row)
    user["session_id"] = sid
    user["csrf_token"] = srow["csrf_token"]
    return user


def _require_user(request: Request) -> dict[str, Any]:
    user = _read_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


def _require_admin(request: Request) -> dict[str, Any]:
    user = _require_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _is_login_locked(username: str, ip: str) -> tuple[bool, int]:
    with _db_connect() as con:
        row = con.execute(
            "SELECT fail_count, first_fail_at, lock_until FROM login_attempts WHERE username = ? AND ip = ?",
            (username, ip),
        ).fetchone()
    if not row:
        return False, 0
    if row["lock_until"]:
        lock_until = datetime.fromisoformat(row["lock_until"])
        if lock_until > _now():
            return True, int((lock_until - _now()).total_seconds())
    return False, 0


def _register_failed_login(username: str, ip: str) -> None:
    with _db_connect() as con:
        row = con.execute(
            "SELECT fail_count, first_fail_at FROM login_attempts WHERE username = ? AND ip = ?",
            (username, ip),
        ).fetchone()
        now = _now()
        if not row:
            con.execute(
                """
                INSERT INTO login_attempts (username, ip, fail_count, first_fail_at, lock_until)
                VALUES (?, ?, 1, ?, NULL)
                """,
                (username, ip, now.isoformat()),
            )
        else:
            first_fail = datetime.fromisoformat(row["first_fail_at"])
            if now - first_fail > timedelta(minutes=LOGIN_WINDOW_MINUTES):
                fail_count = 1
                first_fail = now
            else:
                fail_count = int(row["fail_count"]) + 1
            lock_until = None
            if fail_count >= LOGIN_MAX_ATTEMPTS:
                lock_until = (now + timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat()
                fail_count = 0
                first_fail = now
            con.execute(
                """
                UPDATE login_attempts
                SET fail_count = ?, first_fail_at = ?, lock_until = ?
                WHERE username = ? AND ip = ?
                """,
                (fail_count, first_fail.isoformat(), lock_until, username, ip),
            )
        con.commit()


def _reset_failed_login(username: str, ip: str) -> None:
    with _db_connect() as con:
        con.execute("DELETE FROM login_attempts WHERE username = ? AND ip = ?", (username, ip))
        con.commit()


def _ensure_column(con: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = [r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in columns:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def _read_proc_mem_percent() -> float:
    try:
        mem_total = 0.0
        mem_available = 0.0
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = float(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_available = float(line.split()[1])
        if mem_total <= 0:
            return 0.0
        used = max(0.0, mem_total - mem_available)
        return round((used / mem_total) * 100.0, 2)
    except Exception:
        return 0.0


def _read_proc_net_bytes() -> tuple[int, int]:
    try:
        rx_total = 0
        tx_total = 0
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.readlines()[2:]
        for line in lines:
            parts = line.replace(":", " ").split()
            if len(parts) < 17:
                continue
            iface = parts[0]
            if iface == "lo":
                continue
            rx_total += int(parts[1])
            tx_total += int(parts[9])
        return rx_total, tx_total
    except Exception:
        return 0, 0


def _collect_system_snapshot() -> dict[str, Any]:
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        load1, load5, load15 = 0.0, 0.0, 0.0
    cpu_count = max(1, os.cpu_count() or 1)
    load_pct = round(min(100.0, (load1 / cpu_count) * 100.0), 2)
    disk = os.statvfs("/")
    disk_total = disk.f_blocks * disk.f_frsize
    disk_free = disk.f_bavail * disk.f_frsize
    disk_used = max(0, disk_total - disk_free)
    disk_used_pct = round((disk_used / disk_total) * 100.0, 2) if disk_total > 0 else 0.0
    rx_bytes, tx_bytes = _read_proc_net_bytes()
    return {
        "ts": _now().isoformat(),
        "load1": round(load1, 4),
        "load5": round(load5, 4),
        "load15": round(load15, 4),
        "cpu_load_pct": load_pct,
        "memory_used_pct": _read_proc_mem_percent(),
        "disk_used_pct": disk_used_pct,
        "net_rx_bytes": int(rx_bytes),
        "net_tx_bytes": int(tx_bytes),
    }


def _service_state(raw_status: str, health: str, exit_code: Optional[int]) -> str:
    if raw_status == "running":
        if health == "unhealthy":
            return "in_error"
        if health == "starting":
            return "pending"
        return "running"
    if raw_status in {"created", "restarting", "removing"}:
        return "pending"
    if raw_status in {"exited", "dead"}:
        return "in_error" if (exit_code or 0) != 0 else "stopped"
    if raw_status in {"paused"}:
        return "pending"
    return "unknown"


def _get_container_statuses() -> dict[str, Any]:
    if docker is None:
        return {
            "status": "degraded",
            "reason": "python docker SDK is not available",
            "items": [],
        }
    try:
        client = docker.from_env()
    except Exception as e:
        return {"status": "degraded", "reason": f"docker unavailable: {e}", "items": []}

    items: list[dict[str, Any]] = []
    try:
        for name in STACK_CONTAINERS:
            try:
                c = client.containers.get(name)
            except NotFound:
                items.append(
                    {
                        "name": name,
                        "state": "stopped",
                        "raw_status": "not_found",
                        "health": "none",
                        "created": None,
                        "started": None,
                        "finished": None,
                        "exit_code": None,
                        "error": "container not found",
                    }
                )
                continue
            state = c.attrs.get("State", {})
            health = (state.get("Health") or {}).get("Status", "none")
            raw_status = str(state.get("Status", "unknown"))
            exit_code = state.get("ExitCode")
            items.append(
                {
                    "name": name,
                    "state": _service_state(raw_status, health, exit_code),
                    "raw_status": raw_status,
                    "health": health,
                    "created": c.attrs.get("Created"),
                    "started": state.get("StartedAt"),
                    "finished": state.get("FinishedAt"),
                    "exit_code": exit_code,
                    "error": state.get("Error", ""),
                }
            )
    except DockerException as e:
        return {"status": "degraded", "reason": f"docker error: {e}", "items": []}
    finally:
        try:
            client.close()
        except Exception:
            pass

    return {"status": "ok", "items": items}


def _get_xray_collector_status() -> dict[str, str]:
    if docker is None:
        return {"state": "degraded", "reason": "docker SDK unavailable in api container"}
    client = None
    try:
        client = docker.from_env()
        container = client.containers.get(XRAY_CONTAINER_NAME)
        state = (container.attrs.get("State") or {}).get("Status", "unknown")
        if state != "running":
            return {"state": "degraded", "reason": f"xray container is {state}"}
        result = container.exec_run(
            ["xray", "api", "statsquery", "--server=127.0.0.1:10085"],
            stdout=False,
            stderr=True,
        )
        exit_code = int(getattr(result, "exit_code", 1))
        if exit_code == 0:
            return {"state": "active", "reason": "statsquery is reachable"}
        output = getattr(result, "output", b"")
        err = output.decode("utf-8", errors="replace").strip() if output else ""
        return {"state": "degraded", "reason": err or f"statsquery exit code {exit_code}"}
    except Exception as e:
        return {"state": "degraded", "reason": str(e)}
    finally:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass


def _read_deploy_history(limit: int = 20) -> dict[str, Any]:
    limit = max(1, min(100, int(limit)))
    path = Path(DEPLOY_HISTORY_PATH)
    if not path.exists():
        return {
            "status": "ok",
            "path": str(path),
            "items": [],
            "reason": "deploy history file not found yet",
        }
    try:
        with path.open("r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        return {"status": "degraded", "path": str(path), "items": [], "reason": f"read error: {e}"}
    rows = lines[-limit:]
    items: list[dict[str, Any]] = []
    for raw in reversed(rows):
        parts = raw.split("|")
        item: dict[str, Any] = {"raw": raw}
        if parts:
            item["ts"] = parts[0]
        for p in parts[1:]:
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            item[k.strip()] = v.strip()
        items.append(item)
    return {"status": "ok", "path": str(path), "items": items}


def _online_user_ids(con: sqlite3.Connection) -> list[int]:
    threshold = (_now() - timedelta(seconds=ONLINE_WINDOW_SECONDS)).isoformat()
    rows = con.execute(
        """
        SELECT DISTINCT user_id
        FROM sessions
        WHERE revoked = 0
          AND expires_at > ?
          AND COALESCE(last_seen, created_at) >= ?
        """,
        (_now().isoformat(), threshold),
    ).fetchall()
    return [int(r["user_id"]) for r in rows]


def _read_wg_dump_totals() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    try:
        with open(WG_DUMP_PATH, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception:
        return result
    # First line is interface data, next lines are peer rows.
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 7:
            parts = line.split()
        if len(parts) < 7:
            continue
        public_key = parts[0]
        try:
            latest_handshake = int(parts[4])
            rx_total = int(parts[5])
            tx_total = int(parts[6])
        except ValueError:
            continue
        allowed_ips = parts[3] if len(parts) > 3 else ""
        result[public_key] = {
            "latest_handshake": latest_handshake,
            "rx_total": rx_total,
            "tx_total": tx_total,
            "allowed_ips": allowed_ips,
        }
    return result


def _collect_wireguard_user_traffic(con: sqlite3.Connection, ts_iso: str) -> None:
    totals = _read_wg_dump_totals()
    if not totals:
        return
    bindings = con.execute(
        """
        SELECT b.user_id, b.public_key, COALESCE(c.last_rx_bytes, -1) AS last_rx_bytes, COALESCE(c.last_tx_bytes, -1) AS last_tx_bytes
        FROM wg_peer_bindings b
        LEFT JOIN wg_peer_counters c ON c.public_key = b.public_key
        """
    ).fetchall()
    for b in bindings:
        pk = b["public_key"]
        t = totals.get(pk)
        if not t:
            continue
        rx_total = int(t["rx_total"])
        tx_total = int(t["tx_total"])
        last_rx = int(b["last_rx_bytes"])
        last_tx = int(b["last_tx_bytes"])
        if last_rx < 0 or last_tx < 0:
            rx_delta = 0
            tx_delta = 0
        else:
            rx_delta = max(0, rx_total - last_rx)
            tx_delta = max(0, tx_total - last_tx)
        if rx_delta > 0 or tx_delta > 0:
            con.execute(
                """
                INSERT INTO user_wireguard_traffic_samples (ts, user_id, public_key, rx_bytes, tx_bytes, rx_total, tx_total)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ts_iso, int(b["user_id"]), pk, rx_delta, tx_delta, rx_total, tx_total),
            )
        con.execute(
            """
            INSERT INTO wg_peer_counters (public_key, last_rx_bytes, last_tx_bytes, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(public_key)
            DO UPDATE SET last_rx_bytes=excluded.last_rx_bytes, last_tx_bytes=excluded.last_tx_bytes, updated_at=excluded.updated_at
            """,
            (pk, rx_total, tx_total, ts_iso),
        )


def _read_xray_user_totals() -> dict[str, dict[str, int]]:
    totals: dict[str, dict[str, int]] = {}
    lines: list[str] = []
    if docker is not None:
        client = None
        try:
            client = docker.from_env()
            container = client.containers.get(XRAY_CONTAINER_NAME)
            result = container.exec_run(
                ["xray", "api", "statsquery", "--server=127.0.0.1:10085"],
                stdout=True,
                stderr=False,
            )
            exit_code = int(getattr(result, "exit_code", 1))
            output = getattr(result, "output", b"")
            if exit_code == 0 and output:
                text = output.decode("utf-8", errors="replace")
                lines = [line.strip() for line in text.splitlines() if line.strip()]
        except Exception:
            lines = []
        finally:
            try:
                if client is not None:
                    client.close()
            except Exception:
                pass

    # Compatibility fallback: use shared file when available.
    if not lines:
        try:
            with open(XRAY_STATS_PATH, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
        except Exception:
            return totals

    for line in lines:
        m = XRAY_USER_STATS_RE.search(line)
        if not m:
            continue
        email, direction = m.group(1), m.group(2)
        parts = line.replace("\t", " ").split()
        bytes_raw = parts[-1] if parts else "0"
        current = totals.setdefault(email, {"uplink": 0, "downlink": 0})
        try:
            current[direction] = int(bytes_raw)
        except ValueError:
            continue
    return totals


def _read_xray_connection_template() -> dict[str, str]:
    result: dict[str, str] = {
        "server_address": "",
        "server_port": "",
        "sni": "",
        "public_key": "",
        "short_id": "",
        "flow": "xtls-rprx-vision",
    }
    try:
        with open(XRAY_CLIENT_INFO_PATH, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line.startswith("Server address:"):
                    result["server_address"] = line.split(":", 1)[1].strip()
                elif line.startswith("Server port:"):
                    result["server_port"] = line.split(":", 1)[1].strip()
                elif line.startswith("SNI:"):
                    result["sni"] = line.split(":", 1)[1].strip()
                elif line.startswith("Public key:"):
                    result["public_key"] = line.split(":", 1)[1].strip()
                elif line.startswith("Short ID:"):
                    result["short_id"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return result


def _ensure_user_xray_profile(user: dict[str, Any]) -> dict[str, str]:
    with _db_connect() as con:
        row = con.execute(
            "SELECT xray_uuid, xray_email FROM user_access_profiles WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
        if row:
            return {"xray_uuid": str(row["xray_uuid"]), "xray_email": str(row["xray_email"])}
        xray_uuid = str(uuid.uuid4())
        username = str(user.get("username", "user")).strip().lower()
        xray_email = f"{username}-{int(user['id'])}@proxy-vpn"
        con.execute(
            """
            INSERT INTO user_access_profiles
            (user_id, xray_uuid, xray_email, last_device_type, last_platform, last_region_profile, created_at, updated_at)
            VALUES (?, ?, ?, 'mobile', 'apple', 'ru', ?, ?)
            """,
            (user["id"], xray_uuid, xray_email, _now().isoformat(), _now().isoformat()),
        )
        con.execute(
            """
            INSERT INTO xray_client_bindings (user_id, client_email, label, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(client_email)
            DO UPDATE SET user_id=excluded.user_id, label=excluded.label
            """,
            (user["id"], xray_email, "auto-profile", _now().isoformat()),
        )
        con.commit()
    return {"xray_uuid": xray_uuid, "xray_email": xray_email}


def _get_user_device_preferences(user_id: int) -> dict[str, str]:
    with _db_connect() as con:
        row = con.execute(
            """
            SELECT last_device_type, last_platform, last_region_profile
            FROM user_access_profiles
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()
    if not row:
        return {"device_type": "mobile", "platform": "apple", "region_profile": "ru"}
    return {
        "device_type": str(row["last_device_type"] or "mobile"),
        "platform": str(row["last_platform"] or "apple"),
        "region_profile": str(row["last_region_profile"] or "ru"),
    }


def _set_user_device_preferences(user_id: int, device_type: str, platform: str, region_profile: str) -> None:
    with _db_connect() as con:
        con.execute(
            """
            UPDATE user_access_profiles
            SET last_device_type = ?, last_platform = ?, last_region_profile = ?, updated_at = ?
            WHERE user_id = ?
            """,
            (device_type, platform, region_profile, _now().isoformat(), user_id),
        )
        con.commit()


def _ensure_xray_client_in_config(xray_uuid: str, xray_email: str) -> None:
    try:
        with open(XRAY_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return
    inbounds = cfg.get("inbounds", [])
    if not inbounds:
        return
    first = inbounds[0]
    settings = first.setdefault("settings", {})
    clients = settings.setdefault("clients", [])
    exists = any(str(c.get("email", "")).strip().lower() == xray_email.lower() for c in clients)
    if exists:
        return
    clients.append({"id": xray_uuid, "flow": "xtls-rprx-vision", "email": xray_email})
    try:
        with open(XRAY_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except Exception:
        return
    if docker is None:
        return
    client = None
    try:
        client = docker.from_env()
        c = client.containers.get(XRAY_CONTAINER_NAME)
        c.restart(timeout=10)
    except Exception:
        pass
    finally:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass


def _collect_xray_user_traffic(con: sqlite3.Connection, ts_iso: str) -> None:
    totals = _read_xray_user_totals()
    if not totals:
        return
    bindings = con.execute(
        """
        SELECT b.user_id, b.client_email, COALESCE(c.last_uplink_bytes, -1) AS last_uplink_bytes, COALESCE(c.last_downlink_bytes, -1) AS last_downlink_bytes
        FROM xray_client_bindings b
        LEFT JOIN xray_client_counters c ON c.client_email = b.client_email
        """
    ).fetchall()
    for b in bindings:
        email = b["client_email"]
        t = totals.get(email)
        if not t:
            continue
        up_total = int(t["uplink"])
        down_total = int(t["downlink"])
        last_up = int(b["last_uplink_bytes"])
        last_down = int(b["last_downlink_bytes"])
        if last_up < 0 or last_down < 0:
            up_delta = 0
            down_delta = 0
        else:
            up_delta = max(0, up_total - last_up)
            down_delta = max(0, down_total - last_down)
        if up_delta > 0 or down_delta > 0:
            con.execute(
                """
                INSERT INTO user_xray_traffic_samples (ts, user_id, client_email, rx_bytes, tx_bytes, downlink_total, uplink_total)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ts_iso, int(b["user_id"]), email, down_delta, up_delta, down_total, up_total),
            )
        con.execute(
            """
            INSERT INTO xray_client_counters (client_email, last_uplink_bytes, last_downlink_bytes, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(client_email)
            DO UPDATE SET last_uplink_bytes=excluded.last_uplink_bytes, last_downlink_bytes=excluded.last_downlink_bytes, updated_at=excluded.updated_at
            """,
            (email, up_total, down_total, ts_iso),
        )


def _metrics_sampler_loop() -> None:
    while True:
        snapshot = _collect_system_snapshot()
        with _db_connect() as con:
            con.execute(
                """
                INSERT INTO metric_samples (ts, load1, load5, load15, cpu_load_pct, memory_used_pct, disk_used_pct, net_rx_bytes, net_tx_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot["ts"],
                    snapshot["load1"],
                    snapshot["load5"],
                    snapshot["load15"],
                    snapshot["cpu_load_pct"],
                    snapshot["memory_used_pct"],
                    snapshot["disk_used_pct"],
                    snapshot["net_rx_bytes"],
                    snapshot["net_tx_bytes"],
                ),
            )
            _collect_wireguard_user_traffic(con, snapshot["ts"])
            _collect_xray_user_traffic(con, snapshot["ts"])
            con.execute(
                """
                DELETE FROM metric_samples
                WHERE ts < datetime('now', '-7 day')
                """
            )
            con.execute(
                """
                DELETE FROM user_traffic_samples
                WHERE ts < datetime('now', '-30 day')
                """
            )
            con.execute(
                """
                DELETE FROM user_wireguard_traffic_samples
                WHERE ts < datetime('now', '-30 day')
                """
            )
            con.execute(
                """
                DELETE FROM user_xray_traffic_samples
                WHERE ts < datetime('now', '-30 day')
                """
            )
            con.commit()
        time.sleep(METRICS_SAMPLE_INTERVAL_SECONDS)


def _start_metrics_sampler_once() -> None:
    global _METRICS_THREAD_STARTED
    with _METRICS_THREAD_LOCK:
        if _METRICS_THREAD_STARTED:
            return
        thread = threading.Thread(target=_metrics_sampler_loop, daemon=True, name="metrics-sampler")
        thread.start()
        _METRICS_THREAD_STARTED = True


def _page(title: str, body: str, active: str = "dashboard", user: Optional[dict[str, Any]] = None) -> HTMLResponse:
    nav_items = [
        ("/login", "login", "Login"),
        ("/cabinet", "cabinet", "User cabinet"),
        ("/admin", "admin", "Admin panel"),
        ("/docs", "docs", "API docs"),
    ]
    if user is None:
        nav_html = "".join(
            [
                f'<a class="nav-item {"active" if key == active else ""}" href="{href}">{label}</a>'
                for href, key, label in nav_items
                if key in {"login", "docs"}
            ]
        )
        profile_html = "<div class='muted'>Not signed in</div>"
    else:
        nav_html = "".join(
            [
                f'<a class="nav-item {"active" if key == active else ""}" href="{href}">{label}</a>'
                for href, key, label in nav_items
                if key != "login"
            ]
        )
        profile_html = (
            f"<div><b>{escape(user['username'])}</b></div>"
            f"<div class='muted'>{escape(user['role'])}</div>"
            f"<button class='btn-ghost' style='margin-top:8px;width:100%;' onclick='sidebarLogout()'>Logout</button>"
        )

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{
      --bg-1: #dbe5f5;
      --bg-2: #f5f7fb;
      --panel: rgba(255, 255, 255, 0.62);
      --panel-strong: rgba(255, 255, 255, 0.84);
      --stroke: rgba(50, 65, 90, 0.18);
      --text: #1f2937;
      --muted: #64748b;
      --blue: #2563eb;
      --shadow: 0 20px 40px rgba(15, 23, 42, 0.16);
    }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(1200px 600px at 10% -20%, #bfd4ff 0%, var(--bg-2) 40%, var(--bg-1) 100%);
      color: var(--text);
      min-height: 100vh;
    }}
    .app {{
      max-width: 1200px;
      margin: 18px auto;
      padding: 0 16px 16px;
      display: grid;
      grid-template-columns: 260px 1fr;
      gap: 14px;
    }}
    .sidebar {{
      background: var(--panel);
      border: 1px solid var(--stroke);
      border-radius: 18px;
      backdrop-filter: blur(14px);
      box-shadow: var(--shadow);
      padding: 14px;
      height: calc(100vh - 52px);
      position: sticky;
      top: 18px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }}
    .window-dots {{
      display: flex;
      gap: 6px;
      margin-bottom: 4px;
    }}
    .dot {{
      width: 11px;
      height: 11px;
      border-radius: 50%;
    }}
    .dot.red {{ background: #ff5f57; }}
    .dot.yellow {{ background: #febc2e; }}
    .dot.green {{ background: #28c840; }}
    .brand {{
      font-size: 17px;
      font-weight: 700;
      margin: 0 0 2px;
    }}
    .nav {{
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    .nav-item {{
      color: var(--text);
      text-decoration: none;
      padding: 9px 10px;
      border-radius: 10px;
      border: 1px solid transparent;
      font-size: 14px;
    }}
    .nav-item:hover {{
      background: rgba(255,255,255,0.6);
      border-color: var(--stroke);
    }}
    .nav-item.active {{
      background: rgba(37, 99, 235, 0.14);
      border-color: rgba(37, 99, 235, 0.32);
      color: #1d4ed8;
      font-weight: 600;
    }}
    .profile {{
      margin-top: auto;
      padding: 10px;
      border-radius: 10px;
      border: 1px solid var(--stroke);
      background: rgba(255,255,255,0.55);
    }}
    .content {{
      min-width: 0;
    }}
    .topbar {{
      background: var(--panel-strong);
      border: 1px solid var(--stroke);
      border-radius: 18px;
      backdrop-filter: blur(10px);
      box-shadow: var(--shadow);
      padding: 14px 16px;
      margin-bottom: 14px;
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
    }}
    .wrap {{
      padding: 0;
    }}
    .card {{
      background: var(--panel-strong);
      border: 1px solid var(--stroke);
      border-radius: 16px;
      padding: 16px;
      margin-bottom: 16px;
      box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);
    }}
    a {{
      color: #1d4ed8;
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    .muted {{
      color: var(--muted);
      font-size: 14px;
    }}
    input {{
      width: 100%;
      box-sizing: border-box;
      margin-bottom: 8px;
      padding: 10px;
      border-radius: 8px;
      border: 1px solid var(--stroke);
      background: rgba(255,255,255,0.76);
      color: var(--text);
    }}
    button {{
      padding: 10px 14px;
      border: 0;
      border-radius: 8px;
      background: var(--blue);
      color: #fff;
      cursor: pointer;
    }}
    pre {{
      white-space: pre-wrap;
      background: rgba(248,250,252,0.9);
      padding: 12px;
      border-radius: 8px;
      border: 1px solid var(--stroke);
      color: #0f172a;
    }}
    table {{
      font-size: 14px;
    }}
    th, td {{
      padding: 8px 6px;
      border-bottom: 1px solid rgba(100, 116, 139, 0.15);
    }}
    .status-pill {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.02em;
    }}
    .status-running {{ background: rgba(22,163,74,0.16); color: #166534; }}
    .status-pending {{ background: rgba(245,158,11,0.18); color: #92400e; }}
    .status-stopped {{ background: rgba(100,116,139,0.18); color: #334155; }}
    .status-in_error {{ background: rgba(239,68,68,0.18); color: #991b1b; }}
    .status-unknown {{ background: rgba(148,163,184,0.2); color: #334155; }}
    .btn-ghost {{
      background: rgba(15,23,42,0.06);
      color: #0f172a;
      border: 1px solid rgba(50,65,90,0.2);
      padding: 7px 10px;
      border-radius: 7px;
      font-size: 12px;
    }}
    .tab-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      padding: 4px;
      border-radius: 12px;
      border: 1px solid rgba(50,65,90,0.16);
      background: rgba(255,255,255,0.65);
    }}
    .tab-btn {{
      background: transparent;
      color: #334155;
      border: 1px solid transparent;
      padding: 8px 12px;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 600;
    }}
    .tab-btn:hover {{
      background: rgba(255,255,255,0.8);
      border-color: rgba(50,65,90,0.2);
    }}
    .tab-btn.active {{
      background: rgba(37,99,235,0.16);
      color: #1d4ed8;
      border-color: rgba(37,99,235,0.34);
    }}
    .user-card {{
      display: grid;
      grid-template-columns: 92px 1fr;
      gap: 14px;
      align-items: start;
    }}
    .user-avatar {{
      width: 92px;
      height: 92px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      font-size: 28px;
      font-weight: 700;
      color: #1e40af;
      background: radial-gradient(circle at 30% 20%, rgba(59,130,246,0.28), rgba(148,163,184,0.15));
      border: 1px solid rgba(59,130,246,0.25);
    }}
    .user-meta-row {{
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 8px;
      padding: 6px 0;
      border-bottom: 1px dashed rgba(100,116,139,0.2);
    }}
    .user-meta-row:last-child {{ border-bottom: 0; }}
    .label-muted {{ color: #64748b; font-size: 13px; }}
    .modal-backdrop {{
      position: fixed;
      inset: 0;
      background: rgba(2, 6, 23, 0.48);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 999;
      padding: 16px;
    }}
    .modal-card {{
      width: min(980px, 100%);
      max-height: 85vh;
      overflow: auto;
      background: #f8fafc;
      border: 1px solid rgba(50,65,90,0.22);
      border-radius: 12px;
      padding: 12px;
      box-shadow: 0 24px 60px rgba(2, 6, 23, 0.35);
    }}
    @media (max-width: 900px) {{
      .app {{
        grid-template-columns: 1fr;
      }}
      .sidebar {{
        height: auto;
        position: static;
      }}
    }}
  </style>
</head>
<body>
  <div class="app">
    <aside class="sidebar">
      <div class="window-dots">
        <span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span>
      </div>
      <div class="brand">proxy-vpn</div>
      <div class="muted">Control center</div>
      <nav class="nav">{nav_html}</nav>
      <div class="profile">{profile_html}</div>
    </aside>
    <main class="content">
      <div class="topbar">
        <div><strong>{title}</strong></div>
      </div>
      <div class="wrap">{body}</div>
    </main>
  </div>
</body>
<script>
function sidebarCsrfToken() {{
  const m = document.cookie.match(/(?:^|; )proxy_vpn_csrf=([^;]+)/);
  return m && m[1] ? decodeURIComponent(m[1]) : '';
}}
async function sidebarLogout() {{
  await fetch('/api/v1/auth/logout', {{method:'POST', headers:{{'X-CSRF-Token': sidebarCsrfToken()}}}});
  window.location.href = '/';
}}
</script>
</html>"""
    return HTMLResponse(content=html, status_code=200)


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class AdminCreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"


class AdminBindWireGuardRequest(BaseModel):
    user_id: int
    public_key: str
    label: str = ""


class AdminBindXrayClientRequest(BaseModel):
    user_id: int
    client_email: str
    label: str = ""


class UserProfileUpdateRequest(BaseModel):
    username: str
    email: str
    password: str = ""


def startup() -> None:
    db_path = _db_path()
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _db_connect() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role in ('admin', 'user')),
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                sid TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                csrf_token TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(con, "sessions", "last_seen", "last_seen TEXT")
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT NOT NULL,
                ip TEXT NOT NULL,
                fail_count INTEGER NOT NULL,
                first_fail_at TEXT NOT NULL,
                lock_until TEXT,
                PRIMARY KEY (username, ip)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS metric_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                load1 REAL NOT NULL,
                load5 REAL NOT NULL,
                load15 REAL NOT NULL,
                cpu_load_pct REAL NOT NULL,
                memory_used_pct REAL NOT NULL,
                disk_used_pct REAL NOT NULL,
                net_rx_bytes INTEGER NOT NULL,
                net_tx_bytes INTEGER NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS user_traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                rx_bytes INTEGER NOT NULL,
                tx_bytes INTEGER NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS wg_peer_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                public_key TEXT UNIQUE NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS wg_peer_counters (
                public_key TEXT PRIMARY KEY,
                last_rx_bytes INTEGER NOT NULL,
                last_tx_bytes INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS user_wireguard_traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                public_key TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL,
                tx_bytes INTEGER NOT NULL,
                rx_total INTEGER NOT NULL,
                tx_total INTEGER NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS xray_client_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_email TEXT UNIQUE NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS xray_client_counters (
                client_email TEXT PRIMARY KEY,
                last_uplink_bytes INTEGER NOT NULL,
                last_downlink_bytes INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS user_xray_traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                client_email TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL,
                tx_bytes INTEGER NOT NULL,
                downlink_total INTEGER NOT NULL,
                uplink_total INTEGER NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS user_access_profiles (
                user_id INTEGER PRIMARY KEY,
                xray_uuid TEXT UNIQUE NOT NULL,
                xray_email TEXT UNIQUE NOT NULL,
                last_device_type TEXT NOT NULL DEFAULT 'mobile',
                last_platform TEXT NOT NULL DEFAULT 'apple',
                last_region_profile TEXT NOT NULL DEFAULT 'ru',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(con, "user_access_profiles", "last_device_type", "last_device_type TEXT NOT NULL DEFAULT 'mobile'")
        _ensure_column(con, "user_access_profiles", "last_platform", "last_platform TEXT NOT NULL DEFAULT 'apple'")
        _ensure_column(
            con, "user_access_profiles", "last_region_profile", "last_region_profile TEXT NOT NULL DEFAULT 'ru'"
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS registration_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status in ('pending', 'approved', 'rejected')),
                requested_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by INTEGER,
                review_note TEXT
            )
            """
        )
        row = con.execute("SELECT id FROM users WHERE username = ?", (settings.admin_username,)).fetchone()
        if not row:
            con.execute(
                """
                INSERT INTO users (username, email, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, 'admin', 1, ?)
                """,
                (
                    settings.admin_username,
                    settings.admin_email,
                    _hash_password(settings.admin_password),
                    _now().isoformat(),
                ),
            )
        con.commit()
    _start_metrics_sampler_once()


@app.get("/", response_class=HTMLResponse)
def landing(request: Request) -> HTMLResponse:
    user = _read_current_user(request)
    auth_block = (
        f'<p>Signed in as <b>{escape(user["username"])}</b> ({escape(user["role"])})</p>'
        if user
        else '<p><a href="/login">Login / Register</a></p>'
    )
    return _page(
        "proxy-vpn panel",
        f"""
<div class="card">
  <h1>proxy-vpn</h1>
  <p class="muted">Production-like local UI: auth, RBAC, CSRF, session revocation and brute-force protection.</p>
  {auth_block}
  <p><a href="/cabinet">User cabinet</a> | <a href="/admin">Admin panel</a> | <a href="/docs">API docs</a></p>
</div>
<div class="card">
  <h2>Service status</h2>
  <p class="muted">Human-readable service dashboard is available in <a href="/admin">Admin panel</a> -> Overview.</p>
  <p class="muted">Raw JSON endpoints are still available for automation: <a href="/health">/health</a>, <a href="/api/v1/meta">/api/v1/meta</a>.</p>
</div>
""",
        active="dashboard",
        user=user,
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    user = _read_current_user(request)
    return _page(
        "proxy-vpn login",
        """
<div class="card">
  <h1>Login</h1>
  <input id="login-username" placeholder="username" />
  <input id="login-password" placeholder="password" type="password" />
  <button onclick="login()">Sign in</button>
  <p class="muted">Default admin from env: admin / admin123!</p>
</div>
<div class="card">
  <h2>Register</h2>
  <input id="reg-username" placeholder="username" />
  <input id="reg-email" placeholder="email" />
  <input id="reg-password" placeholder="password" type="password" />
  <button onclick="registerUser()">Create account</button>
  <p class="muted">Registration goes to pending state and requires admin approval.</p>
</div>
<div class="card">
  <h2>Output</h2>
  <pre id="out">Ready.</pre>
</div>
<script>
let csrfToken = '';
async function initCsrf() {
  const r = await fetch('/api/v1/auth/csrf');
  const j = await r.json();
  csrfToken = j.csrf_token || '';
}
initCsrf();
async function login() {
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  const r = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
    body: JSON.stringify({username, password})
  });
  const t = await r.text();
  document.getElementById('out').textContent = t;
  if (r.ok) window.location.href = '/cabinet';
}
async function registerUser() {
  const username = document.getElementById('reg-username').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;
  const r = await fetch('/api/v1/auth/register', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
    body: JSON.stringify({username, email, password})
  });
  document.getElementById('out').textContent = await r.text();
}
</script>
""",
        active="login",
        user=user,
    )


@app.get("/cabinet", response_class=HTMLResponse)
def cabinet(request: Request) -> HTMLResponse:
    user = _read_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=307)
    initials = (user["username"][:2] if user.get("username") else "U").upper()
    return _page(
        "proxy-vpn user cabinet",
        f"""
<div class="card">
  <div class="user-card">
    <div class="user-avatar">{escape(initials)}</div>
    <div>
      <h1 style="margin:0 0 4px;">User card</h1>
      <p class="muted" style="margin:0 0 10px;">Current profile state</p>
      <div class="user-meta-row"><div class="label-muted">Username</div><div><b id="cab-current-username">{escape(user["username"])}</b></div></div>
      <div class="user-meta-row"><div class="label-muted">Email</div><div><b id="cab-current-email">{escape(user["email"])}</b></div></div>
      <div class="user-meta-row"><div class="label-muted">Role</div><div><span class="status-pill status-running">{escape(user["role"])}</span></div></div>
      <div style="margin-top:10px;">
        <button onclick="openEditProfileModal()">Edit profile</button>
      </div>
    </div>
  </div>
</div>
<div class="card">
  <h2>Device setup</h2>
  <p class="muted">Choose your device and get ready-to-use proxy/vpn config + install instructions.</p>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px;align-items:end;">
    <div>
      <div class="label-muted">Device type</div>
      <select id="dev-type" style="width:100%;padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">
        <option value="mobile">mobile</option>
        <option value="desktop">desktop</option>
      </select>
    </div>
    <div>
      <div class="label-muted">Platform</div>
      <select id="dev-platform" style="width:100%;padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);"></select>
    </div>
    <div>
      <div class="label-muted">Region profile</div>
      <select id="dev-region" style="width:100%;padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">
        <option value="ru">RU</option>
        <option value="global">Global</option>
      </select>
    </div>
    <button onclick="loadDeviceCard()">Load card</button>
  </div>
  <div id="device-card-out" style="margin-top:12px;"></div>
</div>
<div id="edit-profile-modal" class="modal-backdrop" onclick="closeEditProfileModal(event)">
  <div class="modal-card" onclick="event.stopPropagation()">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
      <strong>Edit profile</strong>
      <button class="btn-ghost" onclick="closeEditProfileModal()">Close</button>
    </div>
    <div style="margin-top:10px;">
      <input id="cab-username" placeholder="username" value="{escape(user["username"])}" />
      <input id="cab-email" placeholder="email" value="{escape(user["email"])}" />
      <input id="cab-password" placeholder="new password (optional)" type="password" />
      <button onclick="saveProfile()">Save changes</button>
      <pre id="cab-out">Ready.</pre>
    </div>
  </div>
</div>
<script>
const csrfToken = {repr(user["csrf_token"])};
const escHtml = (s) => String(s ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
function getCsrfToken() {{
  const m = document.cookie.match(/(?:^|; )proxy_vpn_csrf=([^;]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  return csrfToken;
}}
function openEditProfileModal() {{
  const modal = document.getElementById('edit-profile-modal');
  if (modal) modal.style.display = 'flex';
}}
function closeEditProfileModal(event) {{
  if (event && event.target && event.target.id !== 'edit-profile-modal') return;
  const modal = document.getElementById('edit-profile-modal');
  if (modal) modal.style.display = 'none';
}}
function refreshPlatformOptions() {{
  const type = document.getElementById('dev-type').value;
  const platformEl = document.getElementById('dev-platform');
  if (!platformEl) return;
  const options = type === 'mobile' ? ['apple', 'android'] : ['apple', 'linux', 'windows'];
  platformEl.innerHTML = options.map(o => `<option value="${{o}}">${{o}}</option>`).join('');
}}
function renderDeviceCard(card) {{
  const out = document.getElementById('device-card-out');
  if (!out) return;
  if (!card) {{
    out.innerHTML = '<p class="muted">No card data.</p>';
    return;
  }}
  const lines = (card.instructions || []).map((s, i) => `<li>${{i + 1}}. ${{escHtml(s)}}</li>`).join('');
  const primary = card.primary_client || {{}};
  const installUrl = escHtml(primary.install_url || '#');
  const source = escHtml(primary.source || 'source');
  const clientName = escHtml(primary.name || card.client_app || 'Client');
  out.innerHTML = `
    <div class="card" style="margin-bottom:0;">
      <h3 style="margin-top:0;">${{escHtml(card.title || 'Configuration')}}</h3>
      <p class="muted">Protocol: <b>${{escHtml(card.protocol || '-')}}</b> · Recommended app: <b>${{clientName}}</b></p>
      <p class="muted" style="margin:6px 0 8px;">${{escHtml(card.client_about || 'Free client for importing VLESS URI and connecting in VPN/proxy mode.')}}</p>
      <div class="user-meta-row"><div class="label-muted">Config URI</div><div><code id="cfg-uri" style="word-break:break-all;">${{escHtml(card.config_uri || '')}}</code></div></div>
      <div style="margin-top:8px;">
        <button class="btn-ghost" onclick="copyConfigUri()">Copy URI</button>
      </div>
      <div style="margin-top:8px;">
        <a href="${{installUrl}}" target="_blank" rel="noopener noreferrer"><button>Install ${{clientName}}</button></a>
        <span class="status-pill status-stopped" style="margin-left:8px;">${{source}}</span>
      </div>
      <h4 style="margin:12px 0 6px;">Instructions</h4>
      <ul style="margin:0 0 4px 14px;padding:0;">${{lines}}</ul>
    </div>
  `;
}}
async function copyConfigUri() {{
  const el = document.getElementById('cfg-uri');
  if (!el) return;
  await navigator.clipboard.writeText(el.textContent || '');
}}
async function loadDeviceCard() {{
  const type = document.getElementById('dev-type').value;
  const platform = document.getElementById('dev-platform').value;
  const region = document.getElementById('dev-region').value;
  const out = document.getElementById('device-card-out');
  if (out) out.innerHTML = '<p class="muted">Loading...</p>';
  const r = await fetch('/api/v1/user/device-config?device_type=' + encodeURIComponent(type) + '&platform=' + encodeURIComponent(platform) + '&region_profile=' + encodeURIComponent(region));
  const t = await r.text();
  if (!r.ok) {{
    if (out) out.innerHTML = '<pre>' + escHtml(t) + '</pre>';
    return;
  }}
  let j = null;
  try {{ j = JSON.parse(t); }} catch (e) {{ j = null; }}
  renderDeviceCard(j ? j.card : null);
}}
async function initDeviceCard() {{
  const out = document.getElementById('device-card-out');
  if (out) out.innerHTML = '<p class="muted">Loading...</p>';
  const r = await fetch('/api/v1/user/device-config');
  const t = await r.text();
  if (!r.ok) {{
    if (out) out.innerHTML = '<pre>' + escHtml(t) + '</pre>';
    return;
  }}
  let j = null;
  try {{ j = JSON.parse(t); }} catch (e) {{ j = null; }}
  if (!j) {{
    if (out) out.innerHTML = '<p class="muted">No card data.</p>';
    return;
  }}
  const typeEl = document.getElementById('dev-type');
  const platformEl = document.getElementById('dev-platform');
  const regionEl = document.getElementById('dev-region');
  if (typeEl && j.device_type) typeEl.value = j.device_type;
  refreshPlatformOptions();
  if (platformEl && j.platform) platformEl.value = j.platform;
  if (regionEl && j.region_profile) regionEl.value = j.region_profile;
  renderDeviceCard(j.card || null);
}}
async function saveProfile() {{
  const username = document.getElementById('cab-username').value.trim();
  const email = document.getElementById('cab-email').value.trim();
  const password = document.getElementById('cab-password').value;
  const payload = {{username, email}};
  if (password) payload.password = password;
  const r = await fetch('/api/v1/user/profile', {{
    method:'POST',
    headers: {{'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()}},
    body: JSON.stringify(payload)
  }});
  const t = await r.text();
  document.getElementById('cab-out').textContent = t;
  if (r.ok) {{
    const nameEl = document.getElementById('cab-current-username');
    const emailEl = document.getElementById('cab-current-email');
    if (nameEl) nameEl.textContent = username;
    if (emailEl) emailEl.textContent = email;
    closeEditProfileModal();
  }}
}}
document.getElementById('dev-type').addEventListener('change', () => {{
  refreshPlatformOptions();
  loadDeviceCard();
}});
document.getElementById('dev-region').addEventListener('change', () => {{
  loadDeviceCard();
}});
refreshPlatformOptions();
initDeviceCard();
</script>
""",
        active="cabinet",
        user=user,
    )


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request) -> HTMLResponse:
    user = _read_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=307)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    with _db_connect() as con:
        pending_rows = con.execute(
            """
            SELECT id, username, email, requested_at
            FROM registration_requests
            WHERE status = 'pending'
            ORDER BY requested_at ASC
            """
        ).fetchall()
        users_rows = con.execute(
            """
            SELECT id, username, email, role, is_active, created_at
            FROM users
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()
        wg_bind_rows = con.execute(
            """
            SELECT b.public_key, b.label, b.created_at, u.id user_id, u.username, u.email,
                   COALESCE(c.last_rx_bytes, 0) last_rx_bytes, COALESCE(c.last_tx_bytes, 0) last_tx_bytes
            FROM wg_peer_bindings b
            JOIN users u ON u.id = b.user_id
            LEFT JOIN wg_peer_counters c ON c.public_key = b.public_key
            ORDER BY b.id DESC
            """
        ).fetchall()
        xray_bind_rows = con.execute(
            """
            SELECT b.client_email, b.label, b.created_at, u.id user_id, u.username, u.email,
                   COALESCE(c.last_downlink_bytes, 0) last_downlink_bytes, COALESCE(c.last_uplink_bytes, 0) last_uplink_bytes
            FROM xray_client_bindings b
            JOIN users u ON u.id = b.user_id
            LEFT JOIN xray_client_counters c ON c.client_email = b.client_email
            ORDER BY b.id DESC
            """
        ).fetchall()

    pending_html = "".join(
        [
            f"<tr>"
            f"<td>{row['id']}</td>"
            f"<td>{escape(row['username'])}</td>"
            f"<td>{escape(row['email'])}</td>"
            f"<td>{escape(row['requested_at'])}</td>"
            f"<td>"
            f"<button onclick=\"approveReq({row['id']})\">Approve</button> "
            f"<button onclick=\"rejectReq({row['id']})\">Reject</button>"
            f"</td>"
            f"</tr>"
            for row in pending_rows
        ]
    )
    if not pending_html:
        pending_html = "<tr><td colspan='5' class='muted'>No pending requests</td></tr>"

    users_html = "".join(
        [
            f"<tr>"
            f"<td>{escape(row['username'])}</td>"
            f"<td>{escape(row['email'])}</td>"
            f"<td>{escape(row['role'])}</td>"
            f"<td>{'active' if int(row['is_active']) == 1 else 'blocked'}</td>"
            f"<td>{escape(row['created_at'])}</td>"
            f"<td>"
            + (
                "<span class='muted'>self</span>"
                if int(row["id"]) == int(user["id"])
                else (
                    f"<button class='btn-ghost' onclick='blockUser({int(row['id'])})'>Block</button> "
                    if int(row["is_active"]) == 1
                    else f"<button class='btn-ghost' onclick='unblockUser({int(row['id'])})'>Unblock</button> "
                )
            )
            + (
                ""
                if int(row["id"]) == int(user["id"])
                else f"<button class='btn-ghost' onclick='deleteUser({int(row['id'])}, \"{escape(row['username'])}\")'>Delete</button>"
            )
            + "</td>"
            f"</tr>"
            for row in users_rows
        ]
    )
    if not users_html:
        users_html = "<tr><td colspan='6' class='muted'>No users yet</td></tr>"

    user_options_html = "".join(
        [f"<option value='{row['id']}'>{escape(row['username'])} ({escape(row['role'])})</option>" for row in users_rows]
    )
    if not user_options_html:
        user_options_html = "<option value=''>No users</option>"

    wg_bindings_html = "".join(
        [
            f"<tr>"
            f"<td>{escape(row['username'])}</td>"
            f"<td><code style='font-size:12px'>{escape(row['public_key'])}</code></td>"
            f"<td>{escape(row['label'] or '')}</td>"
            f"<td>RX {row['last_rx_bytes']} / TX {row['last_tx_bytes']}</td>"
            f"<td><button onclick=\"removeWgBinding('{escape(row['public_key'])}')\">Unbind</button></td>"
            f"</tr>"
            for row in wg_bind_rows
        ]
    )
    if not wg_bindings_html:
        wg_bindings_html = "<tr><td colspan='5' class='muted'>No WG peer bindings yet</td></tr>"

    xray_bindings_html = "".join(
        [
            f"<tr>"
            f"<td>{escape(row['username'])}</td>"
            f"<td><code style='font-size:12px'>{escape(row['client_email'])}</code></td>"
            f"<td>{escape(row['label'] or '')}</td>"
            f"<td>RX {row['last_downlink_bytes']} / TX {row['last_uplink_bytes']}</td>"
            f"<td><button onclick=\"removeXrayBinding('{escape(row['client_email'])}')\">Unbind</button></td>"
            f"</tr>"
            for row in xray_bind_rows
        ]
    )
    if not xray_bindings_html:
        xray_bindings_html = "<tr><td colspan='5' class='muted'>No Xray client bindings yet</td></tr>"

    return _page(
        "proxy-vpn admin panel",
        f"""
<div class="card">
  <div class="tab-strip" id="admin-tabs">
    <button class="tab-btn" data-tab="overview" onclick="showSection('overview')">Overview</button>
    <button class="tab-btn" data-tab="approvals" onclick="showSection('approvals')">Approvals</button>
    <button class="tab-btn" data-tab="users" onclick="showSection('users')">Users</button>
    <button class="tab-btn" data-tab="traffic" onclick="showSection('traffic')">Traffic</button>
    <button class="tab-btn" data-tab="logs" onclick="showSection('logs')">Logs</button>
  </div>
</div>

<div class="card admin-section" data-section="overview">
  <h2>Realtime system overview</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;">
    <div><div class="muted">Online users</div><div id="m-online" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">CPU load</div><div id="m-cpu" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">Memory used</div><div id="m-mem" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">Disk used</div><div id="m-disk" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">Traffic 24h</div><div id="m-traffic" style="font-size:16px;font-weight:700;">-</div></div>
  </div>
  <p class="muted" id="m-avg">avg: -</p>
</div>

<div class="card admin-section" data-section="overview">
  <h2>CPU / Memory trend (last 60 min)</h2>
  <canvas id="metrics-canvas" width="900" height="220" style="width:100%;max-width:100%;border:1px solid rgba(100,116,139,0.2);border-radius:10px;background:rgba(255,255,255,0.6);"></canvas>
</div>

<div class="card admin-section" data-section="overview">
  <h2>Users online now</h2>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Username</th><th align="left">Email</th><th align="left">Role</th><th align="left">Sessions</th><th align="left">Last seen</th></tr>
    </thead>
    <tbody id="online-users-body"><tr><td colspan="5" class="muted">Loading...</td></tr></tbody>
  </table>
</div>

<div class="card admin-section" data-section="overview">
  <h2>Service health dashboard</h2>
  <p class="muted">Container states are read from Docker runtime. Click "Logs" for pending/error containers.</p>
  <p id="xray-collector-state" class="muted">xray exact collector: -</p>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Container</th><th align="left">State</th><th align="left">Runtime</th><th align="left">Health</th><th align="left">Action</th></tr>
    </thead>
    <tbody id="services-body"><tr><td colspan="5" class="muted">Loading...</td></tr></tbody>
  </table>
  <p class="muted" id="services-meta"></p>
</div>

<div class="card admin-section" data-section="overview">
  <h2>Last deploy events</h2>
  <p class="muted">Recent deploy/rollback events from deploy history log.</p>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Time (UTC)</th><th align="left">Source</th><th align="left">Status</th><th align="left">From</th><th align="left">To</th><th align="left">Details</th></tr>
    </thead>
    <tbody id="deploy-events-body"><tr><td colspan="6" class="muted">Loading...</td></tr></tbody>
  </table>
  <p class="muted" id="deploy-events-meta"></p>
</div>

<div class="card admin-section" data-section="approvals">
  <h2>Pending registration approvals</h2>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">ID</th><th align="left">Username</th><th align="left">Email</th><th align="left">Requested</th><th align="left">Actions</th></tr>
    </thead>
    <tbody>{pending_html}</tbody>
  </table>
</div>

<div class="card admin-section" data-section="users">
  <h2>User management</h2>
  <p class="muted">Create user/admin account from modal form.</p>
  <button onclick="openCreateUserModal()">Create user/admin</button>
</div>

<div class="card admin-section" data-section="users">
  <h2>Recent users</h2>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Username</th><th align="left">Email</th><th align="left">Role</th><th align="left">State</th><th align="left">Created</th><th align="left">Actions</th></tr>
    </thead>
    <tbody>{users_html}</tbody>
  </table>
</div>

<div class="card admin-section" data-section="traffic">
  <h2>WireGuard peer bindings (exact accounting source)</h2>
  <p class="muted">Bind each WireGuard public key to an app user. Then traffic is calculated from real WG counters.</p>
  <div style="display:grid;grid-template-columns:2fr 3fr 2fr auto;gap:8px;align-items:center;">
    <select id="wg-bind-user" style="padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">{user_options_html}</select>
    <input id="wg-bind-key" placeholder="WireGuard peer public key" />
    <input id="wg-bind-label" placeholder="label (optional)" />
    <button onclick="bindWgPeer()">Bind</button>
  </div>
  <table style="width:100%; border-collapse:collapse; margin-top:10px;">
    <thead>
      <tr><th align="left">User</th><th align="left">Public key</th><th align="left">Label</th><th align="left">Last totals</th><th align="left">Action</th></tr>
    </thead>
    <tbody id="wg-bindings-body">{wg_bindings_html}</tbody>
  </table>
</div>

<div class="card admin-section" data-section="traffic">
  <h2>Xray client bindings (exact accounting source)</h2>
  <p class="muted">Bind each Xray client email (from Xray config) to an app user. Data comes from Xray StatsService counters.</p>
  <div style="display:grid;grid-template-columns:2fr 3fr 2fr auto;gap:8px;align-items:center;">
    <select id="xray-bind-user" style="padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">{user_options_html}</select>
    <input id="xray-bind-email" placeholder="Xray client email (e.g. user1@proxy-vpn)" />
    <input id="xray-bind-label" placeholder="label (optional)" />
    <button onclick="bindXrayClient()">Bind</button>
  </div>
  <table style="width:100%; border-collapse:collapse; margin-top:10px;">
    <thead>
      <tr><th align="left">User</th><th align="left">Client email</th><th align="left">Label</th><th align="left">Last totals</th><th align="left">Action</th></tr>
    </thead>
    <tbody id="xray-bindings-body">{xray_bindings_html}</tbody>
  </table>
</div>

<div class="card admin-section" data-section="traffic">
  <h2>Per-user traffic (WG + Xray exact)</h2>
  <p class="muted">Data is based on WireGuard/Xray counters and binding tables above.</p>
  <p class="muted" id="traffic-source">source: -</p>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">User</th><th align="left">Email</th><th align="left">Role</th><th align="left">RX 24h</th><th align="left">TX 24h</th><th align="left">Total 24h</th></tr>
    </thead>
    <tbody id="user-traffic-body"><tr><td colspan="6" class="muted">Loading...</td></tr></tbody>
  </table>
</div>

<div class="card admin-section" data-section="logs">
  <h2>Admin actions log</h2>
  <pre id="admin-out">Ready.</pre>
</div>
<div id="create-user-modal" class="modal-backdrop" onclick="closeCreateUserModal(event)">
  <div class="modal-card" onclick="event.stopPropagation()">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
      <strong>Create user/admin</strong>
      <button class="btn-ghost" onclick="closeCreateUserModal()">Close</button>
    </div>
    <div style="margin-top:10px;">
      <input id="new-username" placeholder="username" />
      <input id="new-email" placeholder="email" />
      <input id="new-password" placeholder="password" type="password" />
      <select id="new-role" style="width:100%;padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);margin-bottom:8px;">
        <option value="user">user</option>
        <option value="admin">admin</option>
      </select>
      <button onclick="createUser()">Create account</button>
      <pre id="create-user-out" style="margin-top:8px;">Ready.</pre>
    </div>
  </div>
</div>
<div id="service-log-modal" class="modal-backdrop" onclick="closeServiceLogs(event)">
  <div class="modal-card" onclick="event.stopPropagation()">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
      <strong id="service-log-title">Container logs</strong>
      <div style="display:flex;align-items:center;gap:8px;">
        <label class="muted" style="display:flex;align-items:center;gap:6px;">
          <input id="service-log-stderr-only" type="checkbox" style="width:auto;margin:0;" onchange="refreshServiceLogsNow()" />
          stderr only
        </label>
        <button class="btn-ghost" onclick="refreshServiceLogsNow()">Refresh now</button>
        <button class="btn-ghost" onclick="closeServiceLogs()">Close</button>
      </div>
    </div>
    <pre id="service-log-content" style="margin-top:10px;max-height:65vh;overflow:auto;">Loading...</pre>
  </div>
</div>
<script>
const csrfToken = {repr(user["csrf_token"])};
let currentServiceLogContainer = '';
let serviceLogsIntervalId = null;
const escHtml = (s) => String(s ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
function getCsrfToken() {{
  const m = document.cookie.match(/(?:^|; )proxy_vpn_csrf=([^;]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  return csrfToken;
}}
function showSection(section) {{
  document.querySelectorAll('.admin-section').forEach(el => {{
    el.style.display = (el.dataset.section === section) ? 'block' : 'none';
  }});
  document.querySelectorAll('#admin-tabs .tab-btn').forEach(btn => {{
    const isActive = btn.dataset.tab === section;
    btn.classList.toggle('active', isActive);
  }});
}}
const fmtBytes = (n) => {{
  if (!Number.isFinite(n)) return '-';
  const units = ['B','KB','MB','GB','TB'];
  let i = 0; let v = n;
  while (v >= 1024 && i < units.length - 1) {{ v /= 1024; i++; }}
  return v.toFixed(i === 0 ? 0 : 2) + ' ' + units[i];
}};
function stateBadge(state) {{
  const cls = ['running','pending','stopped','in_error','unknown'].includes(state) ? state : 'unknown';
  return `<span class="status-pill status-${{cls}}">${{cls}}</span>`;
}}
function deployStatusBadge(status) {{
  const s = String(status || 'unknown');
  let cls = 'unknown';
  if (['success', 'rollback_ok', 'noop'].includes(s)) cls = 'running';
  else if (['started'].includes(s)) cls = 'pending';
  else if (s.startsWith('failed')) cls = 'in_error';
  return `<span class="status-pill status-${{cls}}">${{escHtml(s)}}</span>`;
}}
function renderServices(items, xrayCollector) {{
  const body = document.getElementById('services-body');
  const meta = document.getElementById('services-meta');
  const collector = document.getElementById('xray-collector-state');
  if (!body) return;
  if (collector) {{
    if (xrayCollector && xrayCollector.state) {{
      const badge = xrayCollector.state === 'active'
        ? '<span class="status-pill status-running">active</span>'
        : '<span class="status-pill status-in_error">degraded</span>';
      collector.innerHTML = 'xray exact collector: ' + badge + (xrayCollector.reason ? (' - ' + escHtml(xrayCollector.reason)) : '');
    }} else {{
      collector.textContent = 'xray exact collector: -';
    }}
  }}
  if (!items || items.length === 0) {{
    body.innerHTML = '<tr><td colspan="5" class="muted">Docker socket unavailable or no containers found.</td></tr>';
    if (meta) meta.textContent = 'Tip: mount /var/run/docker.sock into api container.';
    return;
  }}
  body.innerHTML = items.map(i => {{
    const action = (i.state === 'pending' || i.state === 'in_error')
      ? `<button class="btn-ghost" onclick="openServiceLogs('${{escHtml(i.name)}}')">Logs</button>`
      : '<span class="muted">-</span>';
    const runtime = `${{escHtml(i.raw_status || '-')}}${{i.exit_code !== null && i.exit_code !== undefined ? (' (code ' + i.exit_code + ')') : ''}}`;
    return `<tr>
      <td><code>${{escHtml(i.name)}}</code></td>
      <td>${{stateBadge(i.state)}}</td>
      <td>${{runtime}}</td>
      <td>${{escHtml(i.health || 'none')}}</td>
      <td>${{action}}</td>
    </tr>`;
  }}).join('');
  if (meta) meta.textContent = 'Click Logs for pending/error containers. Tail: 120 lines.';
}}
function renderDeployEvents(items, path, reason) {{
  const body = document.getElementById('deploy-events-body');
  const meta = document.getElementById('deploy-events-meta');
  if (!body) return;
  if (!items || items.length === 0) {{
    body.innerHTML = '<tr><td colspan="6" class="muted">No deploy events yet.</td></tr>';
    if (meta) meta.textContent = (reason || 'History file is empty.') + (path ? (' Path: ' + path) : '');
    return;
  }}
  body.innerHTML = items.map(i => `<tr>
    <td>${{escHtml(i.ts || '-')}}</td>
    <td>${{escHtml(i.source || '-')}}</td>
    <td>${{deployStatusBadge(i.status)}}</td>
    <td><code>${{escHtml(i.from || '-')}}</code></td>
    <td><code>${{escHtml(i.to || '-')}}</code></td>
    <td>${{escHtml(i.details || i.raw || '-')}}</td>
  </tr>`).join('');
  if (meta) meta.textContent = 'Source file: ' + (path || '-') + ' | showing latest ' + items.length + ' events';
}}
async function openServiceLogs(containerName) {{
  currentServiceLogContainer = containerName;
  const modal = document.getElementById('service-log-modal');
  const title = document.getElementById('service-log-title');
  const content = document.getElementById('service-log-content');
  if (!modal || !title || !content) return;
  modal.style.display = 'flex';
  title.textContent = 'Container logs: ' + containerName;
  refreshServiceLogsNow();
  if (serviceLogsIntervalId) clearInterval(serviceLogsIntervalId);
  serviceLogsIntervalId = setInterval(refreshServiceLogsNow, 2000);
}}
async function refreshServiceLogsNow() {{
  const content = document.getElementById('service-log-content');
  const stderrOnlyEl = document.getElementById('service-log-stderr-only');
  if (!content || !currentServiceLogContainer) return;
  const stderrOnly = !!(stderrOnlyEl && stderrOnlyEl.checked);
  content.textContent = 'Loading...';
  const query = stderrOnly ? '?tail=120&stderr_only=true' : '?tail=120';
  const r = await fetch('/api/v1/admin/services/' + encodeURIComponent(currentServiceLogContainer) + '/logs' + query);
  if (!r.ok) {{
    content.textContent = await r.text();
    return;
  }}
  const j = await r.json();
  content.textContent = j.logs || 'No logs';
}}
function closeServiceLogs(event) {{
  if (event && event.target && event.target.id !== 'service-log-modal') return;
  const modal = document.getElementById('service-log-modal');
  if (modal) modal.style.display = 'none';
  if (serviceLogsIntervalId) {{
    clearInterval(serviceLogsIntervalId);
    serviceLogsIntervalId = null;
  }}
  currentServiceLogContainer = '';
}}
function openCreateUserModal() {{
  const modal = document.getElementById('create-user-modal');
  if (modal) modal.style.display = 'flex';
}}
function closeCreateUserModal(event) {{
  if (event && event.target && event.target.id !== 'create-user-modal') return;
  const modal = document.getElementById('create-user-modal');
  if (modal) modal.style.display = 'none';
}}
function renderUserTraffic(items) {{
  const body = document.getElementById('user-traffic-body');
  if (!items || items.length === 0) {{
    body.innerHTML = '<tr><td colspan="6" class="muted">No data</td></tr>';
    return;
  }}
  body.innerHTML = items.map(i => {{
    const rx = Number(i.rx_bytes || 0);
    const tx = Number(i.tx_bytes || 0);
    const total = rx + tx;
    return `<tr>
      <td>${{i.username}}</td>
      <td>${{i.email}}</td>
      <td>${{i.role}}</td>
      <td>${{fmtBytes(rx)}}</td>
      <td>${{fmtBytes(tx)}}</td>
      <td>${{fmtBytes(total)}}</td>
    </tr>`;
  }}).join('');
}}
function drawMetrics(points) {{
  const canvas = document.getElementById('metrics-canvas');
  if (!canvas || !points || points.length < 2) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height, pad = 24;
  ctx.clearRect(0, 0, w, h);
  const valuesCpu = points.map(p => Number(p.cpu_load_pct || 0));
  const valuesMem = points.map(p => Number(p.memory_used_pct || 0));
  const maxY = Math.max(100, ...valuesCpu, ...valuesMem);
  const x = (i) => pad + (i / (points.length - 1)) * (w - pad * 2);
  const y = (v) => h - pad - (v / maxY) * (h - pad * 2);
  ctx.strokeStyle = 'rgba(100,116,139,0.4)';
  ctx.beginPath(); ctx.moveTo(pad, h - pad); ctx.lineTo(w - pad, h - pad); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(pad, pad); ctx.lineTo(pad, h - pad); ctx.stroke();
  ctx.strokeStyle = '#2563eb';
  ctx.lineWidth = 2;
  ctx.beginPath();
  valuesCpu.forEach((v, i) => {{ if (i === 0) ctx.moveTo(x(i), y(v)); else ctx.lineTo(x(i), y(v)); }});
  ctx.stroke();
  ctx.strokeStyle = '#16a34a';
  ctx.beginPath();
  valuesMem.forEach((v, i) => {{ if (i === 0) ctx.moveTo(x(i), y(v)); else ctx.lineTo(x(i), y(v)); }});
  ctx.stroke();
  ctx.fillStyle = '#1f2937';
  ctx.font = '12px -apple-system';
  ctx.fillText('CPU %', pad + 8, pad + 12);
  ctx.fillStyle = '#16a34a';
  ctx.fillText('MEM %', pad + 60, pad + 12);
}}
async function refreshAdminLive() {{
  const [statsR, onlineR, tsR, trafficR, servicesR, deployEventsR] = await Promise.all([
    fetch('/api/v1/admin/stats'),
    fetch('/api/v1/admin/online-users'),
    fetch('/api/v1/admin/system-metrics/timeseries?minutes=60'),
    fetch('/api/v1/admin/user-traffic/summary?hours=24'),
    fetch('/api/v1/admin/services/status'),
    fetch('/api/v1/admin/deploy-events?limit=12')
  ]);
  if (statsR.ok) {{
    const s = (await statsR.json()).stats || {{}};
    document.getElementById('m-online').textContent = String(s.active_sessions ?? '-');
    document.getElementById('m-cpu').textContent = `${{Number(s.current_cpu_load_pct || 0).toFixed(1)}}%`;
    document.getElementById('m-mem').textContent = `${{Number(s.current_memory_used_pct || 0).toFixed(1)}}%`;
    document.getElementById('m-disk').textContent = `${{Number(s.current_disk_used_pct || 0).toFixed(1)}}%`;
    document.getElementById('m-traffic').textContent = `RX ${{fmtBytes(Number(s.traffic_rx_24h_bytes || 0))}} / TX ${{fmtBytes(Number(s.traffic_tx_24h_bytes || 0))}}`;
    document.getElementById('m-avg').textContent = `avg 1h: CPU ${{Number(s.avg_cpu_1h_pct || 0).toFixed(1)}}% · MEM ${{Number(s.avg_mem_1h_pct || 0).toFixed(1)}}%`;
  }}
  if (onlineR.ok) {{
    const j = await onlineR.json();
    const body = document.getElementById('online-users-body');
    if (!j.items || j.items.length === 0) {{
      body.innerHTML = '<tr><td colspan="5" class="muted">No online users</td></tr>';
    }} else {{
      body.innerHTML = j.items.map(i => `<tr>
        <td>${{i.username}}</td><td>${{i.email}}</td><td>${{i.role}}</td><td>${{i.sessions}}</td><td>${{i.last_seen || '-'}}</td>
      </tr>`).join('');
    }}
  }}
  if (tsR.ok) {{
    const t = await tsR.json();
    drawMetrics(t.points || []);
  }}
  if (trafficR.ok) {{
    const t = await trafficR.json();
    renderUserTraffic(t.items || []);
    const src = document.getElementById('traffic-source');
    if (src) src.textContent = 'source: ' + (t.source || '-');
  }}
  if (servicesR.ok) {{
    const s = await servicesR.json();
    renderServices(s.items || [], s.xray_collector || null);
    const meta = document.getElementById('services-meta');
    if (meta && s.reason) meta.textContent = s.reason;
  }}
  if (deployEventsR.ok) {{
    const d = await deployEventsR.json();
    renderDeployEvents(d.items || [], d.path || '', d.reason || '');
  }}
}}
async function bindWgPeer() {{
  const userId = Number(document.getElementById('wg-bind-user').value || 0);
  const publicKey = document.getElementById('wg-bind-key').value.trim();
  const label = document.getElementById('wg-bind-label').value.trim();
  const r = await fetch('/api/v1/admin/wireguard-bindings', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()}},
    body: JSON.stringify({{user_id: userId, public_key: publicKey, label}})
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
async function removeWgBinding(publicKey) {{
  const r = await fetch('/api/v1/admin/wireguard-bindings/' + encodeURIComponent(publicKey), {{
    method: 'DELETE',
    headers: {{'X-CSRF-Token': getCsrfToken()}}
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
async function bindXrayClient() {{
  const userId = Number(document.getElementById('xray-bind-user').value || 0);
  const clientEmail = document.getElementById('xray-bind-email').value.trim();
  const label = document.getElementById('xray-bind-label').value.trim();
  const r = await fetch('/api/v1/admin/xray-bindings', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()}},
    body: JSON.stringify({{user_id: userId, client_email: clientEmail, label}})
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
async function removeXrayBinding(clientEmail) {{
  const r = await fetch('/api/v1/admin/xray-bindings/' + encodeURIComponent(clientEmail), {{
    method: 'DELETE',
    headers: {{'X-CSRF-Token': getCsrfToken()}}
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
async function approveReq(id) {{
  const r = await fetch('/api/v1/admin/registration-requests/' + id + '/approve', {{
    method: 'POST',
    headers: {{'X-CSRF-Token': getCsrfToken()}}
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
async function rejectReq(id) {{
  const r = await fetch('/api/v1/admin/registration-requests/' + id + '/reject', {{
    method: 'POST',
    headers: {{'X-CSRF-Token': getCsrfToken()}}
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
async function createUser() {{
  const username = document.getElementById('new-username').value;
  const email = document.getElementById('new-email').value;
  const password = document.getElementById('new-password').value;
  const role = document.getElementById('new-role').value;
  const out = document.getElementById('create-user-out');
  if (out) out.textContent = 'Sending...';
  const r = await fetch('/api/v1/admin/users/create', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()}},
    body: JSON.stringify({{username, email, password, role}})
  }});
  const body = await r.text();
  if (out) out.textContent = body;
  document.getElementById('admin-out').textContent = body;
  if (r.ok) {{
    closeCreateUserModal();
    window.location.reload();
  }}
}}
async function blockUser(userId) {{
  const r = await fetch('/api/v1/admin/users/' + userId + '/block', {{
    method: 'POST',
    headers: {{'X-CSRF-Token': getCsrfToken()}}
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
async function unblockUser(userId) {{
  const r = await fetch('/api/v1/admin/users/' + userId + '/unblock', {{
    method: 'POST',
    headers: {{'X-CSRF-Token': getCsrfToken()}}
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
async function deleteUser(userId, username) {{
  if (!confirm('Delete user "' + username + '" permanently?')) return;
  const r = await fetch('/api/v1/admin/users/' + userId, {{
    method: 'DELETE',
    headers: {{'X-CSRF-Token': getCsrfToken()}}
  }});
  document.getElementById('admin-out').textContent = await r.text();
  if (r.ok) window.location.reload();
}}
refreshAdminLive();
showSection('overview');
setInterval(refreshAdminLive, 10000);
</script>
""",
        active="admin",
        user=user,
    )


@app.get("/api/v1/auth/csrf")
def csrf_token() -> JSONResponse:
    token = secrets.token_urlsafe(24)
    resp = JSONResponse({"status": "ok", "csrf_token": token})
    _set_csrf_cookie(resp, token)
    return resp


@app.post("/api/v1/auth/register")
def register(request: Request, payload: RegisterRequest) -> JSONResponse:
    _ensure_csrf(request)
    if "@" not in payload.email:
        raise HTTPException(status_code=400, detail="Invalid email")
    if len(payload.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="Username is too short")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 chars")
    username = payload.username.strip().lower()
    with _db_connect() as con:
        exists_user = con.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, payload.email.lower()),
        ).fetchone()
        if exists_user:
            raise HTTPException(status_code=409, detail="User already exists")
        exists_pending = con.execute(
            """
            SELECT id FROM registration_requests
            WHERE (username = ? OR email = ?) AND status = 'pending'
            """,
            (username, payload.email.lower()),
        ).fetchone()
        if exists_pending:
            raise HTTPException(status_code=409, detail="Registration request is already pending")
        con.execute(
            """
            INSERT INTO registration_requests (username, email, password_hash, status, requested_at)
            VALUES (?, ?, ?, 'pending', ?)
            """,
            (
                username,
                payload.email.lower(),
                _hash_password(payload.password),
                _now().isoformat(),
            ),
        )
        con.commit()
    return JSONResponse({"status": "ok", "message": "registration request submitted, waiting for admin approval"})


@app.post("/api/v1/auth/login")
def login(request: Request, payload: LoginRequest) -> JSONResponse:
    _ensure_csrf(request)
    username = payload.username.strip().lower()
    ip = _client_ip(request)
    locked, wait_seconds = _is_login_locked(username, ip)
    if locked:
        raise HTTPException(status_code=429, detail=f"Too many attempts. Retry in {wait_seconds}s")
    with _db_connect() as con:
        row = con.execute(
            "SELECT id, username, email, password_hash, role, is_active FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not row or row["is_active"] != 1 or not _verify_password(payload.password, row["password_hash"]):
        _register_failed_login(username, ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    _reset_failed_login(username, ip)
    _revoke_session(request)
    user = {k: row[k] for k in ["id", "username", "email", "role", "is_active"]}
    resp = JSONResponse({"status": "ok", "user": {"username": user["username"], "role": user["role"]}})
    _issue_session_cookie(resp, request, user)
    return resp


@app.post("/api/v1/auth/logout")
def logout(request: Request) -> JSONResponse:
    _ensure_csrf(request)
    _revoke_session(request)
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    resp.delete_cookie(CSRF_COOKIE, path="/")
    return resp


@app.post("/api/v1/auth/logout-all")
def logout_all(request: Request) -> JSONResponse:
    _ensure_csrf(request)
    user = _require_user(request)
    with _db_connect() as con:
        con.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user["id"],))
        con.commit()
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    resp.delete_cookie(CSRF_COOKIE, path="/")
    return resp


@app.get("/api/v1/auth/me")
def me(request: Request) -> JSONResponse:
    user = _require_user(request)
    return JSONResponse({"status": "ok", "user": user})


@app.post("/api/v1/user/profile")
def update_user_profile(request: Request, payload: UserProfileUpdateRequest) -> JSONResponse:
    _ensure_csrf(request)
    user = _require_user(request)
    username = payload.username.strip().lower()
    email = payload.email.strip().lower()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username is too short")
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    if payload.password and len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 chars")
    with _db_connect() as con:
        exists = con.execute(
            "SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?",
            (username, email, user["id"]),
        ).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="Username or email is already in use")
        if payload.password:
            con.execute(
                """
                UPDATE users
                SET username = ?, email = ?, password_hash = ?
                WHERE id = ?
                """,
                (username, email, _hash_password(payload.password), user["id"]),
            )
        else:
            con.execute(
                """
                UPDATE users
                SET username = ?, email = ?
                WHERE id = ?
                """,
                (username, email, user["id"]),
            )
        con.commit()
    return JSONResponse({"status": "ok", "message": "profile updated"})


@app.get("/api/v1/user/device-config")
def user_device_config(
    request: Request,
    device_type: Optional[str] = None,
    platform: Optional[str] = None,
    region_profile: Optional[str] = None,
) -> JSONResponse:
    user = _require_user(request)
    prefs_seed = _ensure_user_xray_profile(user)
    prefs = _get_user_device_preferences(int(user["id"]))
    device_type = (device_type or prefs["device_type"]).strip().lower()
    platform = (platform or prefs["platform"]).strip().lower()
    region_profile = (region_profile or prefs["region_profile"]).strip().lower()
    if device_type not in {"mobile", "desktop"}:
        raise HTTPException(status_code=400, detail="device_type must be mobile or desktop")
    allowed = {"mobile": {"apple", "android"}, "desktop": {"apple", "linux", "windows"}}
    if platform not in allowed[device_type]:
        platform = "apple" if device_type == "mobile" else "windows"
    if region_profile not in {"ru", "global"}:
        region_profile = "ru"

    profile = prefs_seed
    _set_user_device_preferences(int(user["id"]), device_type, platform, region_profile)
    _ensure_xray_client_in_config(profile["xray_uuid"], profile["xray_email"])
    tpl = _read_xray_connection_template()

    host = tpl.get("server_address", "").strip() or request.url.hostname or "127.0.0.1"
    port = tpl.get("server_port", "").strip() or os.environ.get("XRAY_PORT", "8443")
    sni = tpl.get("sni", "").strip() or host
    pbk = tpl.get("public_key", "").strip()
    sid = tpl.get("short_id", "").strip()
    flow = tpl.get("flow", "xtls-rprx-vision")
    uri = (
        f"vless://{profile['xray_uuid']}@{host}:{port}"
        f"?encryption=none&flow={flow}&security=reality&sni={sni}&fp=chrome&pbk={pbk}&sid={sid}&type=tcp"
        f"#proxy-vpn-{user['username']}-{platform}"
    )

    instructions: list[str] = []
    app_name = ""
    primary_client: dict[str, str] = {}
    client_about = "Free client for importing VLESS URI and connecting in VPN/proxy mode."
    if device_type == "mobile" and platform == "apple":
        app_name = "Hiddify Next / Karing (free)"
        primary_client = {
            "name": "Karing",
            "install_url": "https://apps.apple.com/us/app/karing/id6472431552",
            "source": "store",
        }
        client_about = "Karing is a free Apple client for VLESS/Xray profiles with simple URI import."
        instructions = [
            "Install Karing from App Store using the button below.",
            "Open app -> Add profile/node -> Import from Clipboard/URI.",
            "Paste VLESS URI from this card and save profile.",
            "Enable tunnel/proxy mode and verify access to blocked resource.",
        ]
    elif device_type == "mobile" and platform == "android":
        app_name = "v2rayNG / Hiddify Next (free)"
        primary_client = {
            "name": "v2rayNG",
            "install_url": "https://play.google.com/store/apps/details?id=com.v2ray.ang",
            "source": "store",
        }
        client_about = "v2rayNG is a free Android client with stable support for Xray/VLESS links."
        instructions = [
            "Install v2rayNG from Google Play using the button below.",
            "Add profile -> Import from Clipboard or manual VLESS URI.",
            "Paste URI from this card and save.",
            "Start connection (VPN mode in app) and test route.",
        ]
    elif device_type == "desktop" and platform == "windows":
        app_name = "v2rayN"
        primary_client = {
            "name": "v2rayN",
            "install_url": "https://github.com/2dust/v2rayN/releases",
            "source": "github",
        }
        client_about = "v2rayN is a free Windows GUI client for Xray/VLESS with easy clipboard import."
        instructions = [
            "Download latest v2rayN from releases page.",
            "Servers -> Import from clipboard (or Ctrl+V).",
            "Set imported node as active.",
            "Enable system proxy and validate connection.",
        ]
    elif device_type == "desktop" and platform == "apple":
        app_name = "Nekoray / V2rayU (free)"
        primary_client = {
            "name": "V2rayU",
            "install_url": "https://github.com/yanue/V2rayU/releases",
            "source": "github",
        }
        client_about = "V2rayU is a free macOS client that supports VLESS URI import and system proxy modes."
        instructions = [
            "Download and install V2rayU from releases page.",
            "Import VLESS URI from clipboard.",
            "Select profile as active and enable proxy mode.",
            "Verify traffic through the tunnel.",
        ]
    elif device_type == "desktop" and platform == "linux":
        app_name = "Nekoray / sing-box GUI"
        primary_client = {
            "name": "Karing",
            "install_url": "https://github.com/KaringX/karing/releases",
            "source": "github",
        }
        client_about = "Karing provides free Linux builds (AppImage/DEB/RPM) and supports VLESS URI import."
        instructions = [
            "Download Karing (AppImage/DEB/RPM) from releases page.",
            "Create new profile and import VLESS URI.",
            "Enable tun/system proxy according to your desktop setup.",
            "Check connectivity to blocked endpoint.",
        ]
    if not primary_client:
        primary_client = {"name": "Client", "install_url": "", "source": "unknown"}

    return JSONResponse(
        {
            "status": "ok",
            "device_type": device_type,
            "platform": platform,
            "region_profile": region_profile,
            "card": {
                "title": "Proxy/VPN configuration",
                "protocol": "VLESS + REALITY (Xray)",
                "client_app": app_name,
                "config_uri": uri,
                "config_fields": {
                    "server": host,
                    "port": port,
                    "uuid": profile["xray_uuid"],
                    "email": profile["xray_email"],
                    "sni": sni,
                    "public_key": pbk,
                    "short_id": sid,
                    "flow": flow,
                },
                "instructions": instructions,
                "primary_client": primary_client,
                "client_about": client_about,
            },
        }
    )


@app.get("/api/v1/admin/stats")
def admin_stats(request: Request) -> JSONResponse:
    _require_admin(request)
    with _db_connect() as con:
        total_users = con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        active_users = con.execute("SELECT COUNT(*) c FROM users WHERE is_active = 1").fetchone()["c"]
        active_sessions = con.execute("SELECT COUNT(*) c FROM sessions WHERE revoked = 0").fetchone()["c"]
        pending_requests = con.execute(
            "SELECT COUNT(*) c FROM registration_requests WHERE status = 'pending'"
        ).fetchone()["c"]
        current = con.execute(
            """
            SELECT load1, load5, cpu_load_pct, memory_used_pct, disk_used_pct, net_rx_bytes, net_tx_bytes, ts
            FROM metric_samples
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        one_hour = con.execute(
            """
            SELECT AVG(cpu_load_pct) avg_cpu, AVG(memory_used_pct) avg_mem, AVG(disk_used_pct) avg_disk
            FROM metric_samples
            WHERE ts >= datetime('now', '-1 hour')
            """
        ).fetchone()
        net_window = con.execute(
            """
            SELECT
              (MAX(net_rx_bytes) - MIN(net_rx_bytes)) rx_delta,
              (MAX(net_tx_bytes) - MIN(net_tx_bytes)) tx_delta
            FROM metric_samples
            WHERE ts >= datetime('now', '-24 hour')
            """
        ).fetchone()
    return JSONResponse(
        {
            "status": "ok",
            "stats": {
                "total_users": total_users,
                "active_users": active_users,
                "active_sessions": active_sessions,
                "pending_requests": pending_requests,
                "current_load1": float(current["load1"]) if current else 0.0,
                "current_load5": float(current["load5"]) if current else 0.0,
                "current_cpu_load_pct": float(current["cpu_load_pct"]) if current else 0.0,
                "current_memory_used_pct": float(current["memory_used_pct"]) if current else 0.0,
                "current_disk_used_pct": float(current["disk_used_pct"]) if current else 0.0,
                "traffic_rx_24h_bytes": int(net_window["rx_delta"] or 0) if net_window else 0,
                "traffic_tx_24h_bytes": int(net_window["tx_delta"] or 0) if net_window else 0,
                "avg_cpu_1h_pct": round(float(one_hour["avg_cpu"] or 0.0), 2) if one_hour else 0.0,
                "avg_mem_1h_pct": round(float(one_hour["avg_mem"] or 0.0), 2) if one_hour else 0.0,
                "avg_disk_1h_pct": round(float(one_hour["avg_disk"] or 0.0), 2) if one_hour else 0.0,
            },
        }
    )


@app.get("/api/v1/admin/services/status")
def admin_services_status(request: Request) -> JSONResponse:
    _require_admin(request)
    data = _get_container_statuses()
    data["xray_collector"] = _get_xray_collector_status()
    return JSONResponse(data)


@app.get("/api/v1/admin/services/{container_name}/logs")
def admin_service_logs(request: Request, container_name: str, tail: int = 120, stderr_only: bool = False) -> JSONResponse:
    _require_admin(request)
    if container_name not in STACK_CONTAINERS:
        raise HTTPException(status_code=404, detail="Container is not managed by proxy-vpn")
    if docker is None:
        return JSONResponse({"status": "degraded", "logs": "Docker SDK is unavailable in api container."})
    tail = max(20, min(500, int(tail)))
    client = None
    try:
        client = docker.from_env()
        c = client.containers.get(container_name)
        logs_raw = c.logs(stdout=(not stderr_only), stderr=True, tail=tail, timestamps=True)
        logs_text = logs_raw.decode("utf-8", errors="replace")
        return JSONResponse(
            {
                "status": "ok",
                "container": container_name,
                "tail": tail,
                "stderr_only": stderr_only,
                "logs": logs_text,
            }
        )
    except NotFound:
        raise HTTPException(status_code=404, detail="Container not found")
    except DockerException as e:
        return JSONResponse({"status": "degraded", "logs": f"Docker error: {e}"})
    finally:
        try:
            client.close()  # type: ignore[name-defined]
        except Exception:
            pass


@app.get("/api/v1/admin/deploy-events")
def admin_deploy_events(request: Request, limit: int = 20) -> JSONResponse:
    _require_admin(request)
    data = _read_deploy_history(limit=limit)
    return JSONResponse(data)


@app.get("/api/v1/admin/online-users")
def admin_online_users(request: Request) -> JSONResponse:
    _require_admin(request)
    threshold = (_now() - timedelta(seconds=ONLINE_WINDOW_SECONDS)).isoformat()
    with _db_connect() as con:
        rows = con.execute(
            """
            SELECT u.username, u.email, u.role, COUNT(s.sid) sessions, MAX(s.last_seen) last_seen
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.revoked = 0
              AND s.expires_at > ?
              AND COALESCE(s.last_seen, s.created_at) >= ?
            GROUP BY u.id, u.username, u.email, u.role
            ORDER BY last_seen DESC
            """,
            (_now().isoformat(), threshold),
        ).fetchall()
    return JSONResponse({"status": "ok", "items": [dict(r) for r in rows], "online_count": len(rows)})


@app.get("/api/v1/admin/system-metrics")
def admin_system_metrics(request: Request) -> JSONResponse:
    _require_admin(request)
    with _db_connect() as con:
        row = con.execute(
            """
            SELECT ts, load1, load5, load15, cpu_load_pct, memory_used_pct, disk_used_pct, net_rx_bytes, net_tx_bytes
            FROM metric_samples
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        avg = con.execute(
            """
            SELECT AVG(cpu_load_pct) avg_cpu, AVG(memory_used_pct) avg_mem, AVG(disk_used_pct) avg_disk
            FROM metric_samples
            WHERE ts >= datetime('now', '-1 hour')
            """
        ).fetchone()
    return JSONResponse(
        {
            "status": "ok",
            "current": dict(row) if row else _collect_system_snapshot(),
            "avg_1h": {
                "cpu_load_pct": round(float(avg["avg_cpu"] or 0.0), 2) if avg else 0.0,
                "memory_used_pct": round(float(avg["avg_mem"] or 0.0), 2) if avg else 0.0,
                "disk_used_pct": round(float(avg["avg_disk"] or 0.0), 2) if avg else 0.0,
            },
        }
    )


@app.get("/api/v1/admin/system-metrics/timeseries")
def admin_system_metrics_timeseries(request: Request, minutes: int = 60) -> JSONResponse:
    _require_admin(request)
    minutes = max(5, min(24 * 60, minutes))
    with _db_connect() as con:
        rows = con.execute(
            """
            SELECT ts, cpu_load_pct, memory_used_pct, disk_used_pct, net_rx_bytes, net_tx_bytes
            FROM metric_samples
            WHERE ts >= datetime('now', ?)
            ORDER BY ts ASC
            """,
            (f"-{minutes} minutes",),
        ).fetchall()
    points = [dict(r) for r in rows]
    # Compute rates from consecutive samples.
    for i in range(1, len(points)):
        prev = points[i - 1]
        cur = points[i]
        try:
            dt = max(
                1.0,
                (
                    datetime.fromisoformat(cur["ts"]) - datetime.fromisoformat(prev["ts"])
                ).total_seconds(),
            )
        except Exception:
            dt = float(METRICS_SAMPLE_INTERVAL_SECONDS)
        cur["rx_rate_bps"] = max(0.0, (cur["net_rx_bytes"] - prev["net_rx_bytes"]) / dt)
        cur["tx_rate_bps"] = max(0.0, (cur["net_tx_bytes"] - prev["net_tx_bytes"]) / dt)
    if points:
        points[0]["rx_rate_bps"] = 0.0
        points[0]["tx_rate_bps"] = 0.0
    return JSONResponse({"status": "ok", "minutes": minutes, "points": points})


@app.get("/api/v1/admin/user-traffic/summary")
def admin_user_traffic_summary(request: Request, hours: int = 24) -> JSONResponse:
    _require_admin(request)
    hours = max(1, min(24 * 30, hours))
    with _db_connect() as con:
        wg_exact_rows = con.execute(
            """
            SELECT COUNT(*) c
            FROM user_wireguard_traffic_samples
            WHERE ts >= datetime('now', ?)
            """,
            (f"-{hours} hours",),
        ).fetchone()
        xray_exact_rows = con.execute(
            """
            SELECT COUNT(*) c
            FROM user_xray_traffic_samples
            WHERE ts >= datetime('now', ?)
            """,
            (f"-{hours} hours",),
        ).fetchone()
        use_exact = int(wg_exact_rows["c"] or 0) > 0 or int(xray_exact_rows["c"] or 0) > 0
        if use_exact:
            rows = con.execute(
                """
                SELECT u.id user_id, u.username, u.email, u.role,
                       COALESCE(w.rx_bytes, 0) + COALESCE(x.rx_bytes, 0) rx_bytes,
                       COALESCE(w.tx_bytes, 0) + COALESCE(x.tx_bytes, 0) tx_bytes
                FROM users u
                LEFT JOIN (
                  SELECT user_id, SUM(rx_bytes) rx_bytes, SUM(tx_bytes) tx_bytes
                  FROM user_wireguard_traffic_samples
                  WHERE ts >= datetime('now', ?)
                  GROUP BY user_id
                ) w ON w.user_id = u.id
                LEFT JOIN (
                  SELECT user_id, SUM(rx_bytes) rx_bytes, SUM(tx_bytes) tx_bytes
                  FROM user_xray_traffic_samples
                  WHERE ts >= datetime('now', ?)
                  GROUP BY user_id
                ) x ON x.user_id = u.id
                ORDER BY (COALESCE(w.rx_bytes, 0) + COALESCE(x.rx_bytes, 0) + COALESCE(w.tx_bytes, 0) + COALESCE(x.tx_bytes, 0)) DESC, u.username ASC
                """,
                (f"-{hours} hours", f"-{hours} hours"),
            ).fetchall()
        else:
            rows = con.execute(
                """
                SELECT u.id user_id, u.username, u.email, u.role,
                       COALESCE(SUM(t.rx_bytes), 0) rx_bytes,
                       COALESCE(SUM(t.tx_bytes), 0) tx_bytes
                FROM users u
                LEFT JOIN user_traffic_samples t ON t.user_id = u.id AND t.ts >= datetime('now', ?)
                GROUP BY u.id, u.username, u.email, u.role
                ORDER BY (rx_bytes + tx_bytes) DESC, u.username ASC
                """,
                (f"-{hours} hours",),
            ).fetchall()
        if use_exact:
            source = "wireguard_xray_exact"
        else:
            source = "estimated_session_share"
    return JSONResponse(
        {
            "status": "ok",
            "hours": hours,
            "source": source,
            "items": [dict(r) for r in rows],
        }
    )


@app.get("/api/v1/admin/user-traffic/timeseries")
def admin_user_traffic_timeseries(request: Request, user_id: int, minutes: int = 60) -> JSONResponse:
    _require_admin(request)
    minutes = max(5, min(24 * 60, minutes))
    with _db_connect() as con:
        user = con.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        wg_rows = con.execute(
            """
            SELECT ts, SUM(rx_bytes) rx_bytes, SUM(tx_bytes) tx_bytes
            FROM user_wireguard_traffic_samples
            WHERE user_id = ? AND ts >= datetime('now', ?)
            GROUP BY ts
            ORDER BY ts ASC
            """,
            (user_id, f"-{minutes} minutes"),
        ).fetchall()
        xray_rows = con.execute(
            """
            SELECT ts, SUM(rx_bytes) rx_bytes, SUM(tx_bytes) tx_bytes
            FROM user_xray_traffic_samples
            WHERE user_id = ? AND ts >= datetime('now', ?)
            GROUP BY ts
            ORDER BY ts ASC
            """,
            (user_id, f"-{minutes} minutes"),
        ).fetchall()
        rows: list[sqlite3.Row] = []
        source = "wireguard_xray_exact"
        if wg_rows or xray_rows:
            merged: dict[str, dict[str, float]] = {}
            for r in wg_rows:
                ts = str(r["ts"])
                agg = merged.setdefault(ts, {"rx_bytes": 0.0, "tx_bytes": 0.0})
                agg["rx_bytes"] += float(r["rx_bytes"] or 0.0)
                agg["tx_bytes"] += float(r["tx_bytes"] or 0.0)
            for r in xray_rows:
                ts = str(r["ts"])
                agg = merged.setdefault(ts, {"rx_bytes": 0.0, "tx_bytes": 0.0})
                agg["rx_bytes"] += float(r["rx_bytes"] or 0.0)
                agg["tx_bytes"] += float(r["tx_bytes"] or 0.0)
            rows = [
                {"ts": ts, "rx_bytes": int(v["rx_bytes"]), "tx_bytes": int(v["tx_bytes"])}
                for ts, v in sorted(merged.items(), key=lambda item: item[0])
            ]
        else:
            rows = con.execute(
                """
                SELECT ts, SUM(rx_bytes) rx_bytes, SUM(tx_bytes) tx_bytes
                FROM user_traffic_samples
                WHERE user_id = ? AND ts >= datetime('now', ?)
                GROUP BY ts
                ORDER BY ts ASC
                """,
                (user_id, f"-{minutes} minutes"),
            ).fetchall()
            source = "estimated_session_share"
    points = [dict(r) for r in rows]
    for i in range(1, len(points)):
        prev = points[i - 1]
        cur = points[i]
        try:
            dt = max(1.0, (datetime.fromisoformat(cur["ts"]) - datetime.fromisoformat(prev["ts"])).total_seconds())
        except Exception:
            dt = float(METRICS_SAMPLE_INTERVAL_SECONDS)
        cur["rx_rate_bps"] = max(0.0, (float(cur["rx_bytes"]) - float(prev["rx_bytes"])) / dt)
        cur["tx_rate_bps"] = max(0.0, (float(cur["tx_bytes"]) - float(prev["tx_bytes"])) / dt)
    if points:
        points[0]["rx_rate_bps"] = 0.0
        points[0]["tx_rate_bps"] = 0.0
    return JSONResponse({"status": "ok", "user": dict(user), "minutes": minutes, "source": source, "points": points})


@app.get("/api/v1/admin/wireguard-bindings")
def admin_wireguard_bindings(request: Request) -> JSONResponse:
    _require_admin(request)
    with _db_connect() as con:
        rows = con.execute(
            """
            SELECT b.public_key, b.label, b.created_at, b.user_id, u.username, u.email, u.role,
                   COALESCE(c.last_rx_bytes, 0) last_rx_bytes, COALESCE(c.last_tx_bytes, 0) last_tx_bytes
            FROM wg_peer_bindings b
            JOIN users u ON u.id = b.user_id
            LEFT JOIN wg_peer_counters c ON c.public_key = b.public_key
            ORDER BY b.id DESC
            """
        ).fetchall()
    return JSONResponse({"status": "ok", "items": [dict(r) for r in rows]})


@app.post("/api/v1/admin/wireguard-bindings")
def admin_wireguard_bind(request: Request, payload: AdminBindWireGuardRequest) -> JSONResponse:
    _ensure_csrf(request)
    _require_admin(request)
    public_key = payload.public_key.strip()
    if len(public_key) < 20:
        raise HTTPException(status_code=400, detail="Invalid WireGuard public key")
    with _db_connect() as con:
        user = con.execute("SELECT id FROM users WHERE id = ?", (payload.user_id,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        con.execute(
            """
            INSERT INTO wg_peer_bindings (user_id, public_key, label, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(public_key)
            DO UPDATE SET user_id=excluded.user_id, label=excluded.label
            """,
            (payload.user_id, public_key, payload.label.strip(), _now().isoformat()),
        )
        con.commit()
    return JSONResponse({"status": "ok", "message": "wireguard peer bound"})


@app.delete("/api/v1/admin/wireguard-bindings/{public_key}")
def admin_wireguard_unbind(public_key: str, request: Request) -> JSONResponse:
    _ensure_csrf(request)
    _require_admin(request)
    with _db_connect() as con:
        con.execute("DELETE FROM wg_peer_bindings WHERE public_key = ?", (public_key,))
        con.execute("DELETE FROM wg_peer_counters WHERE public_key = ?", (public_key,))
        con.commit()
    return JSONResponse({"status": "ok", "message": "wireguard peer unbound"})


@app.get("/api/v1/admin/xray-bindings")
def admin_xray_bindings(request: Request) -> JSONResponse:
    _require_admin(request)
    with _db_connect() as con:
        rows = con.execute(
            """
            SELECT b.client_email, b.label, b.created_at, b.user_id, u.username, u.email, u.role,
                   COALESCE(c.last_downlink_bytes, 0) last_downlink_bytes, COALESCE(c.last_uplink_bytes, 0) last_uplink_bytes
            FROM xray_client_bindings b
            JOIN users u ON u.id = b.user_id
            LEFT JOIN xray_client_counters c ON c.client_email = b.client_email
            ORDER BY b.id DESC
            """
        ).fetchall()
    return JSONResponse({"status": "ok", "items": [dict(r) for r in rows]})


@app.post("/api/v1/admin/xray-bindings")
def admin_xray_bind(request: Request, payload: AdminBindXrayClientRequest) -> JSONResponse:
    _ensure_csrf(request)
    _require_admin(request)
    client_email = payload.client_email.strip().lower()
    if "@" not in client_email or len(client_email) < 6:
        raise HTTPException(status_code=400, detail="Invalid Xray client email")
    with _db_connect() as con:
        user = con.execute("SELECT id FROM users WHERE id = ?", (payload.user_id,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        con.execute(
            """
            INSERT INTO xray_client_bindings (user_id, client_email, label, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(client_email)
            DO UPDATE SET user_id=excluded.user_id, label=excluded.label
            """,
            (payload.user_id, client_email, payload.label.strip(), _now().isoformat()),
        )
        con.commit()
    return JSONResponse({"status": "ok", "message": "xray client bound"})


@app.delete("/api/v1/admin/xray-bindings/{client_email}")
def admin_xray_unbind(client_email: str, request: Request) -> JSONResponse:
    _ensure_csrf(request)
    _require_admin(request)
    key = client_email.strip().lower()
    with _db_connect() as con:
        con.execute("DELETE FROM xray_client_bindings WHERE client_email = ?", (key,))
        con.execute("DELETE FROM xray_client_counters WHERE client_email = ?", (key,))
        con.commit()
    return JSONResponse({"status": "ok", "message": "xray client unbound"})


@app.get("/api/v1/admin/registration-requests")
def admin_registration_requests(request: Request) -> JSONResponse:
    _require_admin(request)
    with _db_connect() as con:
        rows = con.execute(
            """
            SELECT id, username, email, status, requested_at, reviewed_at, reviewed_by, review_note
            FROM registration_requests
            ORDER BY id DESC
            """
        ).fetchall()
    return JSONResponse({"status": "ok", "items": [dict(r) for r in rows]})


@app.post("/api/v1/admin/registration-requests/{request_id}/approve")
def admin_approve_registration(request: Request, request_id: int) -> JSONResponse:
    _ensure_csrf(request)
    admin_user = _require_admin(request)
    with _db_connect() as con:
        row = con.execute(
            """
            SELECT id, username, email, password_hash, status
            FROM registration_requests
            WHERE id = ?
            """,
            (request_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Request not found")
        if row["status"] != "pending":
            raise HTTPException(status_code=409, detail="Request already processed")
        exists_user = con.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (row["username"], row["email"]),
        ).fetchone()
        if exists_user:
            raise HTTPException(status_code=409, detail="User already exists")
        con.execute(
            """
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, 'user', 1, ?)
            """,
            (row["username"], row["email"], row["password_hash"], _now().isoformat()),
        )
        con.execute(
            """
            UPDATE registration_requests
            SET status = 'approved', reviewed_at = ?, reviewed_by = ?, review_note = 'approved by admin'
            WHERE id = ?
            """,
            (_now().isoformat(), admin_user["id"], request_id),
        )
        con.commit()
    return JSONResponse({"status": "ok", "message": "request approved"})


@app.post("/api/v1/admin/registration-requests/{request_id}/reject")
def admin_reject_registration(request: Request, request_id: int) -> JSONResponse:
    _ensure_csrf(request)
    admin_user = _require_admin(request)
    with _db_connect() as con:
        row = con.execute(
            "SELECT id, status FROM registration_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Request not found")
        if row["status"] != "pending":
            raise HTTPException(status_code=409, detail="Request already processed")
        con.execute(
            """
            UPDATE registration_requests
            SET status = 'rejected', reviewed_at = ?, reviewed_by = ?, review_note = 'rejected by admin'
            WHERE id = ?
            """,
            (_now().isoformat(), admin_user["id"], request_id),
        )
        con.commit()
    return JSONResponse({"status": "ok", "message": "request rejected"})


@app.post("/api/v1/admin/users/create")
def admin_create_user(request: Request, payload: AdminCreateUserRequest) -> JSONResponse:
    _ensure_csrf(request)
    _require_admin(request)
    role = payload.role.strip().lower()
    if role not in {"user", "admin"}:
        raise HTTPException(status_code=400, detail="Role must be user or admin")
    if "@" not in payload.email:
        raise HTTPException(status_code=400, detail="Invalid email")
    if len(payload.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="Username is too short")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 chars")
    username = payload.username.strip().lower()
    with _db_connect() as con:
        exists_user = con.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, payload.email.lower()),
        ).fetchone()
        if exists_user:
            raise HTTPException(status_code=409, detail="User already exists")
        con.execute(
            """
            INSERT INTO users (username, email, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (username, payload.email.lower(), _hash_password(payload.password), role, _now().isoformat()),
        )
        con.commit()
    return JSONResponse({"status": "ok", "message": "user created"})


@app.post("/api/v1/admin/users/{user_id}/block")
def admin_block_user(request: Request, user_id: int) -> JSONResponse:
    _ensure_csrf(request)
    admin_user = _require_admin(request)
    if int(admin_user["id"]) == int(user_id):
        raise HTTPException(status_code=400, detail="You cannot block your own account")
    with _db_connect() as con:
        target = con.execute("SELECT id, role, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        if target["role"] == "admin" and int(target["is_active"]) == 1:
            admins_left = con.execute(
                "SELECT COUNT(*) c FROM users WHERE role = 'admin' AND is_active = 1 AND id != ?",
                (user_id,),
            ).fetchone()
            if int(admins_left["c"] or 0) <= 0:
                raise HTTPException(status_code=409, detail="Cannot block the last active admin")
        con.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        con.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user_id,))
        con.commit()
    return JSONResponse({"status": "ok", "message": "user blocked"})


@app.post("/api/v1/admin/users/{user_id}/unblock")
def admin_unblock_user(request: Request, user_id: int) -> JSONResponse:
    _ensure_csrf(request)
    _require_admin(request)
    with _db_connect() as con:
        target = con.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        con.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
        con.commit()
    return JSONResponse({"status": "ok", "message": "user unblocked"})


@app.delete("/api/v1/admin/users/{user_id}")
def admin_delete_user(request: Request, user_id: int) -> JSONResponse:
    _ensure_csrf(request)
    admin_user = _require_admin(request)
    if int(admin_user["id"]) == int(user_id):
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    with _db_connect() as con:
        target = con.execute("SELECT id, role, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        if target["role"] == "admin":
            admins_left = con.execute(
                "SELECT COUNT(*) c FROM users WHERE role = 'admin' AND id != ?",
                (user_id,),
            ).fetchone()
            if int(admins_left["c"] or 0) <= 0:
                raise HTTPException(status_code=409, detail="Cannot delete the last admin")
        con.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM user_traffic_samples WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM user_wireguard_traffic_samples WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM user_xray_traffic_samples WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM user_access_profiles WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM wg_peer_bindings WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM xray_client_bindings WHERE user_id = ?", (user_id,))
        con.execute(
            "DELETE FROM xray_client_counters WHERE client_email NOT IN (SELECT client_email FROM xray_client_bindings)"
        )
        con.execute("DELETE FROM wg_peer_counters WHERE public_key NOT IN (SELECT public_key FROM wg_peer_bindings)")
        con.execute("DELETE FROM users WHERE id = ?", (user_id,))
        con.commit()
    return JSONResponse({"status": "ok", "message": "user deleted"})


@app.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name}


@app.get("/api/v1/meta")
def meta():
    return {
        "service": settings.app_name,
        "stack": ["wireguard", "xray", "fastapi", "caddy"],
    }
