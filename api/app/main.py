import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
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
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_MINUTES = int(os.getenv("LOGIN_WINDOW_MINUTES", "10"))
LOGIN_LOCK_MINUTES = int(os.getenv("LOGIN_LOCK_MINUTES", "15"))
ONLINE_WINDOW_SECONDS = 300
METRICS_SAMPLE_INTERVAL_SECONDS = 10
CAPACITY_TARGET_ACTIVE_USERS = int(os.getenv("CAPACITY_TARGET_ACTIVE_USERS", "15"))
CAPACITY_CPU_WARN_P95 = float(os.getenv("CAPACITY_CPU_WARN_P95", "70"))
CAPACITY_CPU_CRIT_P95 = float(os.getenv("CAPACITY_CPU_CRIT_P95", "80"))
CAPACITY_RAM_WARN_P95 = float(os.getenv("CAPACITY_RAM_WARN_P95", "80"))
CAPACITY_RAM_CRIT_P95 = float(os.getenv("CAPACITY_RAM_CRIT_P95", "85"))
CAPACITY_DISK_WARN_P95 = float(os.getenv("CAPACITY_DISK_WARN_P95", "85"))
CAPACITY_DISK_CRIT_P95 = float(os.getenv("CAPACITY_DISK_CRIT_P95", "92"))
DEFAULT_TRAFFIC_LIMIT_TB = float(os.getenv("TRAFFIC_LIMIT_TB", "32"))
DEFAULT_AVG_USER_TRAFFIC_GB = float(os.getenv("AVG_USER_TRAFFIC_GB", "50"))
DEFAULT_ACTIVE_USER_RATIO_PCT = float(os.getenv("ACTIVE_USER_RATIO_PCT", "25"))
DEFAULT_MAX_REGISTERED_USERS = int(os.getenv("MAX_REGISTERED_USERS", "0"))
DEFAULT_DASHBOARD_REFRESH_SECONDS = int(os.getenv("DASHBOARD_REFRESH_SECONDS", "30"))
DEFAULT_PROXY_BYPASS_CUSTOM = os.getenv("DEFAULT_PROXY_BYPASS_CUSTOM", "")
WG_DUMP_PATH = "/wireguard-config/wg_dump.txt"
XRAY_STATS_PATH = "/xray-config/stats_raw.txt"
XRAY_CONFIG_PATH = "/xray-config/config.json"
XRAY_CLIENT_INFO_PATH = "/xray-config/client-connection.txt"
DEPLOY_HISTORY_PATH = os.getenv("DEPLOY_HISTORY_PATH", "/logs/deploy-history.log")
APP_RELEASE_STATE_PATH = os.getenv("APP_RELEASE_STATE_PATH", "/logs/app-release-state.json")
UPDATE_CHECK_REQUEST_PATH = os.getenv("UPDATE_CHECK_REQUEST_PATH", "/logs/update-check-request.json")
UPDATE_APPLY_REQUEST_PATH = os.getenv("UPDATE_APPLY_REQUEST_PATH", "/logs/update-apply-request.json")
BACKUP_STATUS_PATH = os.getenv("BACKUP_STATUS_PATH", "/logs/backup-status.json")
UPDATE_AUDIT_PATH = os.getenv("UPDATE_AUDIT_PATH", "/logs/update-audit.jsonl")
PROXY_BYPASS_RULES_PATH = os.getenv("PROXY_BYPASS_RULES_PATH", "config/proxy-bypass-rules.txt")
SECURITY_GUARD_URL = os.getenv("SECURITY_GUARD_URL", "http://security-guard:9100").rstrip("/")
SECURITY_HTTP_WINDOW_SECONDS = int(os.getenv("SECURITY_HTTP_WINDOW_SECONDS", "10"))
SECURITY_HTTP_MAX_REQUESTS = int(os.getenv("SECURITY_HTTP_MAX_REQUESTS", "120"))
SECURITY_PROBE_PATH_THRESHOLD = int(os.getenv("SECURITY_PROBE_PATH_THRESHOLD", "12"))
SECURITY_BLOCK_SECONDS_DDOS = int(os.getenv("SECURITY_BLOCK_SECONDS_DDOS", "600"))
SECURITY_BLOCK_SECONDS_BRUTE = int(os.getenv("SECURITY_BLOCK_SECONDS_BRUTE", "900"))
SECURITY_SERVER_CHECK_INTERVAL_SECONDS = int(os.getenv("SECURITY_SERVER_CHECK_INTERVAL_SECONDS", "60"))
SECURITY_SERVER_EVENT_COOLDOWN_SECONDS = int(os.getenv("SECURITY_SERVER_EVENT_COOLDOWN_SECONDS", "300"))
SECURITY_GUARD_UNAVAILABLE_REASON = "security guard unavailable"
XRAY_USER_STATS_RE = re.compile(r"user>>>(.+?)>>>traffic>>>(uplink|downlink)")
XRAY_VALUE_RE = re.compile(r"(?:\"value\"\\s*:\\s*|value\\s*[:=]\\s*)(\\d+)")
XRAY_CONTAINER_NAME = "proxy-vpn-xray"
STACK_CONTAINERS = [
    "proxy-vpn-caddy",
    "proxy-vpn-api",
    "proxy-vpn-security-guard",
    XRAY_CONTAINER_NAME,
    "proxy-vpn-wireguard",
]
_METRICS_THREAD_LOCK = threading.Lock()
_METRICS_THREAD_STARTED = False
_SECURITY_RATE_LOCK = threading.Lock()
_SECURITY_RATE_BUCKETS: dict[str, list[float]] = {}
_SECURITY_SERVER_LOCK = threading.Lock()
_SECURITY_SERVER_LAST_CHECK_TS = 0.0
_SECURITY_SERVER_LAST_EVENTS: dict[str, float] = {}


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


@app.middleware("http")
async def security_guard_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/docs") or path.startswith("/openapi.json"):
        return await call_next(request)
    ip = _client_ip(request)
    if ip and ip != "unknown":
        enforce_block = not _is_internal_ip(ip)
        if enforce_block:
            blocked = _security_block_check(ip)
            if blocked.get("status") == "ok" and blocked.get("blocked") is True:
                return JSONResponse(
                    {
                        "status": "blocked",
                        "detail": "Request blocked by security guard",
                        "reason": blocked.get("reason", ""),
                        "blocked_until": blocked.get("blocked_until"),
                    },
                    status_code=403,
                )
        _security_track_http_rate(ip, path, enforce_block=enforce_block)
    response = await call_next(request)
    if ip and ip != "unknown" and _is_suspicious_probe_path(path):
        _security_report_event(
            ip=ip,
            attack_type="exploit_probe",
            direction="inbound->panel",
            reason=f"suspicious path requested: {path}",
            severity="high" if response.status_code in (401, 403, 404, 405) else "medium",
            target="panel/api",
            source="api-middleware",
        )
    return response


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


def _is_internal_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return bool(obj.is_private or obj.is_loopback or obj.is_link_local)
    except Exception:
        return False


def _security_guard_call(method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    url = f"{SECURITY_GUARD_URL}{path}"
    data = None
    headers = {"User-Agent": "proxy-vpn-api/1.0"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=1.8) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        out = json.loads(raw) if raw else {}
        if not isinstance(out, dict):
            return {"status": "degraded", "reason": "security guard response is invalid"}
        return out
    except Exception as e:
        return {"status": "degraded", "reason": f"security guard unavailable: {e}"}


def _security_report_event(
    ip: str,
    attack_type: str,
    direction: str,
    reason: str,
    *,
    target: str = "panel/api",
    severity: str = "medium",
    action: str = "observed",
    block_seconds: int = 0,
    source: str = "api",
    count: int = 1,
) -> dict[str, Any]:
    return _security_guard_call(
        "POST",
        "/event",
        {
            "ip": ip,
            "attack_type": attack_type,
            "direction": direction,
            "target": target,
            "severity": severity,
            "reason": reason,
            "action": action,
            "block_seconds": max(0, int(block_seconds)),
            "source": source,
            "count": max(1, int(count)),
        },
    )


def _security_block_check(ip: str) -> dict[str, Any]:
    query = urllib.parse.urlencode({"ip": ip})
    return _security_guard_call("GET", f"/blocked/check?{query}")


def _is_suspicious_probe_path(path: str) -> bool:
    p = path.lower()
    tokens = [
        ".env",
        "wp-admin",
        "wp-login",
        "phpmyadmin",
        "cgi-bin",
        "xmlrpc.php",
        "boaform",
        "actuator",
        ".git/config",
        "/vendor/phpunit",
    ]
    return any(tok in p for tok in tokens)


def _security_track_http_rate(ip: str, path: str, enforce_block: bool = True) -> Optional[int]:
    now = time.time()
    with _SECURITY_RATE_LOCK:
        items = _SECURITY_RATE_BUCKETS.get(ip, [])
        min_ts = now - float(max(1, SECURITY_HTTP_WINDOW_SECONDS))
        items = [t for t in items if t >= min_ts]
        items.append(now)
        _SECURITY_RATE_BUCKETS[ip] = items
        req_count = len(items)
    if req_count >= max(10, SECURITY_HTTP_MAX_REQUESTS):
        _security_report_event(
            ip=ip,
            attack_type="ddos_http_flood",
            direction="inbound->server",
            reason=f"high request rate in {SECURITY_HTTP_WINDOW_SECONDS}s window (possible edge flood)",
            severity="critical" if enforce_block else "high",
            action="blocked" if enforce_block else "observed",
            block_seconds=SECURITY_BLOCK_SECONDS_DDOS if enforce_block else 0,
            source="api-http-rate",
            count=req_count,
        )
        return req_count
    if _is_suspicious_probe_path(path) and req_count >= max(4, SECURITY_PROBE_PATH_THRESHOLD):
        _security_report_event(
            ip=ip,
            attack_type="exploit_probe_scan",
            direction="inbound->server",
            reason="multiple suspicious probe paths",
            severity="high",
            action="blocked" if enforce_block else "observed",
            block_seconds=max(300, SECURITY_BLOCK_SECONDS_DDOS // 2) if enforce_block else 0,
            source="api-path-scan",
            count=req_count,
        )
    return None


def _security_should_emit(key: str, cooldown_seconds: int) -> bool:
    now = time.time()
    with _SECURITY_SERVER_LOCK:
        last = float(_SECURITY_SERVER_LAST_EVENTS.get(key, 0.0))
        if now - last < float(max(1, cooldown_seconds)):
            return False
        _SECURITY_SERVER_LAST_EVENTS[key] = now
        return True


def _security_track_server_state(snapshot: dict[str, Any]) -> None:
    now = time.time()
    with _SECURITY_SERVER_LOCK:
        global _SECURITY_SERVER_LAST_CHECK_TS
        if now - float(_SECURITY_SERVER_LAST_CHECK_TS) < float(max(10, SECURITY_SERVER_CHECK_INTERVAL_SECONDS)):
            return
        _SECURITY_SERVER_LAST_CHECK_TS = now

    # Host resource exhaustion signals (can indicate active attack or abusive load).
    cpu = float(snapshot.get("cpu_load_pct") or 0.0)
    mem = float(snapshot.get("memory_used_pct") or 0.0)
    disk = float(snapshot.get("disk_used_pct") or 0.0)
    if cpu >= CAPACITY_CPU_CRIT_P95 and _security_should_emit("host-cpu-critical", SECURITY_SERVER_EVENT_COOLDOWN_SECONDS):
        _security_report_event(
            ip="127.0.0.1",
            attack_type="server_resource_exhaustion",
            direction="inbound->server",
            reason=f"cpu_load_pct={cpu:.1f} crossed critical threshold {CAPACITY_CPU_CRIT_P95:.1f}",
            target="host",
            severity="critical",
            action="mitigated",
            source="server-metrics",
        )
    if mem >= CAPACITY_RAM_CRIT_P95 and _security_should_emit("host-mem-critical", SECURITY_SERVER_EVENT_COOLDOWN_SECONDS):
        _security_report_event(
            ip="127.0.0.1",
            attack_type="server_resource_exhaustion",
            direction="inbound->server",
            reason=f"memory_used_pct={mem:.1f} crossed critical threshold {CAPACITY_RAM_CRIT_P95:.1f}",
            target="host",
            severity="critical",
            action="mitigated",
            source="server-metrics",
        )
    if disk >= CAPACITY_DISK_CRIT_P95 and _security_should_emit("host-disk-critical", SECURITY_SERVER_EVENT_COOLDOWN_SECONDS):
        _security_report_event(
            ip="127.0.0.1",
            attack_type="server_resource_exhaustion",
            direction="inbound->server",
            reason=f"disk_used_pct={disk:.1f} crossed critical threshold {CAPACITY_DISK_CRIT_P95:.1f}",
            target="host",
            severity="high",
            action="mitigated",
            source="server-metrics",
        )

    services = _get_container_statuses()
    if services.get("status") == "ok":
        for item in services.get("items", []):
            state = str(item.get("state") or "")
            name = str(item.get("name") or "unknown")
            if state in {"in_error", "stopped"}:
                key = f"service-{name}-{state}"
                if _security_should_emit(key, SECURITY_SERVER_EVENT_COOLDOWN_SECONDS):
                    _security_report_event(
                        ip="127.0.0.1",
                        attack_type="service_disruption",
                        direction="inbound->server",
                        reason=f"{name} state={state}, raw={item.get('raw_status')}, health={item.get('health')}",
                        target=name,
                        severity="high",
                        action="mitigated",
                        source="server-containers",
                    )
    else:
        if _security_should_emit("docker-status-degraded", SECURITY_SERVER_EVENT_COOLDOWN_SECONDS):
            _security_report_event(
                ip="127.0.0.1",
                attack_type="server_observability_degraded",
                direction="inbound->server",
                reason=str(services.get("reason") or "docker status degraded"),
                target="docker",
                severity="medium",
                action="observed",
                source="server-containers",
            )


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


def _read_server_resource_capacity() -> dict[str, float]:
    cpu = float(max(1, os.cpu_count() or 1))
    ram_gb = 2.0
    storage_gb = 40.0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    ram_kb = float(line.split()[1])
                    ram_gb = max(0.25, round(ram_kb / 1024.0 / 1024.0, 2))
                    break
    except Exception:
        pass
    try:
        disk = os.statvfs("/")
        total = disk.f_blocks * disk.f_frsize
        storage_gb = max(1.0, round(total / (1024.0**3), 2))
    except Exception:
        pass
    return {
        "server_cpu_cores": cpu,
        "server_ram_gb": ram_gb,
        "server_storage_gb": storage_gb,
    }


def _to_pos_float(value: Any, default: float, min_value: float) -> float:
    try:
        v = float(value)
    except Exception:
        return default
    return max(min_value, v)


def _to_pos_int(value: Any, default: int, min_value: int) -> int:
    try:
        v = int(float(value))
    except Exception:
        return default
    return max(min_value, v)


def _normalize_bypass_resources(raw: Any) -> str:
    text = str(raw or "")
    parts = re.split(r"[\n,; ]+", text)
    seen: set[str] = set()
    items: list[str] = []
    for chunk in parts:
        token = chunk.strip().lower()
        if not token or token in seen:
            continue
        seen.add(token)
        items.append(token[:255])
        if len(items) >= 200:
            break
    return "\n".join(items)


def _to_bool_flag(raw: str, default: bool = False) -> bool:
    v = str(raw or "").strip().lower()
    if not v:
        return default
    if v in {"1", "true", "yes", "on"}:
        return True
    if v in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_proxy_bypass_rules_text(text: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in re.split(r"[,\t;]+", line) if p.strip()]
        if not parts:
            continue
        resource = parts[0].lower()[:255]
        if not resource or resource in seen:
            continue
        seen.add(resource)
        # Convention: false => direct/bypass (VPN disabled for resource).
        use_vpn = _to_bool_flag(parts[1], default=False) if len(parts) > 1 else False
        items.append({"resource": resource, "use_vpn": bool(use_vpn)})
        if len(items) >= 500:
            break
    return items


def _serialize_proxy_bypass_rules_text(items: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for row in items:
        if not isinstance(row, dict):
            continue
        resource = str(row.get("resource", "")).strip().lower()
        if not resource:
            continue
        use_vpn = bool(row.get("use_vpn", False))
        lines.append(f"{resource},{'true' if use_vpn else 'false'}")
    return "\n".join(lines)


def _read_proxy_bypass_rules_text(fallback_text: str = "") -> str:
    path = Path(PROXY_BYPASS_RULES_PATH)
    if path.exists():
        try:
            parsed = _parse_proxy_bypass_rules_text(path.read_text(encoding="utf-8"))
            return _serialize_proxy_bypass_rules_text(parsed)
        except Exception:
            pass
    parsed_fallback = _parse_proxy_bypass_rules_text(_normalize_bypass_resources(fallback_text))
    return _serialize_proxy_bypass_rules_text(parsed_fallback)


def _write_proxy_bypass_rules_text(raw_text: str) -> str:
    parsed = _parse_proxy_bypass_rules_text(raw_text)
    serialized = _serialize_proxy_bypass_rules_text(parsed)
    path = Path(PROXY_BYPASS_RULES_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized + ("\n" if serialized else ""), encoding="utf-8")
    return serialized


def _disabled_proxy_bypass_resources(raw_text: str) -> list[str]:
    parsed = _parse_proxy_bypass_rules_text(raw_text)
    return [str(r["resource"]) for r in parsed if not bool(r.get("use_vpn", False))]


def _recalculate_system_config(raw: dict[str, Any]) -> dict[str, Any]:
    cfg = dict(raw)
    cfg["server_cpu_cores"] = _to_pos_float(cfg.get("server_cpu_cores"), 1.0, 0.25)
    cfg["server_ram_gb"] = _to_pos_float(cfg.get("server_ram_gb"), 2.0, 0.25)
    cfg["server_storage_gb"] = _to_pos_float(cfg.get("server_storage_gb"), 40.0, 1.0)
    cfg["traffic_limit_tb"] = _to_pos_float(cfg.get("traffic_limit_tb"), DEFAULT_TRAFFIC_LIMIT_TB, 0.1)
    cfg["avg_user_monthly_traffic_gb"] = _to_pos_float(
        cfg.get("avg_user_monthly_traffic_gb"), DEFAULT_AVG_USER_TRAFFIC_GB, 1.0
    )
    cfg["active_user_ratio_pct"] = _to_pos_float(cfg.get("active_user_ratio_pct"), DEFAULT_ACTIVE_USER_RATIO_PCT, 1.0)
    cfg["cpu_warn_p95"] = _to_pos_float(cfg.get("cpu_warn_p95"), CAPACITY_CPU_WARN_P95, 1.0)
    cfg["cpu_crit_p95"] = _to_pos_float(cfg.get("cpu_crit_p95"), CAPACITY_CPU_CRIT_P95, 1.0)
    cfg["ram_warn_p95"] = _to_pos_float(cfg.get("ram_warn_p95"), CAPACITY_RAM_WARN_P95, 1.0)
    cfg["ram_crit_p95"] = _to_pos_float(cfg.get("ram_crit_p95"), CAPACITY_RAM_CRIT_P95, 1.0)
    cfg["disk_warn_p95"] = _to_pos_float(cfg.get("disk_warn_p95"), CAPACITY_DISK_WARN_P95, 1.0)
    cfg["disk_crit_p95"] = _to_pos_float(cfg.get("disk_crit_p95"), CAPACITY_DISK_CRIT_P95, 1.0)
    cfg["dashboard_refresh_seconds"] = _to_pos_int(
        cfg.get("dashboard_refresh_seconds"), DEFAULT_DASHBOARD_REFRESH_SECONDS, 5
    )
    cfg["dashboard_refresh_seconds"] = min(300, cfg["dashboard_refresh_seconds"])
    cfg["proxy_bypass_custom"] = _serialize_proxy_bypass_rules_text(
        _parse_proxy_bypass_rules_text(str(cfg.get("proxy_bypass_custom", DEFAULT_PROXY_BYPASS_CUSTOM)))
    )

    if cfg["cpu_warn_p95"] > cfg["cpu_crit_p95"]:
        cfg["cpu_warn_p95"] = cfg["cpu_crit_p95"]
    if cfg["ram_warn_p95"] > cfg["ram_crit_p95"]:
        cfg["ram_warn_p95"] = cfg["ram_crit_p95"]
    if cfg["disk_warn_p95"] > cfg["disk_crit_p95"]:
        cfg["disk_warn_p95"] = cfg["disk_crit_p95"]

    traffic_based_limit = int((cfg["traffic_limit_tb"] * 1024.0) / max(1.0, cfg["avg_user_monthly_traffic_gb"]))
    cpu_based_limit = int(cfg["server_cpu_cores"] * 60.0)
    ram_based_limit = int(cfg["server_ram_gb"] * 90.0)
    recommended_max_users = max(1, min(traffic_based_limit, cpu_based_limit, ram_based_limit))
    requested_max_users = _to_pos_int(cfg.get("max_registered_users"), DEFAULT_MAX_REGISTERED_USERS, 0)
    cfg["max_registered_users"] = requested_max_users if requested_max_users > 0 else recommended_max_users
    cfg["recommended_max_users"] = recommended_max_users

    recommended_active_by_ratio = int(cfg["max_registered_users"] * (cfg["active_user_ratio_pct"] / 100.0))
    recommended_active_by_cpu = int(cfg["server_cpu_cores"] * 15.0)
    recommended_active_by_ram = int(cfg["server_ram_gb"] * 10.0)
    recommended_active_users = max(1, min(recommended_active_by_ratio, recommended_active_by_cpu, recommended_active_by_ram))
    requested_target_active = _to_pos_int(cfg.get("target_active_users"), CAPACITY_TARGET_ACTIVE_USERS, 0)
    if requested_target_active <= 0:
        cfg["target_active_users"] = recommended_active_users
    else:
        cfg["target_active_users"] = min(requested_target_active, cfg["max_registered_users"])
    cfg["recommended_active_users"] = recommended_active_users
    cfg["per_user_traffic_budget_gb"] = round((cfg["traffic_limit_tb"] * 1024.0) / max(1, cfg["max_registered_users"]), 2)
    cfg["updated_at"] = _now().isoformat()
    return cfg


def _default_system_config() -> dict[str, Any]:
    detected = _read_server_resource_capacity()
    return _recalculate_system_config(
        {
            **detected,
            "traffic_limit_tb": DEFAULT_TRAFFIC_LIMIT_TB,
            "avg_user_monthly_traffic_gb": DEFAULT_AVG_USER_TRAFFIC_GB,
            "active_user_ratio_pct": DEFAULT_ACTIVE_USER_RATIO_PCT,
            "max_registered_users": DEFAULT_MAX_REGISTERED_USERS,
            "target_active_users": CAPACITY_TARGET_ACTIVE_USERS,
            "cpu_warn_p95": CAPACITY_CPU_WARN_P95,
            "cpu_crit_p95": CAPACITY_CPU_CRIT_P95,
            "ram_warn_p95": CAPACITY_RAM_WARN_P95,
            "ram_crit_p95": CAPACITY_RAM_CRIT_P95,
            "disk_warn_p95": CAPACITY_DISK_WARN_P95,
            "disk_crit_p95": CAPACITY_DISK_CRIT_P95,
            "dashboard_refresh_seconds": DEFAULT_DASHBOARD_REFRESH_SECONDS,
            "proxy_bypass_custom": DEFAULT_PROXY_BYPASS_CUSTOM,
        }
    )


def _load_system_config() -> dict[str, Any]:
    with _db_connect() as con:
        row = con.execute(
            """
            SELECT
              server_cpu_cores, server_ram_gb, server_storage_gb, traffic_limit_tb,
              avg_user_monthly_traffic_gb, active_user_ratio_pct,
              max_registered_users, target_active_users,
              cpu_warn_p95, cpu_crit_p95, ram_warn_p95, ram_crit_p95, disk_warn_p95, disk_crit_p95,
              dashboard_refresh_seconds, proxy_bypass_custom,
              recommended_max_users, recommended_active_users, per_user_traffic_budget_gb, updated_at
            FROM system_config
            WHERE id = 1
            """
        ).fetchone()
    if not row:
        return _default_system_config()
    cfg = dict(row)
    cfg["proxy_bypass_custom"] = _read_proxy_bypass_rules_text(str(cfg.get("proxy_bypass_custom", "")))
    return _recalculate_system_config(cfg)


def _persist_system_config(cfg: dict[str, Any]) -> dict[str, Any]:
    calculated = _recalculate_system_config(cfg)
    calculated["proxy_bypass_custom"] = _write_proxy_bypass_rules_text(str(calculated.get("proxy_bypass_custom", "")))
    with _db_connect() as con:
        con.execute(
            """
            INSERT INTO system_config (
              id, server_cpu_cores, server_ram_gb, server_storage_gb, traffic_limit_tb,
              avg_user_monthly_traffic_gb, active_user_ratio_pct,
              max_registered_users, target_active_users,
              cpu_warn_p95, cpu_crit_p95, ram_warn_p95, ram_crit_p95, disk_warn_p95, disk_crit_p95,
              dashboard_refresh_seconds, proxy_bypass_custom,
              recommended_max_users, recommended_active_users, per_user_traffic_budget_gb, updated_at
            ) VALUES (
              1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(id) DO UPDATE SET
              server_cpu_cores=excluded.server_cpu_cores,
              server_ram_gb=excluded.server_ram_gb,
              server_storage_gb=excluded.server_storage_gb,
              traffic_limit_tb=excluded.traffic_limit_tb,
              avg_user_monthly_traffic_gb=excluded.avg_user_monthly_traffic_gb,
              active_user_ratio_pct=excluded.active_user_ratio_pct,
              max_registered_users=excluded.max_registered_users,
              target_active_users=excluded.target_active_users,
              cpu_warn_p95=excluded.cpu_warn_p95,
              cpu_crit_p95=excluded.cpu_crit_p95,
              ram_warn_p95=excluded.ram_warn_p95,
              ram_crit_p95=excluded.ram_crit_p95,
              disk_warn_p95=excluded.disk_warn_p95,
              disk_crit_p95=excluded.disk_crit_p95,
              dashboard_refresh_seconds=excluded.dashboard_refresh_seconds,
              proxy_bypass_custom=excluded.proxy_bypass_custom,
              recommended_max_users=excluded.recommended_max_users,
              recommended_active_users=excluded.recommended_active_users,
              per_user_traffic_budget_gb=excluded.per_user_traffic_budget_gb,
              updated_at=excluded.updated_at
            """,
            (
                calculated["server_cpu_cores"],
                calculated["server_ram_gb"],
                calculated["server_storage_gb"],
                calculated["traffic_limit_tb"],
                calculated["avg_user_monthly_traffic_gb"],
                calculated["active_user_ratio_pct"],
                calculated["max_registered_users"],
                calculated["target_active_users"],
                calculated["cpu_warn_p95"],
                calculated["cpu_crit_p95"],
                calculated["ram_warn_p95"],
                calculated["ram_crit_p95"],
                calculated["disk_warn_p95"],
                calculated["disk_crit_p95"],
                calculated["dashboard_refresh_seconds"],
                calculated["proxy_bypass_custom"],
                calculated["recommended_max_users"],
                calculated["recommended_active_users"],
                calculated["per_user_traffic_budget_gb"],
                calculated["updated_at"],
            ),
        )
        con.commit()
    return calculated


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


def _read_update_audit(
    limit: int = 50,
    status: str = "",
    branch: str = "",
    file_q: str = "",
    commit_q: str = "",
    date_from: str = "",
    date_to: str = "",
) -> dict[str, Any]:
    limit = max(1, min(300, int(limit)))
    status_q = status.strip().lower()
    branch_q = branch.strip().lower()
    file_q = file_q.strip().lower()
    commit_q = commit_q.strip().lower()
    date_from = date_from.strip()
    date_to = date_to.strip()
    path = Path(UPDATE_AUDIT_PATH)
    if not path.exists():
        return {
            "status": "ok",
            "path": str(path),
            "items": [],
            "reason": "update audit file not found yet",
            "filters": {
                "status": status_q,
                "branch": branch_q,
                "file_q": file_q,
                "commit_q": commit_q,
                "date_from": date_from,
                "date_to": date_to,
            },
        }
    try:
        rows = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(item, dict):
                    continue
                ts = str(item.get("ts", ""))
                st = str(item.get("status", "")).lower()
                br = str(item.get("branch", "")).lower()
                if status_q and st != status_q:
                    continue
                if branch_q and br != branch_q:
                    continue
                if date_from and ts and ts < date_from:
                    continue
                if date_to and ts and ts > date_to:
                    continue
                commits = item.get("commits") if isinstance(item.get("commits"), list) else []
                files = item.get("files") if isinstance(item.get("files"), list) else []
                commit_text = " ".join(
                    str(c.get("title", ""))
                    for c in commits
                    if isinstance(c, dict)
                ).lower()
                file_text = " ".join(
                    str(fi.get("path", ""))
                    for fi in files
                    if isinstance(fi, dict)
                ).lower()
                if commit_q and commit_q not in commit_text:
                    continue
                if file_q and file_q not in file_text:
                    continue
                rows.append(item)
    except Exception as e:
        return {"status": "degraded", "path": str(path), "items": [], "reason": f"read error: {e}"}
    rows = rows[-limit:]
    rows.reverse()
    return {
        "status": "ok",
        "path": str(path),
        "items": rows,
        "filters": {
            "status": status_q,
            "branch": branch_q,
            "file_q": file_q,
            "commit_q": commit_q,
            "date_from": date_from,
            "date_to": date_to,
        },
    }


def _default_release_state() -> dict[str, Any]:
    return {
        "status": "ok",
        "state": {
            "current": {
                "version": "unknown",
                "sha": "na",
                "notes": "No release metadata yet.",
                "deployed_at": _now().isoformat(),
            },
            "available": None,
            "update": {"status": "idle", "message": "No update metadata yet."},
        },
    }


def _read_release_state() -> dict[str, Any]:
    path = Path(APP_RELEASE_STATE_PATH)
    if not path.exists():
        return _default_release_state()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return {"status": "degraded", "reason": f"release state read error: {e}", "state": _default_release_state()["state"]}
    if not isinstance(raw, dict):
        return _default_release_state()
    state = raw if "current" in raw else raw.get("state", {})
    if not isinstance(state, dict):
        state = {}
    current = state.get("current") if isinstance(state.get("current"), dict) else {}
    available = state.get("available")
    update = state.get("update") if isinstance(state.get("update"), dict) else {}
    merged = _default_release_state()["state"]
    merged["current"].update(current)
    merged["available"] = available if isinstance(available, dict) else None
    merged["update"].update(update)
    return {"status": "ok", "state": merged}


def _write_update_request(path_str: str, request: dict[str, Any]) -> dict[str, Any]:
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(request)
    payload["requested_at"] = _now().isoformat()
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return {"status": "ok", "path": str(path), "request": payload}


def _default_backup_state() -> dict[str, Any]:
    return {
        "status": "ok",
        "backup_status": "unknown",
        "updated_at": None,
        "last_success_at": None,
        "message": "No backup status yet.",
        "integrity": {"status": "unknown", "reason": "No integrity data yet."},
        "archive_path": "",
        "path": str(Path(BACKUP_STATUS_PATH)),
    }


def _read_backup_state() -> dict[str, Any]:
    path = Path(BACKUP_STATUS_PATH)
    base = _default_backup_state()
    base["path"] = str(path)
    if not path.exists():
        base["reason"] = "backup status file not found yet"
        return base
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        base["status"] = "degraded"
        base["reason"] = f"backup status read error: {e}"
        return base
    if not isinstance(raw, dict):
        base["status"] = "degraded"
        base["reason"] = "backup status payload is not an object"
        return base
    merged = dict(base)
    merged.update(
        {
            "status": str(raw.get("status", base["status"])),
            "backup_status": str(raw.get("backup_status", base["backup_status"])),
            "updated_at": raw.get("updated_at"),
            "last_success_at": raw.get("last_success_at"),
            "message": str(raw.get("message", base["message"])),
            "archive_path": str(raw.get("archive_path", "")),
        }
    )
    integ = raw.get("integrity")
    if isinstance(integ, dict):
        merged["integrity"] = {
            "status": str(integ.get("status", "unknown")),
            "reason": str(integ.get("reason", "")),
        }
    return merged


def _read_security_events(limit: int = 150) -> dict[str, Any]:
    limit = max(1, min(500, int(limit)))
    data = _security_guard_call("GET", f"/events?limit={limit}")
    if data.get("status") != "ok":
        return {"status": "degraded", "items": [], "reason": data.get("reason", SECURITY_GUARD_UNAVAILABLE_REASON)}
    items = data.get("items")
    if not isinstance(items, list):
        items = []
    return {"status": "ok", "items": items}


def _read_security_blocked(limit: int = 150) -> dict[str, Any]:
    limit = max(1, min(500, int(limit)))
    data = _security_guard_call("GET", f"/blocked?limit={limit}")
    if data.get("status") != "ok":
        return {"status": "degraded", "items": [], "reason": data.get("reason", SECURITY_GUARD_UNAVAILABLE_REASON)}
    items = data.get("items")
    if not isinstance(items, list):
        items = []
    return {"status": "ok", "items": items}


def _security_manual_block(ip: str, reason: str, block_seconds: int) -> dict[str, Any]:
    payload = {
        "ip": ip.strip(),
        "reason": reason.strip() or "manual block",
        "block_seconds": max(60, int(block_seconds)),
    }
    data = _security_guard_call("POST", "/block", payload)
    if data.get("status") != "ok":
        return {"status": "degraded", "reason": data.get("reason", SECURITY_GUARD_UNAVAILABLE_REASON)}
    return {"status": "ok", "result": data}


def _security_manual_unblock(ip: str, reason: str) -> dict[str, Any]:
    payload = {"ip": ip.strip(), "reason": reason.strip() or "manual unblock"}
    data = _security_guard_call("POST", "/unblock", payload)
    if data.get("status") != "ok":
        return {"status": "degraded", "reason": data.get("reason", SECURITY_GUARD_UNAVAILABLE_REASON)}
    return {"status": "ok", "result": data}


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * p)))
    return float(ordered[idx])


def _signal_by_threshold(value: float, warn: float, crit: float) -> str:
    if value >= crit:
        return "critical"
    if value >= warn:
        return "warn"
    return "ok"


def _read_capacity_status(window_minutes: int = 60) -> dict[str, Any]:
    window_minutes = max(10, min(24 * 60, int(window_minutes)))
    threshold = (_now() - timedelta(minutes=window_minutes)).isoformat()
    month_threshold = (_now() - timedelta(days=30)).isoformat()
    cfg = _load_system_config()
    with _db_connect() as con:
        rows = con.execute(
            """
            SELECT cpu_load_pct, memory_used_pct, disk_used_pct, net_rx_bytes, net_tx_bytes
            FROM metric_samples
            WHERE ts >= ?
            ORDER BY ts ASC
            """,
            (threshold,),
        ).fetchall()
        month_rows = con.execute(
            """
            SELECT net_rx_bytes, net_tx_bytes
            FROM metric_samples
            WHERE ts >= ?
            ORDER BY ts ASC
            """,
            (month_threshold,),
        ).fetchall()
        online_threshold = (_now() - timedelta(seconds=ONLINE_WINDOW_SECONDS)).isoformat()
        active_sessions_row = con.execute(
            """
            SELECT COUNT(DISTINCT user_id) c
            FROM sessions
            WHERE revoked = 0
              AND expires_at > ?
              AND COALESCE(last_seen, created_at) >= ?
            """,
            (_now().isoformat(), online_threshold),
        ).fetchone()
    if not rows:
        return {
            "status": "degraded",
            "reason": "no metric samples in selected window",
            "window_minutes": window_minutes,
        }

    cpu = [float(r["cpu_load_pct"] or 0.0) for r in rows]
    mem = [float(r["memory_used_pct"] or 0.0) for r in rows]
    disk = [float(r["disk_used_pct"] or 0.0) for r in rows]
    rx0 = int(rows[0]["net_rx_bytes"] or 0)
    tx0 = int(rows[0]["net_tx_bytes"] or 0)
    rx1 = int(rows[-1]["net_rx_bytes"] or 0)
    tx1 = int(rows[-1]["net_tx_bytes"] or 0)

    cpu_p95 = round(_percentile(cpu, 0.95), 2)
    mem_p95 = round(_percentile(mem, 0.95), 2)
    disk_p95 = round(_percentile(disk, 0.95), 2)
    cpu_avg = round(sum(cpu) / len(cpu), 2)
    mem_avg = round(sum(mem) / len(mem), 2)
    disk_avg = round(sum(disk) / len(disk), 2)
    cpu_current_pct = float(rows[-1]["cpu_load_pct"] or 0.0)
    mem_current_pct = float(rows[-1]["memory_used_pct"] or 0.0)
    disk_current_pct = float(rows[-1]["disk_used_pct"] or 0.0)
    active_sessions = int(active_sessions_row["c"] or 0) if active_sessions_row else 0
    detected = _read_server_resource_capacity()
    month_rx_used = 0
    month_tx_used = 0
    if month_rows:
        month_rx_used = max(0, int(month_rows[-1]["net_rx_bytes"] or 0) - int(month_rows[0]["net_rx_bytes"] or 0))
        month_tx_used = max(0, int(month_rows[-1]["net_tx_bytes"] or 0) - int(month_rows[0]["net_tx_bytes"] or 0))
    traffic_month_used_bytes = month_rx_used + month_tx_used
    traffic_limit_bytes = int(float(cfg["traffic_limit_tb"]) * (1024.0**4))
    traffic_left_bytes = max(0, traffic_limit_bytes - traffic_month_used_bytes)
    traffic_left_pct = round((traffic_left_bytes / traffic_limit_bytes) * 100.0, 2) if traffic_limit_bytes > 0 else 0.0
    traffic_window_total_bytes = max(0, rx1 - rx0) + max(0, tx1 - tx0)
    signals = {
        "cpu": _signal_by_threshold(cpu_p95, float(cfg["cpu_warn_p95"]), float(cfg["cpu_crit_p95"])),
        "memory": _signal_by_threshold(mem_p95, float(cfg["ram_warn_p95"]), float(cfg["ram_crit_p95"])),
        "disk": _signal_by_threshold(disk_p95, float(cfg["disk_warn_p95"]), float(cfg["disk_crit_p95"])),
        "concurrency": "warn" if active_sessions > int(cfg["target_active_users"]) else "ok",
    }
    overall = "ok"
    if "critical" in signals.values():
        overall = "critical"
    elif "warn" in signals.values():
        overall = "warn"

    return {
        "status": "ok",
        "window_minutes": window_minutes,
        "target_active_users": int(cfg["target_active_users"]),
        "samples": len(rows),
        "overall": overall,
        "signals": signals,
        "active_sessions": active_sessions,
        "avg": {"cpu_pct": cpu_avg, "mem_pct": mem_avg, "disk_pct": disk_avg},
        "p95": {"cpu_pct": cpu_p95, "mem_pct": mem_p95, "disk_pct": disk_p95},
        "traffic_window_bytes": {"rx": max(0, rx1 - rx0), "tx": max(0, tx1 - tx0)},
        "runtime": {
            "detected": {
                "cpu_cores": float(detected["server_cpu_cores"]),
                "ram_gb": float(detected["server_ram_gb"]),
                "storage_gb": float(detected["server_storage_gb"]),
            },
            "usage": {
                "cpu_current_pct": round(cpu_current_pct, 2),
                "cpu_used_cores": round((cpu_current_pct / 100.0) * float(detected["server_cpu_cores"]), 2),
                "ram_current_pct": round(mem_current_pct, 2),
                "ram_used_gb": round((mem_current_pct / 100.0) * float(detected["server_ram_gb"]), 2),
                "disk_current_pct": round(disk_current_pct, 2),
                "disk_used_gb": round((disk_current_pct / 100.0) * float(detected["server_storage_gb"]), 2),
                "traffic_month_used_bytes": int(traffic_month_used_bytes),
                "traffic_month_left_bytes": int(traffic_left_bytes),
                "traffic_left_pct": float(traffic_left_pct),
                "traffic_increment_window_bytes": int(traffic_window_total_bytes),
            },
        },
        "thresholds": {
            "cpu_warn_p95": float(cfg["cpu_warn_p95"]),
            "cpu_crit_p95": float(cfg["cpu_crit_p95"]),
            "ram_warn_p95": float(cfg["ram_warn_p95"]),
            "ram_crit_p95": float(cfg["ram_crit_p95"]),
            "disk_warn_p95": float(cfg["disk_warn_p95"]),
            "disk_crit_p95": float(cfg["disk_crit_p95"]),
        },
        "config": {
            "server_cpu_cores": float(cfg["server_cpu_cores"]),
            "server_ram_gb": float(cfg["server_ram_gb"]),
            "server_storage_gb": float(cfg["server_storage_gb"]),
            "traffic_limit_tb": float(cfg["traffic_limit_tb"]),
            "max_registered_users": int(cfg["max_registered_users"]),
            "dashboard_refresh_seconds": int(cfg["dashboard_refresh_seconds"]),
            "recommended_max_users": int(cfg["recommended_max_users"]),
            "recommended_active_users": int(cfg["recommended_active_users"]),
            "per_user_traffic_budget_gb": float(cfg["per_user_traffic_budget_gb"]),
        },
        "upgrade_trigger": "Scale when overall=critical or warnings persist >15 min.",
    }


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
        value_match = XRAY_VALUE_RE.search(line)
        if value_match:
            bytes_raw = value_match.group(1)
        else:
            parts = line.replace("\t", " ").split()
            bytes_raw = parts[-1] if parts else "0"
            if ":" in bytes_raw:
                bytes_raw = bytes_raw.rsplit(":", 1)[-1]
        current = totals.setdefault(email, {"uplink": 0, "downlink": 0})
        try:
            current[direction] = int(bytes_raw)
        except ValueError:
            continue
    return totals


def _sync_xray_bindings_from_profiles(con: sqlite3.Connection) -> None:
    rows = con.execute(
        """
        SELECT user_id, xray_email
        FROM user_access_profiles
        WHERE xray_email IS NOT NULL AND xray_email != ''
        """
    ).fetchall()
    for row in rows:
        user_id = int(row["user_id"])
        email = str(row["xray_email"]).strip().lower()
        if not email:
            continue
        con.execute(
            """
            INSERT INTO xray_client_bindings (user_id, client_email, label, created_at)
            VALUES (?, ?, 'auto-profile', ?)
            ON CONFLICT(client_email)
            DO UPDATE SET user_id = excluded.user_id
            """,
            (user_id, email, _now().isoformat()),
        )


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


def _ensure_xray_binding_for_user(user_id: int, client_email: str, label: str = "auto-profile") -> None:
    key = str(client_email or "").strip().lower()
    if not key:
        return
    with _db_connect() as con:
        exists = con.execute(
            "SELECT id FROM xray_client_bindings WHERE client_email = ?",
            (key,),
        ).fetchone()
        if exists:
            con.execute(
                """
                UPDATE xray_client_bindings
                SET user_id = ?, label = COALESCE(NULLIF(label, ''), ?)
                WHERE client_email = ?
                """,
                (int(user_id), str(label or "auto-profile"), key),
            )
        else:
            con.execute(
                """
                INSERT INTO xray_client_bindings (user_id, client_email, label, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (int(user_id), key, str(label or "auto-profile"), _now().isoformat()),
            )
        con.commit()


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


def _refresh_user_traffic_samples_once() -> None:
    ts_iso = _now().isoformat()
    with _db_connect() as con:
        _sync_xray_bindings_from_profiles(con)
        _collect_wireguard_user_traffic(con, ts_iso)
        _collect_xray_user_traffic(con, ts_iso)
        con.commit()


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
        _security_track_server_state(snapshot)
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
        ("/about", "about", "About"),
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
            f"<button class='btn-ghost' style='margin-top:8px;width:100%;' data-action='sidebar-logout'>Logout</button>"
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
      --link: #1d4ed8;
      --input-bg: rgba(255,255,255,0.76);
      --soft-bg: rgba(255,255,255,0.55);
      --hover-bg: rgba(255,255,255,0.6);
      --code-bg: rgba(248,250,252,0.9);
      --code-text: #0f172a;
      --ghost-bg: rgba(15,23,42,0.06);
      --ghost-text: #0f172a;
      --banner-bg: rgba(37,99,235,0.08);
      --banner-stroke: rgba(37,99,235,0.25);
      --banner-text: #1e3a8a;
      --shadow: 0 20px 40px rgba(15, 23, 42, 0.16);
    }}
    body[data-theme="dark"] {{
      --bg-1: #0b1220;
      --bg-2: #111827;
      --panel: rgba(15, 23, 42, 0.74);
      --panel-strong: rgba(17, 24, 39, 0.9);
      --stroke: rgba(148, 163, 184, 0.22);
      --text: #e5e7eb;
      --muted: #94a3b8;
      --blue: #3b82f6;
      --link: #93c5fd;
      --input-bg: rgba(15, 23, 42, 0.74);
      --soft-bg: rgba(15, 23, 42, 0.6);
      --hover-bg: rgba(59,130,246,0.14);
      --code-bg: rgba(2, 6, 23, 0.75);
      --code-text: #e2e8f0;
      --ghost-bg: rgba(148,163,184,0.2);
      --ghost-text: #e2e8f0;
      --banner-bg: rgba(59,130,246,0.14);
      --banner-stroke: rgba(147,197,253,0.35);
      --banner-text: #dbeafe;
      --shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
    }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(1200px 600px at 10% -20%, #bfd4ff 0%, var(--bg-2) 40%, var(--bg-1) 100%);
      color: var(--text);
      min-height: 100vh;
      color-scheme: light;
    }}
    body[data-theme="dark"] {{
      color-scheme: dark;
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
      background: var(--hover-bg);
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
      background: var(--soft-bg);
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
    .app-footer {{
      margin-top: 8px;
      font-size: 13px;
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      padding: 10px 4px 2px;
    }}
    .card {{
      background: var(--panel-strong);
      border: 1px solid var(--stroke);
      border-radius: 16px;
      padding: 16px;
      margin-bottom: 16px;
      box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);
      overflow-x: auto;
    }}
    a {{
      color: var(--link);
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
      background: var(--input-bg);
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
      background: var(--code-bg);
      padding: 12px;
      border-radius: 8px;
      border: 1px solid var(--stroke);
      color: var(--code-text);
    }}
    table {{
      font-size: 14px;
      min-width: 560px;
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
      background: var(--ghost-bg);
      color: var(--ghost-text);
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
    #update-banner {{
      display: none;
      margin: 0 0 10px 0;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--banner-stroke);
      background: var(--banner-bg);
      color: var(--banner-text);
    }}
    .theme-toggle {{
      padding: 7px 10px;
      border-radius: 999px;
      border: 1px solid var(--stroke);
      background: var(--soft-bg);
      color: var(--text);
      cursor: pointer;
      font-size: 13px;
    }}
    @media (max-width: 900px) {{
      .app {{
        grid-template-columns: 1fr;
        margin: 10px auto;
        padding: 0 10px 10px;
      }}
      .sidebar {{
        height: auto;
        position: static;
        gap: 10px;
      }}
      .nav {{
        flex-direction: row;
        flex-wrap: wrap;
      }}
      .nav-item {{
        flex: 1 1 140px;
      }}
      .topbar {{
        align-items: flex-start;
        flex-wrap: wrap;
      }}
      .user-meta-row {{
        grid-template-columns: 1fr;
        gap: 2px;
      }}
      .app-footer {{
        flex-direction: column;
        align-items: flex-start;
        gap: 6px;
      }}
    }}
    @media (max-width: 900px) and (orientation: landscape) {{
      .app {{
        grid-template-columns: 220px 1fr;
      }}
      .sidebar {{
        position: sticky;
        top: 10px;
        max-height: calc(100vh - 20px);
        overflow: auto;
      }}
      .nav {{
        flex-direction: column;
      }}
      .nav-item {{
        flex: 0 0 auto;
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
        <div style="display:flex;align-items:center;gap:8px;">
          <button id="theme-toggle-btn" class="theme-toggle" data-action="toggle-theme">Night mode</button>
          <span id="app-version-badge" class="status-pill status-stopped">version: -</span>
        </div>
      </div>
      <div id="update-banner"></div>
      <div class="wrap">{body}</div>
      <div class="app-footer">
        <div>Author: Dmitry Solonnikov · Telegram: <a href="https://t.me/Dmitry_as_Solod" target="_blank" rel="noopener noreferrer">@Dmitry_as_Solod</a></div>
        <div>License: <a href="/license">MIT</a></div>
      </div>
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
function applyTheme(theme) {{
  const t = theme === 'dark' ? 'dark' : 'light';
  document.body.setAttribute('data-theme', t);
  localStorage.setItem('proxy_vpn_theme', t);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = t === 'dark' ? 'Light mode' : 'Night mode';
}}
function detectPreferredTheme() {{
  const saved = localStorage.getItem('proxy_vpn_theme');
  if (saved === 'dark' || saved === 'light') return saved;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}}
function toggleTheme() {{
  const current = document.body.getAttribute('data-theme') || detectPreferredTheme();
  applyTheme(current === 'dark' ? 'light' : 'dark');
}}
async function refreshGlobalReleaseState() {{
  const versionEl = document.getElementById('app-version-badge');
  const banner = document.getElementById('update-banner');
  if (!versionEl || !banner) return;
  try {{
    const r = await fetch('/api/v1/app/about');
    if (!r.ok) return;
    const j = await r.json();
    const state = j.state || {{}};
    const current = state.current || {{}};
    const available = state.available || null;
    const update = state.update || {{}};
    const currentVersion = String(current.version || 'unknown');
    versionEl.textContent = 'version: ' + currentVersion;
    if (available && available.version && available.version !== currentVersion) {{
      banner.style.display = 'block';
      const msg = update.message || 'Update available.';
      banner.innerHTML = `Update available: <b>${{available.version}}</b>. ${{msg}}` +
        ` <a href="/about">Open About</a>`;
    }} else {{
      banner.style.display = 'none';
      banner.textContent = '';
    }}
  }} catch (e) {{
    // keep UI stable if release endpoint is unavailable
  }}
}}
applyTheme(detectPreferredTheme());
refreshGlobalReleaseState();
setInterval(refreshGlobalReleaseState, 30000);
document.addEventListener('click', (event) => {{
  const target = event.target;
  if (!target || !target.closest) return;
  const btn = target.closest('[data-action]');
  if (!btn) return;
  const action = String(btn.getAttribute('data-action') || '').trim();
  if (action === 'sidebar-logout') return void sidebarLogout();
  if (action === 'toggle-theme') return void toggleTheme();
}});
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


class AdminConfiguratorUpdateRequest(BaseModel):
    server_cpu_cores: float
    server_ram_gb: float
    server_storage_gb: float
    traffic_limit_tb: float
    avg_user_monthly_traffic_gb: float
    active_user_ratio_pct: float
    max_registered_users: int
    target_active_users: int
    cpu_warn_p95: float
    cpu_crit_p95: float
    ram_warn_p95: float
    ram_crit_p95: float
    disk_warn_p95: float
    disk_crit_p95: float
    dashboard_refresh_seconds: int
    proxy_bypass_custom: str = ""


class AdminSecurityBlockRequest(BaseModel):
    ip: str
    reason: Optional[str] = None
    block_seconds: int = 900


class AdminSecurityUnblockRequest(BaseModel):
    ip: str
    reason: Optional[str] = None


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
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS system_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                server_cpu_cores REAL NOT NULL,
                server_ram_gb REAL NOT NULL,
                server_storage_gb REAL NOT NULL,
                traffic_limit_tb REAL NOT NULL,
                avg_user_monthly_traffic_gb REAL NOT NULL,
                active_user_ratio_pct REAL NOT NULL,
                max_registered_users INTEGER NOT NULL,
                target_active_users INTEGER NOT NULL,
                cpu_warn_p95 REAL NOT NULL,
                cpu_crit_p95 REAL NOT NULL,
                ram_warn_p95 REAL NOT NULL,
                ram_crit_p95 REAL NOT NULL,
                disk_warn_p95 REAL NOT NULL,
                disk_crit_p95 REAL NOT NULL,
                dashboard_refresh_seconds INTEGER NOT NULL DEFAULT 30,
                proxy_bypass_custom TEXT NOT NULL DEFAULT '',
                recommended_max_users INTEGER NOT NULL,
                recommended_active_users INTEGER NOT NULL,
                per_user_traffic_budget_gb REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(
            con,
            "system_config",
            "dashboard_refresh_seconds",
            f"dashboard_refresh_seconds INTEGER NOT NULL DEFAULT {DEFAULT_DASHBOARD_REFRESH_SECONDS}",
        )
        _ensure_column(
            con,
            "system_config",
            "proxy_bypass_custom",
            "proxy_bypass_custom TEXT NOT NULL DEFAULT ''",
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
        elif settings.admin_sync_on_start:
            admin_row = con.execute(
                "SELECT id, email, password_hash, role, is_active FROM users WHERE id = ?",
                (int(row["id"]),),
            ).fetchone()
            if admin_row:
                updates: list[str] = []
                values: list[Any] = []
                if settings.admin_email and settings.admin_email != str(admin_row["email"] or ""):
                    updates.append("email = ?")
                    values.append(settings.admin_email)
                stored_hash = str(admin_row["password_hash"] or "")
                if settings.admin_password and (not stored_hash or not _verify_password(settings.admin_password, stored_hash)):
                    updates.append("password_hash = ?")
                    values.append(_hash_password(settings.admin_password))
                if str(admin_row["role"] or "") != "admin":
                    updates.append("role = 'admin'")
                if int(admin_row["is_active"] or 0) != 1:
                    updates.append("is_active = 1")
                if updates:
                    values.append(int(admin_row["id"]))
                    con.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", tuple(values))
        cfg_row = con.execute("SELECT id FROM system_config WHERE id = 1").fetchone()
        if not cfg_row:
            defaults = _default_system_config()
            defaults["proxy_bypass_custom"] = _write_proxy_bypass_rules_text(str(defaults.get("proxy_bypass_custom", "")))
            con.execute(
                """
                INSERT INTO system_config (
                  id, server_cpu_cores, server_ram_gb, server_storage_gb, traffic_limit_tb,
                  avg_user_monthly_traffic_gb, active_user_ratio_pct,
                  max_registered_users, target_active_users,
                  cpu_warn_p95, cpu_crit_p95, ram_warn_p95, ram_crit_p95, disk_warn_p95, disk_crit_p95,
                  dashboard_refresh_seconds, proxy_bypass_custom,
                  recommended_max_users, recommended_active_users, per_user_traffic_budget_gb, updated_at
                ) VALUES (
                  1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    defaults["server_cpu_cores"],
                    defaults["server_ram_gb"],
                    defaults["server_storage_gb"],
                    defaults["traffic_limit_tb"],
                    defaults["avg_user_monthly_traffic_gb"],
                    defaults["active_user_ratio_pct"],
                    defaults["max_registered_users"],
                    defaults["target_active_users"],
                    defaults["cpu_warn_p95"],
                    defaults["cpu_crit_p95"],
                    defaults["ram_warn_p95"],
                    defaults["ram_crit_p95"],
                    defaults["disk_warn_p95"],
                    defaults["disk_crit_p95"],
                    defaults["dashboard_refresh_seconds"],
                    defaults["proxy_bypass_custom"],
                    defaults["recommended_max_users"],
                    defaults["recommended_active_users"],
                    defaults["per_user_traffic_budget_gb"],
                    defaults["updated_at"],
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


@app.get("/about", response_class=HTMLResponse)
def about_page(request: Request) -> HTMLResponse:
    user = _read_current_user(request)
    is_admin = bool(user and user.get("role") == "admin")
    admin_controls = (
        """
  <div style="display:flex;gap:8px;align-items:center;">
    <button data-action="about-check-updates">Check updates</button>
    <button data-action="about-apply-update">Update now</button>
  </div>
"""
        if is_admin
        else """
  <div style="display:flex;gap:8px;align-items:center;">
    <button disabled title="Only admin can run update checks">Check updates</button>
    <button disabled title="Only admin can apply updates">Update now</button>
  </div>
  <p class="muted">Only admin can run update checks and apply updates.</p>
"""
    )
    return _page(
        "About application",
        f"""
<div class="card">
  <h2>About proxy-vpn</h2>
  <p class="muted">Version and update channel info from server release metadata.</p>
  <div class="user-meta-row"><div class="label-muted">Current version</div><div id="about-current-version">-</div></div>
  <div class="user-meta-row"><div class="label-muted">Current build</div><div id="about-current-sha">-</div></div>
  <div class="user-meta-row"><div class="label-muted">Deployed at</div><div id="about-current-at">-</div></div>
  <div class="user-meta-row"><div class="label-muted">Available update</div><div id="about-available-version">-</div></div>
  <div class="user-meta-row"><div class="label-muted">Update status</div><div id="about-update-status">-</div></div>
  <h3 style="margin-top:12px;">Release notes</h3>
  <pre id="about-release-notes">Loading...</pre>
  <h3 style="margin-top:12px;">Updates history</h3>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Time (UTC)</th><th align="left">Status</th><th align="left">From</th><th align="left">To</th><th align="left">Commit</th></tr>
    </thead>
    <tbody id="about-history-body"><tr><td colspan="5" class="muted">Loading...</td></tr></tbody>
  </table>
  <p class="muted" id="about-history-meta"></p>
  <h3 style="margin-top:12px;">Authorship, rights and license</h3>
  <div class="user-meta-row"><div class="label-muted">Author</div><div>Dmitry Solonnikov</div></div>
  <div class="user-meta-row"><div class="label-muted">Contacts</div><div><a href="https://t.me/Dmitry_as_Solod" target="_blank" rel="noopener noreferrer">@Dmitry_as_Solod</a></div></div>
  <div class="user-meta-row"><div class="label-muted">Copyright</div><div>Copyright (c) 2026 Dmitry Solonnikov</div></div>
  <div class="user-meta-row"><div class="label-muted">License</div><div><a href="/license">MIT License</a> · <a href="https://opensource.org/licenses/MIT" target="_blank" rel="noopener noreferrer">opensource.org</a></div></div>
  {admin_controls}
  <pre id="about-out">Ready.</pre>
</div>
<script>
const aboutCsrfToken = {repr(user["csrf_token"] if user else "")};
const aboutEscHtml = (s) => String((s === undefined || s === null) ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
function aboutHeaderToken() {{
  const m = document.cookie.match(/(?:^|; )proxy_vpn_csrf=([^;]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  return aboutCsrfToken;
}}
function aboutFirstCommitTitle(item) {{
  const commits = Array.isArray(item && item.commits) ? item.commits : [];
  if (!commits.length) return '-';
  const first = commits[0] || {{}};
  return String(first.title || first.sha || '-');
}}
function renderAboutHistory(items) {{
  const body = document.getElementById('about-history-body');
  const meta = document.getElementById('about-history-meta');
  if (!body) return;
  if (!items || items.length === 0) {{
    body.innerHTML = '<tr><td colspan="5" class="muted">No updates history yet.</td></tr>';
    if (meta) meta.textContent = 'No applied updates found.';
    return;
  }}
  body.innerHTML = items.map(i => `<tr>
    <td>${{aboutEscHtml(i.ts || '-')}}</td>
    <td>${{aboutEscHtml(i.status || '-')}}</td>
    <td><code>${{aboutEscHtml(i.from || '-')}}</code></td>
    <td><code>${{aboutEscHtml(i.to || '-')}}</code></td>
    <td>${{aboutEscHtml(aboutFirstCommitTitle(i))}}</td>
  </tr>`).join('');
  if (meta) meta.textContent = 'Records: ' + items.length;
}}
async function loadAboutState() {{
  const r = await fetch('/api/v1/app/about');
  const txt = await r.text();
  if (!r.ok) {{
    const out = document.getElementById('about-out');
    if (out) out.textContent = txt;
    return;
  }}
  let j = null;
  try {{ j = JSON.parse(txt); }} catch (e) {{ j = null; }}
  if (!j) return;
  const s = j.state || {{}};
  const cur = s.current || {{}};
  const av = s.available || null;
  const up = s.update || {{}};
  const notes = av && av.notes ? av.notes : (cur.notes || '-');
  const vCur = String(cur.version || 'unknown');
  document.getElementById('about-current-version').textContent = vCur;
  document.getElementById('about-current-sha').textContent = String(cur.sha || '-');
  document.getElementById('about-current-at').textContent = String(cur.deployed_at || '-');
  document.getElementById('about-available-version').textContent = av && av.version ? String(av.version) : 'no update';
  document.getElementById('about-update-status').textContent = String(up.status || 'idle') + ' - ' + String(up.message || '-');
  document.getElementById('about-release-notes').textContent = String(notes || '-');
  const history = (j.history && Array.isArray(j.history.items)) ? j.history.items : [];
  renderAboutHistory(history);
  if (window.__aboutLastVersion && window.__aboutLastVersion !== vCur) {{
    const out = document.getElementById('about-out');
    if (out) out.textContent = 'Application updated to version ' + vCur + '. Reloading page...';
    setTimeout(() => window.location.reload(), 1200);
  }}
  window.__aboutLastVersion = vCur;
}}
async function requestUpdateCheck() {{
  const out = document.getElementById('about-out');
  if (out) out.textContent = 'Sending update check request...';
  const r = await fetch('/api/v1/admin/update/check', {{
    method: 'POST',
    headers: {{'X-CSRF-Token': aboutHeaderToken()}}
  }});
  const t = await r.text();
  let j = null;
  try {{ j = JSON.parse(t); }} catch (e) {{ j = null; }}
  if (!r.ok) {{
    if (out) out.textContent = j && j.detail ? String(j.detail) : t;
    return;
  }}
  if (out) out.textContent = (j && j.message) ? String(j.message) : 'Update check request accepted.';
  await loadAboutState();
}}
async function requestUpdateApply() {{
  const out = document.getElementById('about-out');
  if (out) out.textContent = 'Sending update apply request...';
  const r = await fetch('/api/v1/admin/update/apply', {{
    method: 'POST',
    headers: {{'X-CSRF-Token': aboutHeaderToken()}}
  }});
  const t = await r.text();
  let j = null;
  try {{ j = JSON.parse(t); }} catch (e) {{ j = null; }}
  if (!r.ok) {{
    if (out) out.textContent = j && j.detail ? String(j.detail) : t;
    return;
  }}
  if (out) out.textContent = (j && j.message) ? String(j.message) : 'Update apply request accepted.';
  await loadAboutState();
}}
document.addEventListener('click', (event) => {{
  const target = event.target;
  if (!target || !target.closest) return;
  const btn = target.closest('[data-action]');
  if (!btn) return;
  const action = String(btn.getAttribute('data-action') || '').trim();
  if (action === 'about-check-updates') return void requestUpdateCheck();
  if (action === 'about-apply-update') return void requestUpdateApply();
}});
loadAboutState();
setInterval(loadAboutState, 15000);
</script>
""",
        active="about",
        user=user,
    )


@app.get("/license", response_class=HTMLResponse)
def license_page(request: Request) -> HTMLResponse:
    user = _read_current_user(request)
    text = "License file is not available."
    path = Path(__file__).resolve().parents[2] / "LICENSE"
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        pass
    safe = escape(text)
    return _page(
        "MIT license",
        f"""
<div class="card">
  <h2>MIT License</h2>
  <p class="muted">This project is distributed under MIT license terms.</p>
  <pre>{safe}</pre>
</div>
""",
        active="about",
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
  <button data-action="login-submit">Sign in</button>
  <p class="muted">Admin credentials are configured from environment/secret files.</p>
</div>
<div class="card">
  <h2>Register</h2>
  <input id="reg-username" placeholder="username" />
  <input id="reg-email" placeholder="email" />
  <input id="reg-password" placeholder="password" type="password" />
  <button data-action="register-submit">Create account</button>
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
document.addEventListener('click', (event) => {
  const target = event.target;
  if (!target || !target.closest) return;
  const btn = target.closest('[data-action]');
  if (!btn) return;
  const action = String(btn.getAttribute('data-action') || '').trim();
  if (action === 'login-submit') return void login();
  if (action === 'register-submit') return void registerUser();
});
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
  <div class="tab-strip" id="cab-tabs">
    <button class="tab-btn" data-cab-section-btn="profile">User card</button>
    <button class="tab-btn" data-cab-section-btn="device">Device setup</button>
    <button class="tab-btn" data-cab-section-btn="traffic">Traffic and resources</button>
  </div>
</div>
<div class="card cab-section" data-cab-section="profile">
  <div class="user-card">
    <div class="user-avatar">{escape(initials)}</div>
    <div>
      <h1 style="margin:0 0 4px;">User card</h1>
      <p class="muted" style="margin:0 0 10px;">Current profile state</p>
      <div class="user-meta-row"><div class="label-muted">Username</div><div><b id="cab-current-username">{escape(user["username"])}</b></div></div>
      <div class="user-meta-row"><div class="label-muted">Email</div><div><b id="cab-current-email">{escape(user["email"])}</b></div></div>
      <div class="user-meta-row"><div class="label-muted">Role</div><div><span class="status-pill status-running">{escape(user["role"])}</span></div></div>
      <div style="margin-top:10px;">
        <button data-action="open-edit-profile-modal">Edit profile</button>
      </div>
    </div>
  </div>
</div>
<div class="card cab-section" data-cab-section="device">
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
    <button data-action="load-device-card">Load card</button>
  </div>
  <div id="device-card-out" style="margin-top:12px;"></div>
</div>
<div class="card cab-section" data-cab-section="traffic">
  <h2>Traffic and resource usage</h2>
  <p class="muted">Live counters and aggregated usage for your profile.</p>
  <div id="cab-traffic-resources" class="muted">Resources: loading...</div>
  <div style="overflow:auto;margin-top:8px;border:1px solid rgba(50,65,90,0.14);border-radius:10px;background:rgba(255,255,255,0.65);">
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr><th align="left">Period</th><th align="left">RX</th><th align="left">TX</th><th align="left">Total</th></tr>
      </thead>
      <tbody id="cab-traffic-summary-body"><tr><td colspan="4" class="muted">Loading...</td></tr></tbody>
    </table>
  </div>
  <div style="margin-top:10px;">
    <canvas id="cab-traffic-canvas" width="900" height="220" style="width:100%;max-width:100%;border:1px solid rgba(100,116,139,0.2);border-radius:10px;background:rgba(255,255,255,0.6);"></canvas>
  </div>
</div>
<div id="edit-profile-modal" class="modal-backdrop">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
      <strong>Edit profile</strong>
      <button class="btn-ghost" data-action="close-edit-profile-modal">Close</button>
    </div>
    <div style="margin-top:10px;">
      <input id="cab-username" placeholder="username" value="{escape(user["username"])}" />
      <input id="cab-email" placeholder="email" value="{escape(user["email"])}" />
      <input id="cab-password" placeholder="new password (optional)" type="password" />
      <button data-action="save-profile">Save changes</button>
      <pre id="cab-out">Ready.</pre>
    </div>
  </div>
</div>
<script>
const csrfToken = {repr(user["csrf_token"])};
const escHtml = (s) => String((s === undefined || s === null) ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
function getCsrfToken() {{
  const m = document.cookie.match(/(?:^|; )proxy_vpn_csrf=([^;]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  return csrfToken;
}}
function showCabSection(section) {{
  const s = String(section || 'profile');
  document.querySelectorAll('#cab-tabs .tab-btn').forEach((btn) => {{
    const key = String(btn.getAttribute('data-cab-section-btn') || '').trim();
    btn.classList.toggle('active', key === s);
  }});
  document.querySelectorAll('.cab-section').forEach((el) => {{
    const key = String(el.getAttribute('data-cab-section') || '').trim();
    el.style.display = (key === s) ? '' : 'none';
  }});
}}
function openEditProfileModal() {{
  const modal = document.getElementById('edit-profile-modal');
  if (modal) modal.style.display = 'flex';
}}
function closeEditProfileModal() {{
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
  const fallbackUrl = escHtml(primary.fallback_url || '');
  const fallbackLabel = escHtml(primary.fallback_label || 'mirror');
  const source = escHtml(primary.source || 'source');
  const clientName = escHtml(primary.name || card.client_app || 'Client');
  const fields = card.config_fields || {{}};
  const fieldRows = [
    ['Address', fields.server],
    ['Port', fields.port],
    ['UUID', fields.uuid],
    ['SNI', fields.sni],
    ['Public Key', fields.public_key],
    ['Short ID', fields.short_id],
    ['Flow', fields.flow],
    ['Network', 'tcp'],
    ['Security', 'reality'],
    ['Encryption', 'none'],
  ]
    .filter(([, value]) => String((value === undefined || value === null) ? '' : value).trim() !== '')
    .map(([name, value]) => {{
      const safeName = escHtml(name);
      const rawValue = String((value === undefined || value === null) ? '' : value);
      const safeValue = escHtml(rawValue);
      return `
        <tr>
          <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);white-space:nowrap;"><b>${{safeName}}</b></td>
          <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);word-break:break-all;"><code>${{safeValue}}</code></td>
          <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);text-align:right;">
            <button class="btn-ghost" data-action="copy-value" data-copy-value="${{encodeURIComponent(rawValue)}}">Copy</button>
          </td>
        </tr>
      `;
    }})
    .join('');
  const fallbackHtml = fallbackUrl
    ? `<div class="muted" style="margin-top:6px;">If install page is unavailable, use <a href="${{fallbackUrl}}" target="_blank" rel="noopener noreferrer">${{fallbackLabel}}</a>.</div>`
    : '';
  out.innerHTML = `
    <div class="card" style="margin-bottom:0;">
      <h3 style="margin-top:0;">${{escHtml(card.title || 'Configuration')}}</h3>
      <p class="muted">Protocol: <b>${{escHtml(card.protocol || '-')}}</b> · Recommended app: <b>${{clientName}}</b></p>
      <p class="muted" style="margin:6px 0 8px;">${{escHtml(card.client_about || 'Free client for importing VLESS URI and connecting in VPN/proxy mode.')}}</p>
      <div class="user-meta-row"><div class="label-muted">Config URI</div><div><code id="cfg-uri" style="word-break:break-all;">${{escHtml(card.config_uri || '')}}</code></div></div>
      <div style="margin-top:8px;">
        <button class="btn-ghost" data-action="copy-config-uri">Copy URI</button>
      </div>
      <h4 style="margin:12px 0 6px;">Manual fields (client menu)</h4>
      <div style="overflow:auto;border:1px solid rgba(50,65,90,0.14);border-radius:10px;background:rgba(255,255,255,0.65);">
        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr>
              <th style="text-align:left;padding:8px;">Field</th>
              <th style="text-align:left;padding:8px;">Value</th>
              <th style="text-align:right;padding:8px;">Action</th>
            </tr>
          </thead>
          <tbody>${{fieldRows || '<tr><td colspan="3" style="padding:8px;" class="muted">No manual fields.</td></tr>'}}</tbody>
        </table>
      </div>
      <div style="margin-top:8px;">
        <a href="${{installUrl}}" target="_blank" rel="noopener noreferrer"><button>Install ${{clientName}}</button></a>
        <span class="status-pill status-stopped" style="margin-left:8px;">${{source}}</span>
      </div>
      ${{fallbackHtml}}
      <h4 style="margin:12px 0 6px;">Instructions</h4>
      <ul style="margin:0 0 4px 14px;padding:0;">${{lines}}</ul>
    </div>
  `;
}}
function fmtBytes(v) {{
  const n = Number(v || 0);
  if (!isFinite(n)) return '0 B';
  const abs = Math.abs(n);
  if (abs >= 1024 ** 4) return (n / (1024 ** 4)).toFixed(2) + ' TB';
  if (abs >= 1024 ** 3) return (n / (1024 ** 3)).toFixed(2) + ' GB';
  if (abs >= 1024 ** 2) return (n / (1024 ** 2)).toFixed(2) + ' MB';
  if (abs >= 1024) return (n / 1024).toFixed(2) + ' KB';
  return Math.round(n) + ' B';
}}
function renderCabinetTrafficSummary(summary) {{
  const body = document.getElementById('cab-traffic-summary-body');
  const resources = document.getElementById('cab-traffic-resources');
  if (!body) return;
  const periods = summary && summary.periods ? summary.periods : {{}};
  const keys = [['day','Day'], ['week','Week'], ['month','Month'], ['year','Year']];
  body.innerHTML = keys.map(([k, label]) => {{
    const item = periods[k] || {{}};
    return `<tr>
      <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);">${{label}}</td>
      <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);">${{fmtBytes(item.rx_bytes || 0)}}</td>
      <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);">${{fmtBytes(item.tx_bytes || 0)}}</td>
      <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);"><b>${{fmtBytes(item.total_bytes || 0)}}</b></td>
    </tr>`;
  }}).join('');
  const r = summary && summary.resources ? summary.resources : {{}};
  if (resources) {{
    resources.textContent = 'Resources now: CPU ' + Number(r.cpu_load_pct || 0).toFixed(1) + '% · RAM ' +
      Number(r.memory_used_pct || 0).toFixed(1) + '% · Disk ' + Number(r.disk_used_pct || 0).toFixed(1) + '%';
  }}
}}
function renderCabinetTrafficChart(points) {{
  const canvas = document.getElementById('cab-traffic-canvas');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const list = Array.isArray(points) ? points : [];
  const values = list.map(p => Number(p.rx_rate_bps || 0) + Number(p.tx_rate_bps || 0));
  const maxV = Math.max(1, ...values);
  ctx.strokeStyle = 'rgba(100,116,139,0.28)';
  for (let i = 0; i < 5; i += 1) {{
    const y = 16 + (h - 32) * (i / 4);
    ctx.beginPath(); ctx.moveTo(8, y); ctx.lineTo(w - 8, y); ctx.stroke();
  }}
  if (!values.length) return;
  ctx.lineWidth = 2;
  ctx.strokeStyle = '#2563eb';
  ctx.beginPath();
  for (let i = 0; i < values.length; i += 1) {{
    const x = 12 + (i / Math.max(1, values.length - 1)) * (w - 24);
    const y = (h - 16) - ((values[i] / maxV) * (h - 32));
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }}
  ctx.stroke();
}}
async function loadCabinetTraffic() {{
  const [sumR, tsR] = await Promise.all([
    fetch('/api/v1/user/traffic/summary'),
    fetch('/api/v1/user/traffic/timeseries?minutes=1440')
  ]);
  if (sumR.ok) {{
    const s = await sumR.json();
    renderCabinetTrafficSummary(s);
  }}
  if (tsR.ok) {{
    const t = await tsR.json();
    renderCabinetTrafficChart(t.points || []);
  }}
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
document.addEventListener('click', (event) => {{
  const target = event.target;
  if (!target || !target.closest) return;
  if (target.id === 'edit-profile-modal') {{
    closeEditProfileModal();
    return;
  }}
  const cabTab = target.closest('[data-cab-section-btn]');
  if (cabTab) {{
    const section = String(cabTab.getAttribute('data-cab-section-btn') || '').trim();
    if (section) {{
      showCabSection(section);
      return;
    }}
  }}
  const btn = target.closest('[data-action]');
  if (!btn) return;
  const action = String(btn.getAttribute('data-action') || '').trim();
  if (action === 'open-edit-profile-modal') return void openEditProfileModal();
  if (action === 'close-edit-profile-modal') return void closeEditProfileModal();
  if (action === 'save-profile') return void saveProfile();
  if (action === 'load-device-card') return void loadDeviceCard();
  if (action === 'copy-config-uri') return void copyConfigUri();
  if (action === 'copy-value') {{
    const encoded = String(btn.getAttribute('data-copy-value') || '');
    return void navigator.clipboard.writeText(decodeURIComponent(encoded));
  }}
}});
refreshPlatformOptions();
showCabSection('profile');
initDeviceCard();
loadCabinetTraffic();
setInterval(loadCabinetTraffic, 30000);
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
    _refresh_user_traffic_samples_once()
    with _db_connect() as con:
        online_user_ids = set(_online_user_ids(con))
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
            f"<button data-action='approve-request' data-request-id='{int(row['id'])}'>Approve</button> "
            f"<button data-action='reject-request' data-request-id='{int(row['id'])}'>Reject</button>"
            f"</td>"
            f"</tr>"
            for row in pending_rows
        ]
    )
    if not pending_html:
        pending_html = "<tr><td colspan='5' class='muted'>No pending requests</td></tr>"

    users_html = "".join(
        [
            (
                f"<tr>"
                f"<td>{escape(row['username'])}</td>"
                f"<td>{escape(row['email'])}</td>"
                f"<td>{escape(row['role'])}</td>"
                f"<td>{'active' if int(row['is_active']) == 1 else 'blocked'} · "
                + (
                    "<span class='status-pill status-running'>Online</span>"
                    if int(row["id"]) in online_user_ids
                    else "<span class='status-pill status-in_error'>Offline</span>"
                )
                + "</td>"
                f"<td>{escape(row['created_at'])}</td>"
                f"<td>"
                + (
                    "<span class='muted'>self</span>"
                    if int(row["id"]) == int(user["id"])
                    else (
                        f"<button class='btn-ghost' data-action='block-user' data-user-id='{int(row['id'])}'>Block</button> "
                        if int(row["is_active"]) == 1
                        else f"<button class='btn-ghost' data-action='unblock-user' data-user-id='{int(row['id'])}'>Unblock</button> "
                    )
                )
                + (
                    ""
                    if int(row["id"]) == int(user["id"])
                    else f"<button class='btn-ghost js-delete-user' data-user-id='{int(row['id'])}' data-username='{escape(str(row['username']))}'>Delete</button>"
                )
                + "</td>"
                f"</tr>"
            )
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
            f"<td><button data-action='remove-wg-binding' data-public-key='{escape(row['public_key'])}'>Unbind</button></td>"
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
            f"<td><button data-action='remove-xray-binding' data-client-email='{escape(row['client_email'])}'>Unbind</button></td>"
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
    <button class="tab-btn" data-tab="overview" data-admin-section="overview">Overview</button>
    <button class="tab-btn" data-tab="security" data-admin-section="security">Security</button>
    <button class="tab-btn" data-tab="configurator" data-admin-section="configurator">Configurator</button>
    <button class="tab-btn" data-tab="approvals" data-admin-section="approvals">Approvals</button>
    <button class="tab-btn" data-tab="users" data-admin-section="users">Users</button>
    <button class="tab-btn" data-tab="traffic" data-admin-section="traffic">Traffic</button>
    <button class="tab-btn" data-tab="logs" data-admin-section="logs">Logs</button>
  </div>
  <div class="tab-strip" id="admin-subtabs" style="margin-top:8px;display:none;"></div>
</div>

<div class="card admin-section" data-section="overview" data-subsection="realtime">
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

<div class="card admin-section" data-section="overview" data-subsection="capacity">
  <h2>Capacity guardrails</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;">
    <div><div class="muted">Overall</div><div id="cap-overall" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">Target active users</div><div id="cap-target" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">CPU p95</div><div id="cap-cpu-p95" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">RAM p95</div><div id="cap-mem-p95" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">Disk p95</div><div id="cap-disk-p95" style="font-size:24px;font-weight:700;">-</div></div>
  </div>
  <p class="muted" id="cap-summary">capacity status: -</p>
</div>

<div class="card admin-section" data-section="configurator" data-subsection="settings">
  <h2>Server capacity configurator</h2>
  <p class="muted">Set server profile and limits. After Apply, dependent limits are recalculated and capacity metrics are updated.</p>
  <h3 style="margin-top:0;">System resource dashboard (actual usage)</h3>
  <table style="width:100%; border-collapse:collapse; margin-bottom:10px;">
    <thead>
      <tr><th align="left">Parameter</th><th align="left">Capacity (detected/config)</th><th align="left">Used</th><th align="left">Left</th><th align="left">Extra</th></tr>
    </thead>
    <tbody id="cfg-runtime-body"><tr><td colspan="5" class="muted">Loading...</td></tr></tbody>
  </table>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;">
    <input id="cfg-server-cpu-cores" placeholder="CPU cores" type="number" step="0.25" min="0.25" />
    <input id="cfg-server-ram-gb" placeholder="RAM (GB)" type="number" step="0.25" min="0.25" />
    <input id="cfg-server-storage-gb" placeholder="Storage (GB)" type="number" step="1" min="1" />
    <input id="cfg-traffic-limit-tb" placeholder="Traffic limit (TB/month)" type="number" step="0.1" min="0.1" />
    <input id="cfg-avg-user-traffic-gb" placeholder="Avg user traffic (GB/month)" type="number" step="1" min="1" />
    <input id="cfg-active-user-ratio-pct" placeholder="Active user ratio (%)" type="number" step="1" min="1" max="100" />
    <input id="cfg-max-registered-users" placeholder="Max registered users (0=auto)" type="number" step="1" min="0" />
    <input id="cfg-target-active-users" placeholder="Target active users (0=auto)" type="number" step="1" min="0" />
  </div>
  <h3 style="margin-top:12px;">Thresholds (p95)</h3>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;">
    <input id="cfg-cpu-warn-p95" placeholder="CPU warn %" type="number" step="1" min="1" max="100" />
    <input id="cfg-cpu-crit-p95" placeholder="CPU critical %" type="number" step="1" min="1" max="100" />
    <input id="cfg-ram-warn-p95" placeholder="RAM warn %" type="number" step="1" min="1" max="100" />
    <input id="cfg-ram-crit-p95" placeholder="RAM critical %" type="number" step="1" min="1" max="100" />
    <input id="cfg-disk-warn-p95" placeholder="Disk warn %" type="number" step="1" min="1" max="100" />
    <input id="cfg-disk-crit-p95" placeholder="Disk critical %" type="number" step="1" min="1" max="100" />
  </div>
  <h3 style="margin-top:12px;">Dashboard refresh</h3>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;">
    <input id="cfg-dashboard-refresh-seconds" placeholder="Refresh interval (sec)" type="number" step="1" min="5" max="300" />
  </div>
  <h3 style="margin-top:12px;">Proxy bypass resources (Direct/Bypass)</h3>
  <p class="muted">Stored in <code>{PROXY_BYPASS_RULES_PATH}</code>. Format per line: <code>resource,false</code> (false = use Direct, VPN disabled).</p>
  <textarea id="cfg-proxy-bypass-custom" placeholder="example.ru,false&#10;gosuslugi.ru,false&#10;youtube.com,true" style="width:100%;min-height:120px;padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);"></textarea>
  <p class="muted" id="cfg-proxy-bypass-validation">Validation: -</p>
  <div style="margin-top:10px;display:flex;gap:8px;align-items:center;">
    <button data-action="apply-configurator">Apply configuration</button>
    <button class="btn-ghost" data-action="reload-configurator">Reload</button>
  </div>
  <p class="muted" id="cfg-derived">derived: -</p>
  <pre id="cfg-out">Ready.</pre>
</div>

<div class="card admin-section" data-section="overview" data-subsection="trend">
  <h2>CPU / Memory trend (last 60 min)</h2>
  <canvas id="metrics-canvas" width="900" height="220" style="width:100%;max-width:100%;border:1px solid rgba(100,116,139,0.2);border-radius:10px;background:rgba(255,255,255,0.6);"></canvas>
</div>

<div class="card admin-section" data-section="overview" data-subsection="online">
  <h2>Users online now</h2>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Username</th><th align="left">Email</th><th align="left">Role</th><th align="left">Sessions</th><th align="left">Last seen</th></tr>
    </thead>
    <tbody id="online-users-body"><tr><td colspan="5" class="muted">Loading...</td></tr></tbody>
  </table>
</div>

<div class="card admin-section" data-section="overview" data-subsection="services">
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

<div class="card admin-section" data-section="overview" data-subsection="deploy">
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

<div class="card admin-section" data-section="overview" data-subsection="updates">
  <h2>Update audit summary</h2>
  <p class="muted">Incremental audit of applied updates: commit titles, changed files, local changes handling before pull.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-bottom:10px;">
    <select id="upd-filter-status" style="padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">
      <option value="">Status: any</option>
      <option value="updated">updated</option>
      <option value="available">available</option>
      <option value="noop">noop</option>
      <option value="failed">failed</option>
      <option value="failed_with_rollback">failed_with_rollback</option>
      <option value="blocked_local_changes">blocked_local_changes</option>
    </select>
    <input id="upd-filter-branch" placeholder="Branch (e.g. main)" />
    <input id="upd-filter-file" placeholder="File contains (e.g. compose.yaml)" />
    <input id="upd-filter-commit" placeholder="Commit text contains" />
    <input id="upd-filter-date-from" placeholder="Date from (ISO UTC)" />
    <input id="upd-filter-date-to" placeholder="Date to (ISO UTC)" />
  </div>
  <div style="margin-bottom:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <button class="btn-ghost" data-action="apply-update-filters">Apply filters</button>
    <button class="btn-ghost" data-action="reset-update-filters">Reset filters</button>
  </div>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Time (UTC)</th><th align="left">Status</th><th align="left">Branch</th><th align="left">From</th><th align="left">To</th><th align="left">Commit title</th><th align="left">Files</th><th align="left">Message</th></tr>
    </thead>
    <tbody id="update-audit-body"><tr><td colspan="8" class="muted">Loading...</td></tr></tbody>
  </table>
  <p class="muted" id="update-audit-meta"></p>
</div>

<div class="card admin-section" data-section="overview" data-subsection="backup">
  <h2>Backup integrity status</h2>
  <p class="muted">Scheduled backups run only after runtime integrity checks pass.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;">
    <div><div class="muted">Backup result</div><div id="backup-overall" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">Integrity gate</div><div id="backup-integrity" style="font-size:24px;font-weight:700;">-</div></div>
    <div><div class="muted">Last check/update</div><div id="backup-updated" style="font-size:14px;font-weight:700;">-</div></div>
    <div><div class="muted">Last successful backup</div><div id="backup-last-success" style="font-size:14px;font-weight:700;">-</div></div>
  </div>
  <p class="muted" id="backup-archive">archive: -</p>
  <pre id="backup-message">No backup status yet.</pre>
</div>

<div class="card admin-section" data-section="security" data-subsection="incidents">
  <h2>Security incidents</h2>
  <p class="muted">Telemetry from dedicated security-guard container: DDoS, brute-force, scan/probe and mitigation actions.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-bottom:10px;">
    <input id="sec-filter-ip" placeholder="Filter IP" />
    <input id="sec-filter-attack" placeholder="Filter attack type" />
    <input id="sec-filter-direction" placeholder="Filter direction" />
    <select id="sec-filter-severity" style="padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">
      <option value="">Severity: any</option>
      <option value="critical">critical</option>
      <option value="high">high</option>
      <option value="medium">medium</option>
      <option value="low">low</option>
    </select>
    <label class="muted" style="display:flex;align-items:center;gap:6px;">
      <input id="sec-aggregate" type="checkbox" style="width:auto;margin:0;" checked />
      Aggregate similar events
    </label>
  </div>
  <div style="margin-bottom:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <button class="btn-ghost" data-action="apply-security-filters">Apply filters</button>
    <button class="btn-ghost" data-action="reset-security-filters">Reset filters</button>
  </div>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Time (UTC)</th><th align="left">Count</th><th align="left">IP</th><th align="left">Geo</th><th align="left">Attack type</th><th align="left">Direction</th><th align="left">Target</th><th align="left">Action</th><th align="left">Severity</th><th align="left">Reason</th></tr>
    </thead>
    <tbody id="security-events-body"><tr><td colspan="10" class="muted">Loading...</td></tr></tbody>
  </table>
  <p class="muted" id="security-events-meta"></p>
</div>

<div class="card admin-section" data-section="security" data-subsection="blocked">
  <h2>Blocked sources</h2>
  <div style="display:grid;grid-template-columns:2fr 2fr 1fr auto auto;gap:8px;align-items:center;margin-bottom:10px;">
    <input id="sec-manual-ip" placeholder="IP for manual block/unblock" />
    <input id="sec-manual-reason" placeholder="Reason (optional)" />
    <input id="sec-manual-seconds" placeholder="Block seconds" type="number" min="60" step="60" value="900" />
    <button data-action="manual-block-ip">Block IP</button>
    <button class="btn-ghost" data-action="manual-unblock-ip">Unblock IP</button>
  </div>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">IP</th><th align="left">Blocked until</th><th align="left">Reason</th><th align="left">Created</th><th align="left">Updated</th><th align="left">Action</th></tr>
    </thead>
    <tbody id="security-blocked-body"><tr><td colspan="6" class="muted">Loading...</td></tr></tbody>
  </table>
  <p class="muted" id="security-blocked-meta"></p>
  <pre id="security-admin-out">Ready.</pre>
</div>

<div class="card admin-section" data-section="approvals" data-subsection="requests">
  <h2>Pending registration approvals</h2>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">ID</th><th align="left">Username</th><th align="left">Email</th><th align="left">Requested</th><th align="left">Actions</th></tr>
    </thead>
    <tbody>{pending_html}</tbody>
  </table>
</div>

<div class="card admin-section" data-section="users" data-subsection="management">
  <h2>User management</h2>
  <p class="muted">Create user/admin account from modal form.</p>
  <button data-action="open-create-user-modal">Create user/admin</button>
</div>

<div class="card admin-section" data-section="users" data-subsection="recent">
  <h2>Recent users</h2>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">Username</th><th align="left">Email</th><th align="left">Role</th><th align="left">State</th><th align="left">Created</th><th align="left">Actions</th></tr>
    </thead>
    <tbody>{users_html}</tbody>
  </table>
</div>

<div class="card admin-section" data-section="traffic" data-subsection="wg-bindings">
  <h2>WireGuard peer bindings (exact accounting source)</h2>
  <p class="muted">Bind each WireGuard public key to an app user. Then traffic is calculated from real WG counters.</p>
  <div style="display:grid;grid-template-columns:2fr 3fr 2fr auto;gap:8px;align-items:center;">
    <select id="wg-bind-user" style="padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">{user_options_html}</select>
    <input id="wg-bind-key" placeholder="WireGuard peer public key" />
    <input id="wg-bind-label" placeholder="label (optional)" />
    <button data-action="bind-wg-peer">Bind</button>
  </div>
  <table style="width:100%; border-collapse:collapse; margin-top:10px;">
    <thead>
      <tr><th align="left">User</th><th align="left">Public key</th><th align="left">Label</th><th align="left">Last totals</th><th align="left">Action</th></tr>
    </thead>
    <tbody id="wg-bindings-body">{wg_bindings_html}</tbody>
  </table>
</div>

<div class="card admin-section" data-section="traffic" data-subsection="xray-bindings">
  <h2>Xray client bindings (exact accounting source)</h2>
  <p class="muted">Bind each Xray client email (from Xray config) to an app user. Data comes from Xray StatsService counters.</p>
  <div style="display:grid;grid-template-columns:2fr 3fr 2fr auto;gap:8px;align-items:center;">
    <select id="xray-bind-user" style="padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">{user_options_html}</select>
    <input id="xray-bind-email" placeholder="Xray client email (e.g. user1@proxy-vpn)" />
    <input id="xray-bind-label" placeholder="label (optional)" />
    <button data-action="bind-xray-client">Bind</button>
  </div>
  <table style="width:100%; border-collapse:collapse; margin-top:10px;">
    <thead>
      <tr><th align="left">User</th><th align="left">Client email</th><th align="left">Label</th><th align="left">Last totals</th><th align="left">Action</th></tr>
    </thead>
    <tbody id="xray-bindings-body">{xray_bindings_html}</tbody>
  </table>
</div>

<div class="card admin-section" data-section="traffic" data-subsection="per-user">
  <h2>Per-user traffic (WG + Xray exact)</h2>
  <p class="muted">Data is based on WireGuard/Xray counters and binding tables above.</p>
  <p class="muted" id="traffic-source">source: -</p>
  <table style="width:100%; border-collapse:collapse;">
    <thead>
      <tr><th align="left">User</th><th align="left">Email</th><th align="left">Role</th><th align="left">RX 24h</th><th align="left">TX 24h</th><th align="left">Total 24h</th></tr>
    </thead>
    <tbody id="user-traffic-body"><tr><td colspan="6" class="muted">Loading...</td></tr></tbody>
  </table>
  <div style="margin-top:10px;display:grid;grid-template-columns:minmax(240px,1fr) auto;gap:8px;align-items:end;">
    <div>
      <div class="label-muted">Selected user details</div>
      <select id="traffic-user-select" style="width:100%;padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);">{user_options_html}</select>
    </div>
    <button class="btn-ghost" data-action="load-user-traffic-details">Load details</button>
  </div>
  <div style="overflow:auto;margin-top:8px;border:1px solid rgba(50,65,90,0.14);border-radius:10px;background:rgba(255,255,255,0.65);">
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr><th align="left">Period</th><th align="left">RX</th><th align="left">TX</th><th align="left">Total</th></tr>
      </thead>
      <tbody id="admin-user-traffic-periods-body"><tr><td colspan="4" class="muted">Select user and click Load details.</td></tr></tbody>
    </table>
  </div>
  <canvas id="admin-user-traffic-canvas" width="900" height="220" style="margin-top:10px;width:100%;max-width:100%;border:1px solid rgba(100,116,139,0.2);border-radius:10px;background:rgba(255,255,255,0.6);"></canvas>
</div>

<div class="card admin-section" data-section="logs" data-subsection="admin-log">
  <h2>Admin actions log</h2>
  <pre id="admin-out">Ready.</pre>
</div>
<div id="create-user-modal" class="modal-backdrop">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
      <strong>Create user/admin</strong>
      <button class="btn-ghost" data-action="close-create-user-modal">Close</button>
    </div>
    <div style="margin-top:10px;">
      <input id="new-username" placeholder="username" />
      <input id="new-email" placeholder="email" />
      <input id="new-password" placeholder="password" type="password" />
      <select id="new-role" style="width:100%;padding:10px;border-radius:8px;background:rgba(255,255,255,0.76);color:#1f2937;border:1px solid rgba(50,65,90,0.18);margin-bottom:8px;">
        <option value="user">user</option>
        <option value="admin">admin</option>
      </select>
      <button data-action="create-user">Create account</button>
      <pre id="create-user-out" style="margin-top:8px;">Ready.</pre>
    </div>
  </div>
</div>
<div id="service-log-modal" class="modal-backdrop">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
      <strong id="service-log-title">Container logs</strong>
      <div style="display:flex;align-items:center;gap:8px;">
        <label class="muted" style="display:flex;align-items:center;gap:6px;">
          <input id="service-log-stderr-only" type="checkbox" style="width:auto;margin:0;" />
          stderr only
        </label>
        <button class="btn-ghost" data-action="refresh-service-logs">Refresh now</button>
        <button class="btn-ghost" data-action="close-service-logs">Close</button>
      </div>
    </div>
    <pre id="service-log-content" style="margin-top:10px;max-height:65vh;overflow:auto;">Loading...</pre>
  </div>
</div>
<script>
const csrfToken = {repr(user["csrf_token"])};
let currentServiceLogContainer = '';
let serviceLogsIntervalId = null;
let adminRefreshIntervalId = null;
let securityEventsCache = [];
let currentAdminSection = 'overview';
const currentAdminSubsection = {{}};
const sectionSubsections = {{
  overview: [
    ['realtime', 'Realtime'],
    ['capacity', 'Capacity'],
    ['trend', 'Trends'],
    ['online', 'Online users'],
    ['services', 'Services'],
    ['deploy', 'Deploy'],
    ['updates', 'Updates audit'],
    ['backup', 'Backup'],
  ],
  security: [
    ['incidents', 'Incidents'],
    ['blocked', 'Blocked IPs'],
  ],
  configurator: [['settings', 'Settings']],
  approvals: [['requests', 'Requests']],
  users: [['management', 'Management'], ['recent', 'Recent users']],
  traffic: [['wg-bindings', 'WG bindings'], ['xray-bindings', 'Xray bindings'], ['per-user', 'Per-user']],
  logs: [['admin-log', 'Admin log']],
}};
const escHtml = (s) => String((s === undefined || s === null) ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
function getCsrfToken() {{
  const m = document.cookie.match(/(?:^|; )proxy_vpn_csrf=([^;]+)/);
  if (m && m[1]) return decodeURIComponent(m[1]);
  return csrfToken;
}}
function showSubsection(section, subsection) {{
  document.querySelectorAll('.admin-section').forEach(el => {{
    if (el.dataset.section !== section) {{
      el.style.display = 'none';
      return;
    }}
    const cardSub = String(el.dataset.subsection || '');
    if (!subsection || !cardSub) {{
      el.style.display = 'block';
      return;
    }}
    el.style.display = (cardSub === subsection) ? 'block' : 'none';
  }});
}}
function renderSubtabs(section) {{
  const root = document.getElementById('admin-subtabs');
  if (!root) return;
  const subs = sectionSubsections[section] || [];
  if (!subs.length || subs.length === 1) {{
    root.style.display = 'none';
    root.innerHTML = '';
    return;
  }}
  root.style.display = 'flex';
  root.innerHTML = subs.map(([key, label]) => {{
    const active = currentAdminSubsection[section] === key ? 'active' : '';
    return `<button class="tab-btn ${{active}}" data-admin-section="${{escHtml(section)}}" data-admin-subsection="${{escHtml(key)}}">${{escHtml(label)}}</button>`;
  }}).join('');
}}
function showSection(section, preferredSubsection = '') {{
  currentAdminSection = section;
  document.querySelectorAll('#admin-tabs .tab-btn').forEach(btn => {{
    const isActive = btn.dataset.tab === section;
    btn.classList.toggle('active', isActive);
  }});
  const subs = sectionSubsections[section] || [];
  const fallback = subs.length ? subs[0][0] : '';
  const selected = preferredSubsection || currentAdminSubsection[section] || fallback;
  currentAdminSubsection[section] = selected;
  renderSubtabs(section);
  showSubsection(section, selected);
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
      ? `<button class="btn-ghost" data-action="open-service-logs" data-container="${{escHtml(i.name)}}">Logs</button>`
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
function firstCommitTitle(item) {{
  const commits = Array.isArray(item && item.commits) ? item.commits : [];
  if (!commits.length) return '-';
  const first = commits[0] || {{}};
  return String(first.title || first.sha || '-');
}}
function filePreview(item) {{
  const files = Array.isArray(item && item.files) ? item.files : [];
  if (!files.length) return '-';
  const preview = files.slice(0, 3).map(f => `${{String(f.status || '?')}} ${{String(f.path || '-')}}`).join(', ');
  if (files.length > 3) return preview + ` (+${{files.length - 3}} more)`;
  return preview;
}}
function renderUpdateAudit(items, path, reason) {{
  const body = document.getElementById('update-audit-body');
  const meta = document.getElementById('update-audit-meta');
  if (!body) return;
  if (!items || items.length === 0) {{
    body.innerHTML = '<tr><td colspan="8" class="muted">No update audit records yet.</td></tr>';
    if (meta) meta.textContent = (reason || 'Audit file is empty.') + (path ? (' Path: ' + path) : '');
    return;
  }}
  body.innerHTML = items.map(i => `<tr>
    <td>${{escHtml(i.ts || '-')}}</td>
    <td>${{deployStatusBadge(i.status)}}</td>
    <td>${{escHtml(i.branch || '-')}}</td>
    <td><code>${{escHtml(i.from || '-')}}</code></td>
    <td><code>${{escHtml(i.to || '-')}}</code></td>
    <td>${{escHtml(firstCommitTitle(i))}}</td>
    <td>${{escHtml(filePreview(i))}}</td>
    <td>${{escHtml(i.message || '-')}}</td>
  </tr>`).join('');
  if (meta) meta.textContent = 'Source file: ' + (path || '-') + ' | showing latest ' + items.length + ' records';
}}
function buildUpdateAuditQuery() {{
  const statusEl = document.getElementById('upd-filter-status');
  const branchEl = document.getElementById('upd-filter-branch');
  const fileEl = document.getElementById('upd-filter-file');
  const commitEl = document.getElementById('upd-filter-commit');
  const dateFromEl = document.getElementById('upd-filter-date-from');
  const dateToEl = document.getElementById('upd-filter-date-to');
  const status = String((statusEl && statusEl.value) || '').trim();
  const branch = String((branchEl && branchEl.value) || '').trim();
  const fileQ = String((fileEl && fileEl.value) || '').trim();
  const commitQ = String((commitEl && commitEl.value) || '').trim();
  const dateFrom = String((dateFromEl && dateFromEl.value) || '').trim();
  const dateTo = String((dateToEl && dateToEl.value) || '').trim();
  const p = new URLSearchParams();
  p.set('limit', '50');
  if (status) p.set('status', status);
  if (branch) p.set('branch', branch);
  if (fileQ) p.set('file_q', fileQ);
  if (commitQ) p.set('commit_q', commitQ);
  if (dateFrom) p.set('date_from', dateFrom);
  if (dateTo) p.set('date_to', dateTo);
  return p.toString();
}}
async function loadUpdateAuditByFilters() {{
  const q = buildUpdateAuditQuery();
  const r = await fetch('/api/v1/admin/update-audit?' + q);
  if (!r.ok) return;
  const d = await r.json();
  renderUpdateAudit(d.items || [], d.path || '', d.reason || '');
}}
function applyUpdateAuditFilters() {{
  loadUpdateAuditByFilters();
}}
function resetUpdateAuditFilters() {{
  const ids = ['upd-filter-branch', 'upd-filter-file', 'upd-filter-commit', 'upd-filter-date-from', 'upd-filter-date-to'];
  ids.forEach((id) => {{
    const el = document.getElementById(id);
    if (el) el.value = '';
  }});
  const st = document.getElementById('upd-filter-status');
  if (st) st.value = '';
  loadUpdateAuditByFilters();
}}
function securitySeverityBadge(level) {{
  const l = String(level || 'unknown').toLowerCase();
  if (l === 'critical' || l === 'high') return `<span class="status-pill status-in_error">${{escHtml(l)}}</span>`;
  if (l === 'medium' || l === 'warn') return `<span class="status-pill status-pending">${{escHtml(l)}}</span>`;
  return `<span class="status-pill status-running">${{escHtml(l)}}</span>`;
}}
function securityActionBadge(action) {{
  const a = String(action || 'observed').toLowerCase();
  if (a === 'blocked') return `<span class="status-pill status-in_error">${{escHtml(a)}}</span>`;
  if (a === 'mitigated' || a === 'throttled') return `<span class="status-pill status-pending">${{escHtml(a)}}</span>`;
  return `<span class="status-pill status-running">${{escHtml(a)}}</span>`;
}}
function aggregateSecurityEvents(items) {{
  const groups = new Map();
  (items || []).forEach((i) => {{
    const key = [
      String(i.ip || ''),
      String(i.attack_type || ''),
      String(i.direction || ''),
      String(i.target || ''),
      String(i.action || ''),
      String(i.severity || ''),
      String(i.reason || ''),
    ].join('|');
    if (!groups.has(key)) {{
      groups.set(key, {{
        ...i,
        count: Number(i.count || 1),
      }});
      return;
    }}
    const cur = groups.get(key);
    cur.count = Number(cur.count || 0) + Number(i.count || 1);
    if (String(i.ts || '') > String(cur.ts || '')) cur.ts = i.ts;
  }});
  return Array.from(groups.values()).sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));
}}
function applySecurityFilters() {{
  const ipEl = document.getElementById('sec-filter-ip');
  const attackEl = document.getElementById('sec-filter-attack');
  const directionEl = document.getElementById('sec-filter-direction');
  const severityEl = document.getElementById('sec-filter-severity');
  const aggregateEl = document.getElementById('sec-aggregate');
  const ipQ = String((ipEl && ipEl.value) || '').trim().toLowerCase();
  const attackQ = String((attackEl && attackEl.value) || '').trim().toLowerCase();
  const directionQ = String((directionEl && directionEl.value) || '').trim().toLowerCase();
  const severityQ = String((severityEl && severityEl.value) || '').trim().toLowerCase();
  const aggregate = !!(aggregateEl && aggregateEl.checked);
  let items = (securityEventsCache || []).filter((i) => {{
    if (ipQ && !String(i.ip || '').toLowerCase().includes(ipQ)) return false;
    if (attackQ && !String(i.attack_type || '').toLowerCase().includes(attackQ)) return false;
    if (directionQ && !String(i.direction || '').toLowerCase().includes(directionQ)) return false;
    if (severityQ && String(i.severity || '').toLowerCase() !== severityQ) return false;
    return true;
  }});
  if (aggregate) items = aggregateSecurityEvents(items);
  renderSecurityEvents(items, '');
}}
function resetSecurityFilters() {{
  const ids = ['sec-filter-ip', 'sec-filter-attack', 'sec-filter-direction'];
  ids.forEach((id) => {{
    const el = document.getElementById(id);
    if (el) el.value = '';
  }});
  const sev = document.getElementById('sec-filter-severity');
  if (sev) sev.value = '';
  const ag = document.getElementById('sec-aggregate');
  if (ag) ag.checked = true;
  applySecurityFilters();
}}
async function manualBlockIp() {{
  const out = document.getElementById('security-admin-out');
  const ipEl = document.getElementById('sec-manual-ip');
  const reasonEl = document.getElementById('sec-manual-reason');
  const secondsEl = document.getElementById('sec-manual-seconds');
  const ip = String((ipEl && ipEl.value) || '').trim();
  const reason = String((reasonEl && reasonEl.value) || '').trim();
  const blockSeconds = Number((secondsEl && secondsEl.value) || 900);
  if (!ip) {{
    if (out) out.textContent = 'IP is required.';
    return;
  }}
  if (out) out.textContent = 'Blocking...';
  const r = await fetch('/api/v1/admin/security/block', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()}},
    body: JSON.stringify({{ip, reason, block_seconds: Math.max(60, Math.trunc(blockSeconds || 900))}})
  }});
  const txt = await r.text();
  if (out) out.textContent = txt;
  await refreshAdminLive();
}}
async function manualUnblockIp(ipArg = null) {{
  const out = document.getElementById('security-admin-out');
  const ipEl = document.getElementById('sec-manual-ip');
  const reasonEl = document.getElementById('sec-manual-reason');
  const ip = String(ipArg || ((ipEl && ipEl.value) || '')).trim();
  const reason = String((reasonEl && reasonEl.value) || '').trim();
  if (!ip) {{
    if (out) out.textContent = 'IP is required.';
    return;
  }}
  if (out) out.textContent = 'Unblocking...';
  const r = await fetch('/api/v1/admin/security/unblock', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()}},
    body: JSON.stringify({{ip, reason}})
  }});
  const txt = await r.text();
  if (out) out.textContent = txt;
  await refreshAdminLive();
}}
function renderSecurityEvents(items, reason) {{
  const body = document.getElementById('security-events-body');
  const meta = document.getElementById('security-events-meta');
  if (!body) return;
  if (!items || items.length === 0) {{
    body.innerHTML = '<tr><td colspan="10" class="muted">No security incidents yet.</td></tr>';
    if (meta) meta.textContent = reason || 'No attack telemetry yet.';
    return;
  }}
  body.innerHTML = items.map(i => `<tr>
    <td>${{escHtml(i.ts || '-')}}</td>
    <td>${{Number(i.count || 1)}}</td>
    <td><code>${{escHtml(i.ip || '-')}}</code></td>
    <td>${{escHtml((i.country || 'Unknown') + ' / ' + (i.city || '-'))}}<br><span class="muted">${{escHtml(i.asn || '-')}}</span></td>
    <td>${{escHtml(i.attack_type || '-')}}</td>
    <td>${{escHtml(i.direction || '-')}}</td>
    <td>${{escHtml(i.target || '-')}}</td>
    <td>${{securityActionBadge(i.action || 'observed')}}</td>
    <td>${{securitySeverityBadge(i.severity || '-')}}</td>
    <td>${{escHtml(i.reason || '-')}}</td>
  </tr>`).join('');
  if (meta) meta.textContent = 'Last incidents: ' + items.length;
}}
function renderSecurityBlocked(items, reason) {{
  const body = document.getElementById('security-blocked-body');
  const meta = document.getElementById('security-blocked-meta');
  if (!body) return;
  if (!items || items.length === 0) {{
    body.innerHTML = '<tr><td colspan="6" class="muted">No blocked IPs.</td></tr>';
    if (meta) meta.textContent = reason || 'Blocklist is empty.';
    return;
  }}
  body.innerHTML = items.map(i => `<tr>
    <td><code>${{escHtml(i.ip || '-')}}</code></td>
    <td>${{escHtml(i.blocked_until || '-')}}</td>
    <td>${{escHtml(i.reason || '-')}}</td>
    <td>${{escHtml(i.created_at || '-')}}</td>
    <td>${{escHtml(i.updated_at || '-')}}</td>
    <td><button class="btn-ghost" data-action="manual-unblock-ip-item" data-ip="${{escHtml(i.ip || '')}}">Unblock</button></td>
  </tr>`).join('');
  if (meta) meta.textContent = 'Currently blocked: ' + items.length;
}}
function backupBadge(state) {{
  const s = String(state || 'unknown');
  if (['success', 'ok', 'passed'].includes(s)) return '<span class="status-pill status-running">' + escHtml(s) + '</span>';
  if (['warn', 'warning', 'skipped', 'unknown'].includes(s)) return '<span class="status-pill status-pending">' + escHtml(s) + '</span>';
  return '<span class="status-pill status-in_error">' + escHtml(s) + '</span>';
}}
function renderBackupStatus(data) {{
  const overallEl = document.getElementById('backup-overall');
  const integrityEl = document.getElementById('backup-integrity');
  const updatedEl = document.getElementById('backup-updated');
  const successEl = document.getElementById('backup-last-success');
  const archiveEl = document.getElementById('backup-archive');
  const msgEl = document.getElementById('backup-message');
  if (!overallEl || !integrityEl || !updatedEl || !successEl || !archiveEl || !msgEl) return;
  const backupState = data && data.backup_status ? data.backup_status : 'unknown';
  const integrityState = data && data.integrity && data.integrity.status ? data.integrity.status : 'unknown';
  overallEl.innerHTML = backupBadge(backupState);
  integrityEl.innerHTML = backupBadge(integrityState);
  updatedEl.textContent = String((data && data.updated_at) || '-');
  successEl.textContent = String((data && data.last_success_at) || '-');
  const path = (data && data.archive_path) ? data.archive_path : '-';
  archiveEl.textContent = 'archive: ' + String(path);
  const msg = (data && data.message) ? data.message : 'No backup status yet.';
  const reason = (data && data.integrity && data.integrity.reason) ? data.integrity.reason : '';
  msgEl.textContent = reason ? (String(msg) + '\\n' + String(reason)) : String(msg);
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
function renderAdminUserTrafficPeriods(periods) {{
  const body = document.getElementById('admin-user-traffic-periods-body');
  if (!body) return;
  const p = periods || {{}};
  const rows = [['day','Day'], ['week','Week'], ['month','Month'], ['year','Year']];
  body.innerHTML = rows.map(([k, label]) => {{
    const i = p[k] || {{}};
    return `<tr>
      <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);">${{label}}</td>
      <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);">${{fmtBytes(i.rx_bytes || 0)}}</td>
      <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);">${{fmtBytes(i.tx_bytes || 0)}}</td>
      <td style="padding:6px 8px;border-bottom:1px solid rgba(50,65,90,0.12);"><b>${{fmtBytes(i.total_bytes || 0)}}</b></td>
    </tr>`;
  }}).join('');
}}
function drawAdminUserTraffic(points) {{
  const canvas = document.getElementById('admin-user-traffic-canvas');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const list = Array.isArray(points) ? points : [];
  const values = list.map(p => Number(p.rx_rate_bps || 0) + Number(p.tx_rate_bps || 0));
  const maxV = Math.max(1, ...values);
  ctx.strokeStyle = 'rgba(100,116,139,0.28)';
  for (let i = 0; i < 5; i += 1) {{
    const y = 16 + (h - 32) * (i / 4);
    ctx.beginPath(); ctx.moveTo(8, y); ctx.lineTo(w - 8, y); ctx.stroke();
  }}
  if (!values.length) return;
  ctx.lineWidth = 2;
  ctx.strokeStyle = '#0f766e';
  ctx.beginPath();
  for (let i = 0; i < values.length; i += 1) {{
    const x = 12 + (i / Math.max(1, values.length - 1)) * (w - 24);
    const y = (h - 16) - ((values[i] / maxV) * (h - 32));
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }}
  ctx.stroke();
}}
async function loadAdminUserTrafficDetails() {{
  const el = document.getElementById('traffic-user-select');
  const userId = Number((el && el.value) || 0);
  if (!userId) return;
  const [periodsR, tsR] = await Promise.all([
    fetch('/api/v1/admin/user-traffic/periods?user_id=' + encodeURIComponent(String(userId))),
    fetch('/api/v1/admin/user-traffic/timeseries?user_id=' + encodeURIComponent(String(userId)) + '&minutes=1440')
  ]);
  if (periodsR.ok) {{
    const p = await periodsR.json();
    renderAdminUserTrafficPeriods(p.periods || {{}});
  }}
  if (tsR.ok) {{
    const t = await tsR.json();
    drawAdminUserTraffic(t.points || []);
  }}
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
function renderCapacityStatus(c) {{
  if (!c || c.status !== 'ok') return;
  const overallEl = document.getElementById('cap-overall');
  const targetEl = document.getElementById('cap-target');
  const cpuEl = document.getElementById('cap-cpu-p95');
  const memEl = document.getElementById('cap-mem-p95');
  const diskEl = document.getElementById('cap-disk-p95');
  const summaryEl = document.getElementById('cap-summary');
  if (overallEl) {{
    const badge = c.overall === 'critical'
      ? '<span class="status-pill status-error">critical</span>'
      : (c.overall === 'warn'
        ? '<span class="status-pill status-pending">warn</span>'
        : '<span class="status-pill status-running">ok</span>');
    overallEl.innerHTML = badge;
  }}
  if (targetEl) targetEl.textContent = `${{Number(c.active_sessions || 0)}} / ${{Number(c.target_active_users || 15)}}`;
  const p95 = c && c.p95 ? c.p95 : {{}};
  const signals = c && c.signals ? c.signals : {{}};
  if (cpuEl) cpuEl.textContent = `${{Number(p95.cpu_pct || 0).toFixed(1)}}%`;
  if (memEl) memEl.textContent = `${{Number(p95.mem_pct || 0).toFixed(1)}}%`;
  if (diskEl) diskEl.textContent = `${{Number(p95.disk_pct || 0).toFixed(1)}}%`;
  if (summaryEl) {{
    summaryEl.textContent = `window: ${{Number(c.window_minutes || 0)}} min, samples: ${{Number(c.samples || 0)}}. ` +
      `signals -> cpu:${{signals.cpu || '-'}}, mem:${{signals.memory || '-'}}, disk:${{signals.disk || '-'}}, concurrency:${{signals.concurrency || '-'}}.`;
  }}
  renderConfigRuntime(c);
}}
function renderConfigRuntime(c) {{
  const body = document.getElementById('cfg-runtime-body');
  if (!body) return;
  if (!c || c.status !== 'ok') {{
    body.innerHTML = '<tr><td colspan="5" class="muted">No runtime data.</td></tr>';
    return;
  }}
  const runtime = c.runtime || {{}};
  const detected = runtime.detected || {{}};
  const usage = runtime.usage || {{}};
  const cfg = c.config || {{}};
  const cpuTotal = Number(detected.cpu_cores || cfg.server_cpu_cores || 0);
  const cpuUsed = Number(usage.cpu_used_cores || 0);
  const cpuLeft = Math.max(0, cpuTotal - cpuUsed);
  const ramTotal = Number(detected.ram_gb || cfg.server_ram_gb || 0);
  const ramUsed = Number(usage.ram_used_gb || 0);
  const ramLeft = Math.max(0, ramTotal - ramUsed);
  const diskTotal = Number(detected.storage_gb || cfg.server_storage_gb || 0);
  const diskUsed = Number(usage.disk_used_gb || 0);
  const diskLeft = Math.max(0, diskTotal - diskUsed);
  const trafficLimitBytes = Number(cfg.traffic_limit_tb || 0) * 1024 * 1024 * 1024 * 1024;
  const trafficUsedBytes = Number(usage.traffic_month_used_bytes || 0);
  const trafficLeftBytes = Number(usage.traffic_month_left_bytes || 0);
  const trafficIncrementBytes = Number(usage.traffic_increment_window_bytes || 0);
  const trafficLeftPct = Number(usage.traffic_left_pct || 0);
  const thresholds = c.thresholds || {{}};
  const signalClass = (state) => state === 'critical' ? 'in_error' : (state === 'warn' ? 'pending' : 'running');
  const signalBadge = (state) => `<span class="status-pill status-${{signalClass(state)}}">${{escHtml(state || 'ok')}}</span>`;
  const metricState = (value, warn, crit) => {{
    const v = Number(value || 0);
    const w = Number(warn || 0);
    const cr = Number(crit || 0);
    if (v >= cr) return 'critical';
    if (v >= w) return 'warn';
    return 'ok';
  }};
  const cpuState = metricState(usage.cpu_current_pct, thresholds.cpu_warn_p95, thresholds.cpu_crit_p95);
  const ramState = metricState(usage.ram_current_pct, thresholds.ram_warn_p95, thresholds.ram_crit_p95);
  const diskState = metricState(usage.disk_current_pct, thresholds.disk_warn_p95, thresholds.disk_crit_p95);
  const trafficState = trafficLeftPct <= 10 ? 'critical' : (trafficLeftPct <= 25 ? 'warn' : 'ok');
  body.innerHTML = `
    <tr>
      <td><b>CPU</b></td>
      <td>${{cpuTotal.toFixed(2)}} cores</td>
      <td>${{cpuUsed.toFixed(2)}} cores (${{Number(usage.cpu_current_pct || 0).toFixed(1)}}%)</td>
      <td>${{cpuLeft.toFixed(2)}} cores</td>
      <td>${{signalBadge(cpuState)}} · target active: ${{Number(c.target_active_users || 0)}}</td>
    </tr>
    <tr>
      <td><b>RAM</b></td>
      <td>${{ramTotal.toFixed(2)}} GB</td>
      <td>${{ramUsed.toFixed(2)}} GB (${{Number(usage.ram_current_pct || 0).toFixed(1)}}%)</td>
      <td>${{ramLeft.toFixed(2)}} GB</td>
      <td>${{signalBadge(ramState)}} · p95: ${{Number(((c.p95 || {{}}).mem_pct) || 0).toFixed(1)}}%</td>
    </tr>
    <tr>
      <td><b>Storage</b></td>
      <td>${{diskTotal.toFixed(2)}} GB</td>
      <td>${{diskUsed.toFixed(2)}} GB (${{Number(usage.disk_current_pct || 0).toFixed(1)}}%)</td>
      <td>${{diskLeft.toFixed(2)}} GB</td>
      <td>${{signalBadge(diskState)}} · p95: ${{Number(((c.p95 || {{}}).disk_pct) || 0).toFixed(1)}}%</td>
    </tr>
    <tr>
      <td><b>Traffic (month)</b></td>
      <td>${{fmtBytes(trafficLimitBytes)}}</td>
      <td>${{fmtBytes(trafficUsedBytes)}}</td>
      <td>${{fmtBytes(trafficLeftBytes)}} (${{trafficLeftPct.toFixed(2)}}%)</td>
      <td>${{signalBadge(trafficState)}} · increment ${{Number(c.window_minutes || 0)}}m: +${{fmtBytes(trafficIncrementBytes)}}</td>
    </tr>
  `;
}}
function setConfigField(id, value) {{
  const el = document.getElementById(id);
  if (!el) return;
  el.value = String((value === undefined || value === null) ? '' : value);
}}
function scheduleAdminRefresh(seconds) {{
  const sec = Math.max(5, Math.min(300, Number(seconds || 30)));
  if (adminRefreshIntervalId) clearInterval(adminRefreshIntervalId);
  adminRefreshIntervalId = setInterval(refreshAdminLive, sec * 1000);
}}
function readConfigNumber(id) {{
  const el = document.getElementById(id);
  if (!el) return 0;
  return Number(el.value || 0);
}}
function validateProxyBypassRulesText(rawText) {{
  const lines = String(rawText || '').split('\\n');
  const normalized = [];
  const invalid = [];
  const seen = {{}};
  for (let i = 0; i < lines.length; i += 1) {{
    const lineNo = i + 1;
    const line = String(lines[i] || '').trim();
    if (!line || line.indexOf('#') === 0) continue;
    const parts = line.split(',');
    if (parts.length < 2) {{
      invalid.push('L' + lineNo + ': expected "resource,true|false"');
      continue;
    }}
    const resource = String(parts[0] || '').trim().toLowerCase();
    const flag = String(parts[1] || '').trim().toLowerCase();
    if (!resource) {{
      invalid.push('L' + lineNo + ': empty resource');
      continue;
    }}
    if (flag !== 'true' && flag !== 'false') {{
      invalid.push('L' + lineNo + ': flag must be true or false');
      continue;
    }}
    if (seen[resource]) continue;
    seen[resource] = true;
    normalized.push(resource + ',' + flag);
  }}
  return {{
    ok: invalid.length === 0,
    normalized_text: normalized.join('\\n'),
    valid_count: normalized.length,
    errors: invalid
  }};
}}
function renderProxyBypassValidation(rawText) {{
  const input = document.getElementById('cfg-proxy-bypass-custom');
  const validation = document.getElementById('cfg-proxy-bypass-validation');
  const check = validateProxyBypassRulesText(rawText);
  if (validation) {{
    validation.textContent = check.ok
      ? ('Validation: OK (' + String(check.valid_count) + ' rules)')
      : ('Validation: errors -> ' + check.errors.slice(0, 4).join('; '));
    validation.style.color = check.ok ? '#166534' : '#b91c1c';
  }}
  if (input) {{
    input.style.border = check.ok
      ? '1px solid rgba(22,101,52,0.45)'
      : '1px solid rgba(185,28,28,0.65)';
  }}
  return check;
}}
function renderConfigurator(config) {{
  if (!config) return;
  setConfigField('cfg-server-cpu-cores', config.server_cpu_cores);
  setConfigField('cfg-server-ram-gb', config.server_ram_gb);
  setConfigField('cfg-server-storage-gb', config.server_storage_gb);
  setConfigField('cfg-traffic-limit-tb', config.traffic_limit_tb);
  setConfigField('cfg-avg-user-traffic-gb', config.avg_user_monthly_traffic_gb);
  setConfigField('cfg-active-user-ratio-pct', config.active_user_ratio_pct);
  setConfigField('cfg-max-registered-users', config.max_registered_users);
  setConfigField('cfg-target-active-users', config.target_active_users);
  setConfigField('cfg-cpu-warn-p95', config.cpu_warn_p95);
  setConfigField('cfg-cpu-crit-p95', config.cpu_crit_p95);
  setConfigField('cfg-ram-warn-p95', config.ram_warn_p95);
  setConfigField('cfg-ram-crit-p95', config.ram_crit_p95);
  setConfigField('cfg-disk-warn-p95', config.disk_warn_p95);
  setConfigField('cfg-disk-crit-p95', config.disk_crit_p95);
  setConfigField('cfg-dashboard-refresh-seconds', config.dashboard_refresh_seconds || 30);
  setConfigField('cfg-proxy-bypass-custom', config.proxy_bypass_custom || '');
  renderProxyBypassValidation(config.proxy_bypass_custom || '');
  const derived = document.getElementById('cfg-derived');
  if (derived) {{
    derived.textContent =
      `derived: recommended_max_users=${{Number(config.recommended_max_users || 0)}} · ` +
      `recommended_active_users=${{Number(config.recommended_active_users || 0)}} · ` +
      `traffic_budget_per_user=${{Number(config.per_user_traffic_budget_gb || 0).toFixed(2)}} GB/month · ` +
      `refresh=${{Number(config.dashboard_refresh_seconds || 30)}}s · ` +
      `bypass_custom=${{String(config.proxy_bypass_custom || '').split('\\n').filter(Boolean).length}}`;
  }}
  scheduleAdminRefresh(config.dashboard_refresh_seconds || 30);
}}
async function loadConfigurator() {{
  const out = document.getElementById('cfg-out');
  if (out) out.textContent = 'Loading...';
  const r = await fetch('/api/v1/admin/configurator');
  const txt = await r.text();
  if (!r.ok) {{
    if (out) out.textContent = txt;
    return;
  }}
  let j = null;
  try {{ j = JSON.parse(txt); }} catch (e) {{ j = null; }}
  if (!j || !j.config) {{
    if (out) out.textContent = txt;
    return;
  }}
  renderConfigurator(j.config);
  if (out) out.textContent = 'Configuration loaded.';
}}
async function applyConfigurator() {{
  const out = document.getElementById('cfg-out');
  const bypassInput = document.getElementById('cfg-proxy-bypass-custom');
  const bypassRaw = String((bypassInput && bypassInput.value) || '');
  const bypassCheck = renderProxyBypassValidation(bypassRaw);
  if (!bypassCheck.ok) {{
    if (out) out.textContent = 'Invalid bypass rules format. Fix lines: ' + bypassCheck.errors.slice(0, 8).join('; ');
    return;
  }}
  const payload = {{
    server_cpu_cores: readConfigNumber('cfg-server-cpu-cores'),
    server_ram_gb: readConfigNumber('cfg-server-ram-gb'),
    server_storage_gb: readConfigNumber('cfg-server-storage-gb'),
    traffic_limit_tb: readConfigNumber('cfg-traffic-limit-tb'),
    avg_user_monthly_traffic_gb: readConfigNumber('cfg-avg-user-traffic-gb'),
    active_user_ratio_pct: readConfigNumber('cfg-active-user-ratio-pct'),
    max_registered_users: Math.trunc(readConfigNumber('cfg-max-registered-users')),
    target_active_users: Math.trunc(readConfigNumber('cfg-target-active-users')),
    cpu_warn_p95: readConfigNumber('cfg-cpu-warn-p95'),
    cpu_crit_p95: readConfigNumber('cfg-cpu-crit-p95'),
    ram_warn_p95: readConfigNumber('cfg-ram-warn-p95'),
    ram_crit_p95: readConfigNumber('cfg-ram-crit-p95'),
    disk_warn_p95: readConfigNumber('cfg-disk-warn-p95'),
    disk_crit_p95: readConfigNumber('cfg-disk-crit-p95'),
    dashboard_refresh_seconds: Math.trunc(readConfigNumber('cfg-dashboard-refresh-seconds')),
    proxy_bypass_custom: bypassCheck.normalized_text,
  }};
  if (out) out.textContent = 'Applying...';
  const r = await fetch('/api/v1/admin/configurator', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json', 'X-CSRF-Token': getCsrfToken()}},
    body: JSON.stringify(payload)
  }});
  const txt = await r.text();
  if (!r.ok) {{
    if (out) out.textContent = txt;
    return;
  }}
  let j = null;
  try {{ j = JSON.parse(txt); }} catch (e) {{ j = null; }}
  if (j && j.config) renderConfigurator(j.config);
  if (j && j.capacity) renderCapacityStatus(j.capacity);
  if (out) out.textContent = (j && j.message) ? j.message : txt;
  await refreshAdminLive();
}}
async function refreshAdminLive() {{
  const [statsR, onlineR, tsR, trafficR, servicesR, deployEventsR, updateAuditR, capacityR, backupStatusR, securityEventsR, securityBlockedR] = await Promise.all([
    fetch('/api/v1/admin/stats'),
    fetch('/api/v1/admin/online-users'),
    fetch('/api/v1/admin/system-metrics/timeseries?minutes=60'),
    fetch('/api/v1/admin/user-traffic/summary?hours=24'),
    fetch('/api/v1/admin/services/status'),
    fetch('/api/v1/admin/deploy-events?limit=12'),
    fetch('/api/v1/admin/update-audit?' + buildUpdateAuditQuery()),
    fetch('/api/v1/admin/capacity-status?window_minutes=60'),
    fetch('/api/v1/admin/backup-status'),
    fetch('/api/v1/admin/security/events?limit=120'),
    fetch('/api/v1/admin/security/blocked?limit=120')
  ]);
  if (statsR.ok) {{
    const s = (await statsR.json()).stats || {{}};
    document.getElementById('m-online').textContent = String((s.active_sessions === undefined || s.active_sessions === null) ? '-' : s.active_sessions);
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
    const sel = document.getElementById('traffic-user-select');
    if (sel && !sel.value && sel.options && sel.options.length > 0) {{
      sel.value = String(sel.options[0].value || '');
    }}
    await loadAdminUserTrafficDetails();
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
  if (updateAuditR.ok) {{
    const u = await updateAuditR.json();
    renderUpdateAudit(u.items || [], u.path || '', u.reason || '');
  }}
  if (capacityR.ok) {{
    const c = await capacityR.json();
    renderCapacityStatus(c);
  }}
  if (backupStatusR.ok) {{
    const b = await backupStatusR.json();
    renderBackupStatus(b);
  }}
  if (securityEventsR.ok) {{
    const s = await securityEventsR.json();
    securityEventsCache = Array.isArray(s.items) ? s.items : [];
    applySecurityFilters();
    const meta = document.getElementById('security-events-meta');
    if (meta && s.reason) meta.textContent = s.reason;
  }}
  if (securityBlockedR.ok) {{
    const s = await securityBlockedR.json();
    renderSecurityBlocked(s.items || [], s.reason || '');
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
document.addEventListener('change', (event) => {{
  const target = event.target;
  if (!target) return;
  if (target.id === 'service-log-stderr-only') refreshServiceLogsNow();
  if (target.id === 'cfg-proxy-bypass-custom') renderProxyBypassValidation(String(target.value || ''));
  if (target.id === 'traffic-user-select') loadAdminUserTrafficDetails();
}});
document.addEventListener('input', (event) => {{
  const target = event.target;
  if (!target) return;
  if (target.id === 'cfg-proxy-bypass-custom') renderProxyBypassValidation(String(target.value || ''));
}});
document.addEventListener('click', (event) => {{
  const target = event.target;
  if (!target || !target.closest) return;
  if (target.id === 'create-user-modal') {{
    closeCreateUserModal();
    return;
  }}
  if (target.id === 'service-log-modal') {{
    closeServiceLogs();
    return;
  }}
  const tabBtn = target.closest('[data-admin-section]');
  if (tabBtn) {{
    const section = String(tabBtn.getAttribute('data-admin-section') || '').trim();
    const subsection = String(tabBtn.getAttribute('data-admin-subsection') || '').trim();
    if (section) {{
      showSection(section, subsection);
      return;
    }}
  }}
  const actionBtn = target.closest('[data-action]');
  if (actionBtn) {{
    const action = String(actionBtn.getAttribute('data-action') || '').trim();
    if (action === 'apply-configurator') return void applyConfigurator();
    if (action === 'reload-configurator') return void loadConfigurator();
    if (action === 'apply-update-filters') return void applyUpdateAuditFilters();
    if (action === 'reset-update-filters') return void resetUpdateAuditFilters();
    if (action === 'apply-security-filters') return void applySecurityFilters();
    if (action === 'reset-security-filters') return void resetSecurityFilters();
    if (action === 'manual-block-ip') return void manualBlockIp();
    if (action === 'manual-unblock-ip') return void manualUnblockIp();
    if (action === 'open-create-user-modal') return void openCreateUserModal();
    if (action === 'close-create-user-modal') return void closeCreateUserModal();
    if (action === 'create-user') return void createUser();
    if (action === 'bind-wg-peer') return void bindWgPeer();
    if (action === 'bind-xray-client') return void bindXrayClient();
    if (action === 'load-user-traffic-details') return void loadAdminUserTrafficDetails();
    if (action === 'refresh-service-logs') return void refreshServiceLogsNow();
    if (action === 'close-service-logs') return void closeServiceLogs();
    if (action === 'open-service-logs') {{
      const containerName = String(actionBtn.getAttribute('data-container') || '').trim();
      if (containerName) return void openServiceLogs(containerName);
      return;
    }}
    if (action === 'remove-wg-binding') {{
      const publicKey = String(actionBtn.getAttribute('data-public-key') || '').trim();
      if (publicKey) return void removeWgBinding(publicKey);
      return;
    }}
    if (action === 'remove-xray-binding') {{
      const clientEmail = String(actionBtn.getAttribute('data-client-email') || '').trim();
      if (clientEmail) return void removeXrayBinding(clientEmail);
      return;
    }}
    if (action === 'approve-request') {{
      const reqId = Number(actionBtn.getAttribute('data-request-id') || 0);
      if (reqId) return void approveReq(reqId);
      return;
    }}
    if (action === 'reject-request') {{
      const reqId = Number(actionBtn.getAttribute('data-request-id') || 0);
      if (reqId) return void rejectReq(reqId);
      return;
    }}
    if (action === 'block-user') {{
      const userId = Number(actionBtn.getAttribute('data-user-id') || 0);
      if (userId) return void blockUser(userId);
      return;
    }}
    if (action === 'unblock-user') {{
      const userId = Number(actionBtn.getAttribute('data-user-id') || 0);
      if (userId) return void unblockUser(userId);
      return;
    }}
    if (action === 'manual-unblock-ip-item') {{
      const ip = String(actionBtn.getAttribute('data-ip') || '').trim();
      if (ip) return void manualUnblockIp(ip);
      return;
    }}
  }}
  const btn = target.closest('.js-delete-user');
  if (!btn) return;
  const userId = Number(btn.getAttribute('data-user-id') || 0);
  const username = String(btn.getAttribute('data-username') || '');
  if (!userId) return;
  deleteUser(userId, username);
}});
refreshAdminLive();
loadConfigurator();
showSection('overview');
scheduleAdminRefresh(30);
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


@app.get("/api/v1/app/about")
def app_about() -> JSONResponse:
    payload = _read_release_state()
    payload["history"] = _read_update_audit(limit=20)
    return JSONResponse(payload)


@app.post("/api/v1/admin/update/check")
def admin_update_check(request: Request) -> JSONResponse:
    user = _require_admin(request)
    _ensure_csrf(request)
    info = _write_update_request(
        UPDATE_CHECK_REQUEST_PATH,
        {"requested_by": user["username"], "kind": "check_updates"},
    )
    return JSONResponse(
        {
            "status": "ok",
            "message": "Update check request accepted. It will be processed by auto-update service.",
            "request": info,
        }
    )


@app.post("/api/v1/admin/update/apply")
def admin_update_apply(request: Request) -> JSONResponse:
    user = _require_admin(request)
    _ensure_csrf(request)
    info = _write_update_request(
        UPDATE_APPLY_REQUEST_PATH,
        {"requested_by": user["username"], "kind": "apply_update"},
    )
    return JSONResponse(
        {
            "status": "ok",
            "message": "Update apply request accepted. Rebuild will start on next auto-update cycle.",
            "request": info,
        }
    )


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
    enforce_block = not _is_internal_ip(ip)
    locked, wait_seconds = _is_login_locked(username, ip)
    if locked:
        _security_report_event(
            ip=ip,
            attack_type="bruteforce_login",
            direction="inbound->auth",
            reason=f"login locked for {wait_seconds}s",
            severity="high",
            action="blocked" if enforce_block else "observed",
            block_seconds=max(wait_seconds, SECURITY_BLOCK_SECONDS_BRUTE) if enforce_block else 0,
            source="auth-login",
        )
        raise HTTPException(status_code=429, detail=f"Too many attempts. Retry in {wait_seconds}s")
    with _db_connect() as con:
        row = con.execute(
            "SELECT id, username, email, password_hash, role, is_active FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not row or row["is_active"] != 1 or not _verify_password(payload.password, row["password_hash"]):
        _register_failed_login(username, ip)
        lock_now, wait_now = _is_login_locked(username, ip)
        _security_report_event(
            ip=ip,
            attack_type="bruteforce_login",
            direction="inbound->auth",
            reason=f"invalid credentials for user={username}",
            severity="high" if lock_now else "medium",
            action="blocked" if (lock_now and enforce_block) else "observed",
            block_seconds=max(wait_now, SECURITY_BLOCK_SECONDS_BRUTE) if (lock_now and enforce_block) else 0,
            source="auth-login",
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    _reset_failed_login(username, ip)
    _revoke_session(request)
    user = {k: row[k] for k in ["id", "username", "email", "role", "is_active"]}
    profile = _ensure_user_xray_profile(user)
    _ensure_xray_client_in_config(profile["xray_uuid"], profile["xray_email"])
    _ensure_xray_binding_for_user(int(user["id"]), profile["xray_email"], "auto-profile")
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
    _ensure_xray_binding_for_user(int(user["id"]), profile["xray_email"], "auto-profile")
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
    cfg = _load_system_config()
    bypass_custom = _disabled_proxy_bypass_resources(str(cfg.get("proxy_bypass_custom", "")))
    bypass_ru_domains = [
        "yandex.ru",
        "vk.com",
        "gosuslugi.ru",
    ]
    bypass_all = bypass_custom if bypass_custom else []
    bypass_hint = (
        "Routing/Bypass rules: set GeoIP RU and geosite category-ru to DIRECT (bypass proxy). "
        + (
            ("Custom DIRECT resources: " + ", ".join(bypass_all[:20]) + ".")
            if bypass_all
            else "No custom DIRECT resources configured."
        )
    )
    manual_fields_hint = (
        f"Manual fields from this card: Address={host}, Port={port}, UUID={profile['xray_uuid']}, "
        f"Network=tcp, TLS/Reality SNI={sni}, Public Key={pbk}, Short ID={sid}, Flow={flow}, Encryption=none."
    )

    instructions: list[str] = []
    app_name = ""
    primary_client: dict[str, str] = {}
    client_candidates: list[dict[str, str]] = []
    client_about = "Free client for importing VLESS URI and connecting in VPN/proxy mode."
    if device_type == "mobile" and platform == "apple":
        app_name = "Hiddify Next / Karing (free)"
        client_candidates = [
            {
            "name": "Karing",
            "install_url": "https://apps.apple.com/us/app/karing/id6472431552",
            "source": "store",
        }
        ]
        client_about = "Karing is a free Apple client for VLESS/Xray profiles with simple URI import."
        instructions = [
            "Install Karing from App Store using the button below.",
            "Karing menu: Profiles -> + -> Add profile -> VLESS/Reality.",
            manual_fields_hint,
            "Karing menu: Routing -> Bypass/Direct rules -> enable direct for GeoIP: RU and geosite: category-ru.",
            bypass_hint,
            "Alternative quick path: Profiles -> + -> Import from Clipboard, then paste Config URI from this card.",
            "Tap Save -> Connect/Start tunnel -> open blocked site and verify traffic.",
        ]
    elif device_type == "mobile" and platform == "android":
        app_name = "v2rayNG / Hiddify Next (free)"
        client_candidates = [
            {
                "name": "Hiddify Next",
                "install_url": "https://play.google.com/store/apps/details?id=app.hiddify.com",
                "source": "store",
            },
            {
                "name": "v2rayNG",
                "install_url": "https://github.com/2dust/v2rayNG/releases",
                "source": "github",
            },
        ]
        client_about = "Hiddify Next and v2rayNG are free Android clients with stable support for Xray/VLESS links."
        instructions = [
            "Install client using the button below (store variant is prioritized).",
            "Hiddify Next menu: Profiles -> + -> Add profile -> VLESS/Reality.",
            manual_fields_hint,
            "Client menu: Routing/Rules -> add DIRECT for GeoIP: RU and geosite: category-ru.",
            bypass_hint,
            "If profile form is unavailable, use Import from Clipboard and paste Config URI from this card.",
            "Tap Connect (Android VPN permission prompt -> Allow) and verify blocked resource access.",
        ]
    elif device_type == "desktop" and platform == "windows":
        app_name = "v2rayN"
        client_candidates = [
            {
            "name": "v2rayN",
            "install_url": "https://github.com/2dust/v2rayN/releases",
            "source": "github",
        }
        ]
        client_about = "v2rayN is a free Windows GUI client for Xray/VLESS with easy clipboard import."
        instructions = [
            "Download latest v2rayN from releases page.",
            "v2rayN menu: Servers -> Add [VLESS] (or Servers -> Import bulk URL from clipboard).",
            manual_fields_hint,
            "v2rayN menu: Routing settings -> set GeoIP RU and geosite:category-ru to Direct.",
            bypass_hint,
            "Set created node as active -> System Proxy -> Set system proxy.",
            "Start service (if needed) and verify traffic in v2rayN logs + blocked resource test.",
        ]
    elif device_type == "desktop" and platform == "apple":
        app_name = "Nekoray / V2rayU (free)"
        client_candidates = [
            {
            "name": "V2rayU",
            "install_url": "https://github.com/yanue/V2rayU/releases",
            "source": "github",
        }
        ]
        client_about = "V2rayU is a free macOS client that supports VLESS URI import and system proxy modes."
        instructions = [
            "Download and install V2rayU from releases page.",
            "V2rayU menu: Server -> Add [VLESS] (or Import vmess/vless URL from clipboard).",
            manual_fields_hint,
            "V2rayU menu: Routing -> Bypass/Direct -> add GeoIP RU + geosite:category-ru.",
            bypass_hint,
            "Select server as active -> V2rayU -> Turn On V2rayU -> Set System Proxy (Auto/PAC).",
            "Open blocked resource and verify traffic through tunnel.",
        ]
    elif device_type == "desktop" and platform == "linux":
        app_name = "Nekoray / sing-box GUI"
        client_candidates = [
            {
            "name": "Karing",
            "install_url": "https://github.com/KaringX/karing/releases",
            "source": "github",
        }
        ]
        client_about = "Karing provides free Linux builds (AppImage/DEB/RPM) and supports VLESS URI import."
        instructions = [
            "Download Karing (AppImage/DEB/RPM) from releases page.",
            "Karing menu: Profiles -> + -> Add profile -> VLESS/Reality (or Import from Clipboard).",
            manual_fields_hint,
            "Karing menu: Routing -> Bypass/Direct -> add GeoIP RU + geosite:category-ru.",
            bypass_hint,
            "Enable Tun or System Proxy mode (according to distro/network manager setup).",
            "Connect and validate access to blocked endpoint.",
        ]

    if client_candidates:
        store_client = next((c for c in client_candidates if c.get("source") == "store"), None)
        primary_client = dict(store_client or client_candidates[0])
        fallback = next((c for c in client_candidates if c.get("install_url") != primary_client.get("install_url")), None)
        if fallback and fallback.get("install_url"):
            primary_client["fallback_url"] = str(fallback["install_url"])
            primary_client["fallback_label"] = f"{fallback.get('name', 'Mirror')} ({fallback.get('source', 'mirror')})"

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
                    "bypass_geoip": "ru",
                    "bypass_geosite": "category-ru",
                    "bypass_custom": ", ".join(bypass_all[:20]) if bypass_all else "",
                    "bypass_ru_examples": ", ".join(bypass_ru_domains),
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
    threshold = (_now() - timedelta(seconds=ONLINE_WINDOW_SECONDS)).isoformat()
    with _db_connect() as con:
        total_users = con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        active_users = con.execute("SELECT COUNT(*) c FROM users WHERE is_active = 1").fetchone()["c"]
        active_sessions = con.execute(
            """
            SELECT COUNT(DISTINCT s.user_id) c
            FROM sessions s
            WHERE s.revoked = 0
              AND s.expires_at > ?
              AND COALESCE(s.last_seen, s.created_at) >= ?
            """,
            (_now().isoformat(), threshold),
        ).fetchone()["c"]
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


@app.get("/api/v1/admin/capacity-status")
def admin_capacity_status(request: Request, window_minutes: int = 60) -> JSONResponse:
    _require_admin(request)
    return JSONResponse(_read_capacity_status(window_minutes=window_minutes))


@app.get("/api/v1/admin/backup-status")
def admin_backup_status(request: Request) -> JSONResponse:
    _require_admin(request)
    return JSONResponse(_read_backup_state())


@app.get("/api/v1/admin/security/events")
def admin_security_events(request: Request, limit: int = 150) -> JSONResponse:
    _require_admin(request)
    return JSONResponse(_read_security_events(limit=limit))


@app.get("/api/v1/admin/security/blocked")
def admin_security_blocked(request: Request, limit: int = 150) -> JSONResponse:
    _require_admin(request)
    return JSONResponse(_read_security_blocked(limit=limit))


@app.post("/api/v1/admin/security/block")
def admin_security_block(request: Request, payload: AdminSecurityBlockRequest) -> JSONResponse:
    _require_admin(request)
    _ensure_csrf(request)
    res = _security_manual_block(
        ip=payload.ip,
        reason=(payload.reason or "manual block"),
        block_seconds=max(60, int(payload.block_seconds or 900)),
    )
    if res.get("status") != "ok":
        raise HTTPException(status_code=503, detail=str(res.get("reason") or "security guard unavailable"))
    return JSONResponse({"status": "ok", "message": "IP blocked", "result": res.get("result", {})})


@app.post("/api/v1/admin/security/unblock")
def admin_security_unblock(request: Request, payload: AdminSecurityUnblockRequest) -> JSONResponse:
    _require_admin(request)
    _ensure_csrf(request)
    res = _security_manual_unblock(
        ip=payload.ip,
        reason=(payload.reason or "manual unblock"),
    )
    if res.get("status") != "ok":
        raise HTTPException(status_code=503, detail=str(res.get("reason") or "security guard unavailable"))
    return JSONResponse({"status": "ok", "message": "IP unblocked", "result": res.get("result", {})})


@app.get("/api/v1/admin/configurator")
def admin_configurator(request: Request) -> JSONResponse:
    _require_admin(request)
    cfg = _load_system_config()
    return JSONResponse({"status": "ok", "config": cfg})


@app.post("/api/v1/admin/configurator")
def admin_configurator_apply(request: Request, payload: AdminConfiguratorUpdateRequest) -> JSONResponse:
    _require_admin(request)
    _ensure_csrf(request)
    cfg = _persist_system_config(payload.model_dump())
    capacity = _read_capacity_status(window_minutes=60)
    return JSONResponse(
        {
            "status": "ok",
            "message": "Configuration applied. Dependent capacity limits recalculated.",
            "config": cfg,
            "capacity": capacity,
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


@app.get("/api/v1/admin/update-audit")
def admin_update_audit(
    request: Request,
    limit: int = 50,
    status: str = "",
    branch: str = "",
    file_q: str = "",
    commit_q: str = "",
    date_from: str = "",
    date_to: str = "",
) -> JSONResponse:
    _require_admin(request)
    data = _read_update_audit(
        limit=limit,
        status=status,
        branch=branch,
        file_q=file_q,
        commit_q=commit_q,
        date_from=date_from,
        date_to=date_to,
    )
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


def _load_user_traffic_periods(con: sqlite3.Connection, user_id: int) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    windows = {
        "day": "-24 hour",
        "week": "-7 day",
        "month": "-30 day",
        "year": "-365 day",
    }
    for key, expr in windows.items():
        wg = con.execute(
            """
            SELECT COALESCE(SUM(rx_bytes), 0) rx_bytes, COALESCE(SUM(tx_bytes), 0) tx_bytes
            FROM user_wireguard_traffic_samples
            WHERE user_id = ? AND ts >= datetime('now', ?)
            """,
            (user_id, expr),
        ).fetchone()
        xr = con.execute(
            """
            SELECT COALESCE(SUM(rx_bytes), 0) rx_bytes, COALESCE(SUM(tx_bytes), 0) tx_bytes
            FROM user_xray_traffic_samples
            WHERE user_id = ? AND ts >= datetime('now', ?)
            """,
            (user_id, expr),
        ).fetchone()
        rx = int((wg["rx_bytes"] if wg else 0) or 0) + int((xr["rx_bytes"] if xr else 0) or 0)
        tx = int((wg["tx_bytes"] if wg else 0) or 0) + int((xr["tx_bytes"] if xr else 0) or 0)
        if rx == 0 and tx == 0:
            est = con.execute(
                """
                SELECT COALESCE(SUM(rx_bytes), 0) rx_bytes, COALESCE(SUM(tx_bytes), 0) tx_bytes
                FROM user_traffic_samples
                WHERE user_id = ? AND ts >= datetime('now', ?)
                """,
                (user_id, expr),
            ).fetchone()
            rx = int((est["rx_bytes"] if est else 0) or 0)
            tx = int((est["tx_bytes"] if est else 0) or 0)
        out[key] = {"rx_bytes": rx, "tx_bytes": tx, "total_bytes": int(rx + tx)}
    return out


def _build_user_traffic_timeseries_response(user_id: int, minutes: int) -> JSONResponse:
    minutes = max(5, min(24 * 60, int(minutes)))
    _refresh_user_traffic_samples_once()
    with _db_connect() as con:
        user = con.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?",
            (int(user_id),),
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
            (int(user_id), f"-{minutes} minutes"),
        ).fetchall()
        xray_rows = con.execute(
            """
            SELECT ts, SUM(rx_bytes) rx_bytes, SUM(tx_bytes) tx_bytes
            FROM user_xray_traffic_samples
            WHERE user_id = ? AND ts >= datetime('now', ?)
            GROUP BY ts
            ORDER BY ts ASC
            """,
            (int(user_id), f"-{minutes} minutes"),
        ).fetchall()
        rows: list[Any] = []
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
                (int(user_id), f"-{minutes} minutes"),
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


@app.get("/api/v1/user/traffic/summary")
def user_traffic_summary(request: Request) -> JSONResponse:
    user = _require_user(request)
    _refresh_user_traffic_samples_once()
    with _db_connect() as con:
        periods = _load_user_traffic_periods(con, int(user["id"]))
        current = con.execute(
            """
            SELECT cpu_load_pct, memory_used_pct, disk_used_pct, ts
            FROM metric_samples
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    return JSONResponse(
        {
            "status": "ok",
            "periods": periods,
            "resources": {
                "cpu_load_pct": float(current["cpu_load_pct"]) if current else 0.0,
                "memory_used_pct": float(current["memory_used_pct"]) if current else 0.0,
                "disk_used_pct": float(current["disk_used_pct"]) if current else 0.0,
                "ts": str(current["ts"]) if current else "",
            },
        }
    )


@app.get("/api/v1/user/traffic/timeseries")
def user_traffic_timeseries(request: Request, minutes: int = 60) -> JSONResponse:
    user = _require_user(request)
    return _build_user_traffic_timeseries_response(user_id=int(user["id"]), minutes=minutes)


@app.get("/api/v1/admin/user-traffic/summary")
def admin_user_traffic_summary(request: Request, hours: int = 24) -> JSONResponse:
    _require_admin(request)
    _refresh_user_traffic_samples_once()
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
        rows = con.execute(
            """
            SELECT u.id user_id, u.username, u.email, u.role,
                   CASE
                     WHEN (COALESCE(w.rx_bytes, 0) + COALESCE(x.rx_bytes, 0) + COALESCE(w.tx_bytes, 0) + COALESCE(x.tx_bytes, 0)) > 0
                     THEN (COALESCE(w.rx_bytes, 0) + COALESCE(x.rx_bytes, 0))
                     ELSE COALESCE(e.rx_bytes, 0)
                   END rx_bytes,
                   CASE
                     WHEN (COALESCE(w.rx_bytes, 0) + COALESCE(x.rx_bytes, 0) + COALESCE(w.tx_bytes, 0) + COALESCE(x.tx_bytes, 0)) > 0
                     THEN (COALESCE(w.tx_bytes, 0) + COALESCE(x.tx_bytes, 0))
                     ELSE COALESCE(e.tx_bytes, 0)
                   END tx_bytes
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
            LEFT JOIN (
              SELECT user_id, SUM(rx_bytes) rx_bytes, SUM(tx_bytes) tx_bytes
              FROM user_traffic_samples
              WHERE ts >= datetime('now', ?)
              GROUP BY user_id
            ) e ON e.user_id = u.id
            ORDER BY (5 + 6) DESC, u.username ASC
            """,
            (f"-{hours} hours", f"-{hours} hours", f"-{hours} hours"),
        ).fetchall()
        source = "wireguard_xray_exact" if use_exact else "estimated_session_share"
    return JSONResponse(
        {
            "status": "ok",
            "hours": hours,
            "source": source,
            "items": [dict(r) for r in rows],
        }
    )


@app.get("/api/v1/admin/user-traffic/periods")
def admin_user_traffic_periods(request: Request, user_id: int) -> JSONResponse:
    _require_admin(request)
    with _db_connect() as con:
        user = con.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        periods = _load_user_traffic_periods(con, int(user_id))
    return JSONResponse({"status": "ok", "user": dict(user), "periods": periods})


@app.get("/api/v1/admin/user-traffic/timeseries")
def admin_user_traffic_timeseries(request: Request, user_id: int, minutes: int = 60) -> JSONResponse:
    _require_admin(request)
    return _build_user_traffic_timeseries_response(user_id=int(user_id), minutes=minutes)


@app.get("/api/v1/admin/wireguard-bindings")
def admin_wireguard_bindings(request: Request) -> JSONResponse:
    _require_admin(request)
    _refresh_user_traffic_samples_once()
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
    _refresh_user_traffic_samples_once()
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
