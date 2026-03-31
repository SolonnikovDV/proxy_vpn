import ipaddress
import json
import os
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel

DB_PATH = os.getenv("SECURITY_DB_PATH", "/data/security.db")
GEOIP_ENABLED = os.getenv("SECURITY_GEOIP_ENABLED", "1") == "1"
GEOIP_TIMEOUT_SECONDS = float(os.getenv("SECURITY_GEOIP_TIMEOUT_SECONDS", "1.5"))
DEFAULT_BLOCK_SECONDS = int(os.getenv("SECURITY_DEFAULT_BLOCK_SECONDS", "900"))
MAX_EVENT_LIMIT = 500
TARGET_PANEL_API = "panel/api"
REASON_MANUAL_BLOCK = "manual block"
SQL_INSERT_SECURITY_EVENT = """
INSERT INTO security_events (
    ts, ip, country, city, asn, attack_type, direction, target, action, severity, reason, source, count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_GEO_CACHE: dict[str, dict[str, str]] = {}
_GEO_LOCK = Lock()

app = FastAPI(title="proxy-vpn security guard", version="0.1.0")


class SecurityEventIn(BaseModel):
    ip: str
    attack_type: str
    direction: str
    target: str = TARGET_PANEL_API
    severity: str = "medium"
    reason: str = ""
    source: str = "api"
    action: str = "observed"
    block_seconds: int = 0
    count: int = 1


class SecurityBlockIn(BaseModel):
    ip: str
    reason: str = REASON_MANUAL_BLOCK
    block_seconds: int = DEFAULT_BLOCK_SECONDS


class SecurityUnblockIn(BaseModel):
    ip: str
    reason: str = "manual unblock"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _db_connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with _db_connect() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                country TEXT,
                city TEXT,
                asn TEXT,
                attack_type TEXT NOT NULL,
                direction TEXT NOT NULL,
                target TEXT NOT NULL,
                action TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT,
                source TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_until TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip)")
        con.commit()


def _normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except Exception:
        return value.strip()


def _local_geo(ip: str) -> dict[str, str]:
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private:
            return {"country": "Private network", "city": "-", "asn": "local/private"}
        if obj.is_loopback:
            return {"country": "Loopback", "city": "-", "asn": "local/loopback"}
    except Exception:
        pass
    return {"country": "Unknown", "city": "-", "asn": "-"}


def _lookup_geo(ip: str) -> dict[str, str]:
    with _GEO_LOCK:
        cached = _GEO_CACHE.get(ip)
    if cached:
        return cached
    local = _local_geo(ip)
    if not GEOIP_ENABLED or local["country"] != "Unknown":
        with _GEO_LOCK:
            _GEO_CACHE[ip] = local
        return local
    try:
        url = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,country,city,as,message"
        req = urllib.request.Request(url, headers={"User-Agent": "proxy-vpn-security-guard/1.0"})
        with urllib.request.urlopen(req, timeout=GEOIP_TIMEOUT_SECONDS) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        if str(payload.get("status", "")).lower() == "success":
            data = {
                "country": str(payload.get("country") or "Unknown"),
                "city": str(payload.get("city") or "-"),
                "asn": str(payload.get("as") or "-"),
            }
        else:
            data = local
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        data = local
    with _GEO_LOCK:
        _GEO_CACHE[ip] = data
    return data


def _block_ip(con: sqlite3.Connection, ip: str, reason: str, block_seconds: int) -> str:
    now = _now()
    until = (now + timedelta(seconds=max(60, block_seconds))).isoformat()
    existing = con.execute("SELECT ip FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    if existing:
        con.execute(
            "UPDATE blocked_ips SET blocked_until = ?, reason = ?, updated_at = ? WHERE ip = ?",
            (until, reason, now.isoformat(), ip),
        )
    else:
        con.execute(
            "INSERT INTO blocked_ips (ip, blocked_until, reason, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (ip, until, reason, now.isoformat(), now.isoformat()),
        )
    return until


@app.on_event("startup")
def startup() -> None:
    _init_db()


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok"}


@app.get("/blocked/check")
def blocked_check(ip: str) -> dict[str, Any]:
    ip = _normalize_ip(ip)
    now = _now().isoformat()
    with _db_connect() as con:
        row = con.execute("SELECT blocked_until, reason FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        if not row:
            return {"status": "ok", "blocked": False, "ip": ip}
        if str(row["blocked_until"]) <= now:
            con.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
            con.commit()
            return {"status": "ok", "blocked": False, "ip": ip}
        return {
            "status": "ok",
            "blocked": True,
            "ip": ip,
            "blocked_until": row["blocked_until"],
            "reason": row["reason"] or "",
        }


@app.post("/event")
def ingest_event(payload: SecurityEventIn) -> dict[str, Any]:
    ip = _normalize_ip(payload.ip)
    geo = _lookup_geo(ip)
    now = _now()
    block_seconds = int(payload.block_seconds or 0)
    action = payload.action
    blocked_until: Optional[str] = None
    with _db_connect() as con:
        if block_seconds > 0:
            action = "blocked"
            blocked_until = _block_ip(
                con,
                ip=ip,
                reason=payload.reason or payload.attack_type,
                block_seconds=block_seconds or DEFAULT_BLOCK_SECONDS,
            )
        con.execute(
            SQL_INSERT_SECURITY_EVENT,
            (
                now.isoformat(),
                ip,
                geo.get("country", "Unknown"),
                geo.get("city", "-"),
                geo.get("asn", "-"),
                payload.attack_type,
                payload.direction,
                payload.target,
                action,
                payload.severity,
                payload.reason,
                payload.source,
                max(1, int(payload.count or 1)),
            ),
        )
        con.commit()
    return {
        "status": "ok",
        "action": action,
        "ip": ip,
        "blocked_until": blocked_until,
    }


@app.post("/block")
def manual_block(payload: SecurityBlockIn) -> dict[str, Any]:
    ip = _normalize_ip(payload.ip)
    now = _now().isoformat()
    with _db_connect() as con:
        blocked_until = _block_ip(
            con,
            ip=ip,
            reason=payload.reason or REASON_MANUAL_BLOCK,
            block_seconds=max(60, int(payload.block_seconds or DEFAULT_BLOCK_SECONDS)),
        )
        geo = _lookup_geo(ip)
        con.execute(
            SQL_INSERT_SECURITY_EVENT,
            (
                now,
                ip,
                geo.get("country", "Unknown"),
                geo.get("city", "-"),
                geo.get("asn", "-"),
                "manual_block",
                "admin->security",
                TARGET_PANEL_API,
                "blocked",
                "high",
                payload.reason or REASON_MANUAL_BLOCK,
                "admin-ui",
                1,
            ),
        )
        con.commit()
    return {"status": "ok", "ip": ip, "blocked_until": blocked_until}


@app.post("/unblock")
def manual_unblock(payload: SecurityUnblockIn) -> dict[str, Any]:
    ip = _normalize_ip(payload.ip)
    now = _now().isoformat()
    with _db_connect() as con:
        con.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        geo = _lookup_geo(ip)
        con.execute(
            SQL_INSERT_SECURITY_EVENT,
            (
                now,
                ip,
                geo.get("country", "Unknown"),
                geo.get("city", "-"),
                geo.get("asn", "-"),
                "manual_unblock",
                "admin->security",
                TARGET_PANEL_API,
                "mitigated",
                "low",
                payload.reason or "manual unblock",
                "admin-ui",
                1,
            ),
        )
        con.commit()
    return {"status": "ok", "ip": ip}


@app.get("/events")
def events(limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(MAX_EVENT_LIMIT, int(limit)))
    with _db_connect() as con:
        rows = con.execute(
            """
            SELECT ts, ip, country, city, asn, attack_type, direction, target, action, severity, reason, source, count
            FROM security_events
            ORDER BY ts DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {"status": "ok", "items": [dict(r) for r in rows]}


@app.get("/blocked")
def blocked(limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(MAX_EVENT_LIMIT, int(limit)))
    now = _now().isoformat()
    with _db_connect() as con:
        con.execute("DELETE FROM blocked_ips WHERE blocked_until <= ?", (now,))
        rows = con.execute(
            """
            SELECT ip, blocked_until, reason, created_at, updated_at
            FROM blocked_ips
            ORDER BY blocked_until DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        con.commit()
    return {"status": "ok", "items": [dict(r) for r in rows]}
