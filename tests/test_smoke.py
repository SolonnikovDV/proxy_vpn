"""Smoke tests for API without Docker (run from repo root)."""

import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
TEST_DB_PATH = ROOT / "data" / "test_smoke.db"
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
sys.path.insert(0, str(ROOT / "api"))

from app.config import settings  # noqa: E402
from app.main import _db_connect, _now, app  # noqa: E402


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _cleanup_smoke_entities() -> None:
    with _db_connect() as con:
        exists = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users' LIMIT 1"
        ).fetchone()
        if not exists:
            return
        rows = con.execute("SELECT id, username, email FROM users WHERE username LIKE 'smoke_%'").fetchall()
        user_ids = [int(r["id"]) for r in rows]
        for uid in user_ids:
            con.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
            con.execute("DELETE FROM user_traffic_samples WHERE user_id = ?", (uid,))
            con.execute("DELETE FROM user_wireguard_traffic_samples WHERE user_id = ?", (uid,))
            con.execute("DELETE FROM user_xray_traffic_samples WHERE user_id = ?", (uid,))
            con.execute("DELETE FROM wg_peer_bindings WHERE user_id = ?", (uid,))
            con.execute("DELETE FROM xray_client_bindings WHERE user_id = ?", (uid,))
        con.execute("DELETE FROM users WHERE username LIKE 'smoke_%'")
        con.execute("DELETE FROM registration_requests WHERE username LIKE 'smoke_%'")
        con.execute("DELETE FROM xray_client_counters WHERE client_email LIKE 'smoke_%@proxy-vpn'")
        con.commit()


@pytest.fixture(autouse=True)
def cleanup_smoke_data():
    _cleanup_smoke_entities()
    yield
    _cleanup_smoke_entities()


def test_health(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["service"] == "proxy-vpn"


def test_meta(client: TestClient):
    r = client.get("/api/v1/meta")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "proxy-vpn"
    assert "wireguard" in body["stack"]


def _csrf_headers(client: TestClient) -> dict[str, str]:
    token = client.cookies.get("proxy_vpn_csrf")
    assert token
    return {"X-CSRF-Token": token}


def _admin_login(client: TestClient) -> None:
    csrf_resp = client.get("/api/v1/auth/csrf")
    assert csrf_resp.status_code == 200
    login_resp = client.post(
        "/api/v1/auth/login",
        headers={"X-CSRF-Token": csrf_resp.json()["csrf_token"]},
        json={"username": settings.admin_username, "password": settings.admin_password},
    )
    assert login_resp.status_code == 200


def test_admin_xray_bindings_flow(client: TestClient):
    _admin_login(client)
    suffix = uuid.uuid4().hex[:8]
    username = f"smoke_xray_{suffix}"
    email = f"{username}@example.com"
    create_resp = client.post(
        "/api/v1/admin/users/create",
        headers=_csrf_headers(client),
        json={"username": username, "email": email, "password": "StrongPwd123!", "role": "user"},
    )
    assert create_resp.status_code == 200

    with _db_connect() as con:
        row = con.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        assert row is not None
        user_id = int(row["id"])

    client_email = f"{username}@proxy-vpn"
    bind_resp = client.post(
        "/api/v1/admin/xray-bindings",
        headers=_csrf_headers(client),
        json={"user_id": user_id, "client_email": client_email, "label": "smoke"},
    )
    assert bind_resp.status_code == 200

    list_resp = client.get("/api/v1/admin/xray-bindings")
    assert list_resp.status_code == 200
    items = list_resp.json()["items"]
    assert any(i["client_email"] == client_email and i["user_id"] == user_id for i in items)

    unbind_resp = client.delete(f"/api/v1/admin/xray-bindings/{client_email}", headers=_csrf_headers(client))
    assert unbind_resp.status_code == 200


def test_admin_user_traffic_combined_exact_source(client: TestClient):
    _admin_login(client)
    suffix = uuid.uuid4().hex[:8]
    username = f"smoke_traffic_{suffix}"
    email = f"{username}@example.com"
    create_resp = client.post(
        "/api/v1/admin/users/create",
        headers=_csrf_headers(client),
        json={"username": username, "email": email, "password": "StrongPwd123!", "role": "user"},
    )
    assert create_resp.status_code == 200

    with _db_connect() as con:
        row = con.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        assert row is not None
        user_id = int(row["id"])
        con.execute(
            """
            INSERT INTO user_xray_traffic_samples
            (ts, user_id, client_email, rx_bytes, tx_bytes, downlink_total, uplink_total)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (_now().isoformat(), user_id, f"{username}@proxy-vpn", 1024, 2048, 123456, 654321),
        )
        con.commit()

    summary_resp = client.get("/api/v1/admin/user-traffic/summary?hours=24")
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert summary["source"] == "wireguard_xray_exact"
    assert any(i["user_id"] == user_id for i in summary["items"])

    ts_resp = client.get(f"/api/v1/admin/user-traffic/timeseries?user_id={user_id}&minutes=60")
    assert ts_resp.status_code == 200
    ts_body = ts_resp.json()
    assert ts_body["source"] == "wireguard_xray_exact"
    assert isinstance(ts_body["points"], list)


def test_admin_user_traffic_timeseries_fallback_estimated(client: TestClient):
    _admin_login(client)
    suffix = uuid.uuid4().hex[:8]
    username = f"smoke_fallback_{suffix}"
    email = f"{username}@example.com"
    create_resp = client.post(
        "/api/v1/admin/users/create",
        headers=_csrf_headers(client),
        json={"username": username, "email": email, "password": "StrongPwd123!", "role": "user"},
    )
    assert create_resp.status_code == 200

    with _db_connect() as con:
        row = con.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        assert row is not None
        user_id = int(row["id"])
        # Ensure this specific user has no exact samples.
        con.execute("DELETE FROM user_wireguard_traffic_samples WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM user_xray_traffic_samples WHERE user_id = ?", (user_id,))
        con.execute(
            """
            INSERT INTO user_traffic_samples
            (ts, user_id, rx_bytes, tx_bytes)
            VALUES (?, ?, ?, ?)
            """,
            (_now().isoformat(), user_id, 3000, 7000),
        )
        con.commit()

    ts_resp = client.get(f"/api/v1/admin/user-traffic/timeseries?user_id={user_id}&minutes=60")
    assert ts_resp.status_code == 200
    ts_body = ts_resp.json()
    assert ts_body["source"] == "estimated_session_share"
    assert isinstance(ts_body["points"], list)
