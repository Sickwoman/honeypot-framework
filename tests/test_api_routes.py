"""Route-level tests for the real Flask app.

Everything else in the suite calls AlertService and friends directly as
Python. These tests go through `alerts_service.app.test_client()` instead, so
they exercise what direct calls skip entirely: the decorator stack
(`@require_permission` -> `@rate_limit` -> `@log_request_response`), request
parsing, HTTP status codes, and the error paths on each route.
"""
import pytest

from api import alerts_service as alerts_module
from api import auth_routes as auth_module
from api.auth import jwt_manager
from api.middleware import RateLimiter
from api.rbac import Role
from api.user_manager import UserManager


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Point the app's services at a per-test database."""
    db_path = str(tmp_path / "alerts.db")

    service = alerts_module.AlertService(db_path=db_path)
    monkeypatch.setattr(alerts_module, "alert_service", service)
    monkeypatch.setattr(alerts_module.audit_logger, "_db_path", db_path)

    users = UserManager(db_path=db_path)
    monkeypatch.setattr(auth_module, "user_manager", users)
    monkeypatch.setattr(auth_module.audit_logger, "_db_path", db_path)

    return {"db_path": db_path, "service": service, "users": users}


@pytest.fixture(autouse=True)
def no_rate_limiting(monkeypatch):
    """Rate limiting is verified in test_auth.py; here it would just make
    results depend on how many tests ran before this one."""
    monkeypatch.setattr(RateLimiter, "is_rate_limited", lambda self, client_id: False)


@pytest.fixture(autouse=True)
def no_threat_intel_subprocess(monkeypatch):
    """Alert creation shells out to the Node enricher; keep tests offline."""
    monkeypatch.setattr(alerts_module, "enrich_alert_with_threat_intel", lambda data: data)


@pytest.fixture(autouse=True)
def no_playbook_side_effects(monkeypatch):
    monkeypatch.setattr(alerts_module, "trigger_matching_playbooks", lambda *a, **k: [])


@pytest.fixture
def client():
    alerts_module.app.config.update(TESTING=True)
    return alerts_module.app.test_client()


def auth_header(role=Role.ADMIN, username="tester"):
    token = jwt_manager.generate_token(user_id="u-1", username=username, roles=[role])
    return {"Authorization": f"Bearer {token}"}


SAMPLE_ALERT = {
    "alert_name": "SSHBruteForce",
    "severity": "HIGH",
    "source_ip": "203.0.113.10",
    "honeypot_type": "cowrie",
    "service_name": "ssh",
    "description": "repeated failed logins",
}


# --------------------------------------------------------------------------- #
# Health / authentication
# --------------------------------------------------------------------------- #
def test_health_needs_no_auth(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "healthy"


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/v1/alerts"),
        ("post", "/api/v1/alerts"),
        ("get", "/api/v1/alerts/statistics"),
        ("get", "/api/v1/alerts/top-ips"),
        ("get", "/api/v1/playbooks"),
        ("get", "/api/v1/users"),
    ],
)
def test_routes_reject_anonymous_callers(client, method, path):
    response = getattr(client, method)(path)

    assert response.status_code == 401


def test_invalid_token_is_rejected(client):
    response = client.get("/api/v1/alerts", headers={"Authorization": "Bearer nonsense"})

    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# Authorization: the RBAC matrix enforced through real routes
# --------------------------------------------------------------------------- #
def test_observer_can_read_alerts(client):
    response = client.get("/api/v1/alerts", headers=auth_header(Role.OBSERVER))

    assert response.status_code == 200


def test_observer_cannot_create_alerts(client):
    response = client.post(
        "/api/v1/alerts", json=SAMPLE_ALERT, headers=auth_header(Role.OBSERVER)
    )

    assert response.status_code == 403
    assert "alerts:create" in response.get_json()["missing"]


def test_analyst_cannot_delete_alerts(client):
    created = client.post(
        "/api/v1/alerts", json=SAMPLE_ALERT, headers=auth_header(Role.ANALYST)
    )
    alert_id = created.get_json()["id"]

    response = client.delete(
        f"/api/v1/alerts/{alert_id}", headers=auth_header(Role.ANALYST)
    )

    assert response.status_code == 403


def test_analyst_cannot_manage_users(client):
    response = client.get("/api/v1/users", headers=auth_header(Role.ANALYST))

    assert response.status_code == 403


def test_admin_can_list_users(client):
    response = client.get("/api/v1/users", headers=auth_header(Role.ADMIN))

    assert response.status_code == 200
    assert "users" in response.get_json()


# --------------------------------------------------------------------------- #
# Alert lifecycle
# --------------------------------------------------------------------------- #
def test_alert_lifecycle_create_read_acknowledge_resolve_delete(client):
    headers = auth_header(Role.ADMIN)

    created = client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=headers)
    assert created.status_code == 201
    alert_id = created.get_json()["id"]

    fetched = client.get(f"/api/v1/alerts/{alert_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.get_json()["alert_name"] == "SSHBruteForce"

    acknowledged = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge", json={"reason": "triaged"}, headers=headers
    )
    assert acknowledged.status_code == 200
    assert acknowledged.get_json()["status"] == "acknowledged"

    resolved = client.post(
        f"/api/v1/alerts/{alert_id}/resolve", json={"notes": "blocked"}, headers=headers
    )
    assert resolved.status_code == 200

    deleted = client.delete(f"/api/v1/alerts/{alert_id}", headers=headers)
    assert deleted.status_code == 200
    assert deleted.get_json()["status"] == "archived"

    # Archived alerts drop out of the default listing.
    listed = client.get("/api/v1/alerts", headers=headers)
    assert all(a["id"] != alert_id for a in listed.get_json()["alerts"])


def test_create_alert_requires_mandatory_fields(client):
    response = client.post(
        "/api/v1/alerts", json={"severity": "HIGH"}, headers=auth_header(Role.ADMIN)
    )

    assert response.status_code == 400
    assert "Missing required fields" in response.get_json()["error"]


def test_unknown_alert_returns_404(client):
    response = client.get("/api/v1/alerts/does-not-exist", headers=auth_header(Role.ADMIN))

    assert response.status_code == 404


def test_alerts_can_be_filtered_by_severity(client):
    headers = auth_header(Role.ADMIN)
    client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=headers)
    client.post(
        "/api/v1/alerts",
        json={**SAMPLE_ALERT, "alert_name": "PortScan", "severity": "LOW"},
        headers=headers,
    )

    response = client.get("/api/v1/alerts?severity=LOW", headers=headers)

    payload = response.get_json()
    assert payload["total"] == 1
    assert payload["alerts"][0]["alert_name"] == "PortScan"


def test_alert_listing_reports_pagination(client):
    headers = auth_header(Role.ADMIN)
    for i in range(3):
        client.post(
            "/api/v1/alerts",
            json={**SAMPLE_ALERT, "alert_name": f"Alert{i}"},
            headers=headers,
        )

    response = client.get("/api/v1/alerts?limit=2&offset=0", headers=headers)

    payload = response.get_json()
    assert payload["total"] == 3
    assert len(payload["alerts"]) == 2
    assert payload["has_more"] is True


def test_statistics_route_returns_totals(client):
    headers = auth_header(Role.ADMIN)
    client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=headers)

    response = client.get("/api/v1/alerts/statistics", headers=headers)

    assert response.status_code == 200
    assert response.get_json()["total_alerts"] == 1


def test_top_ips_route_returns_attackers(client):
    headers = auth_header(Role.ADMIN)
    client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=headers)

    response = client.get("/api/v1/alerts/top-ips", headers=headers)

    assert response.status_code == 200
    assert response.get_json()["top_ips"][0]["source_ip"] == "203.0.113.10"


# --------------------------------------------------------------------------- #
# Error handling: internal detail must not reach the caller
# --------------------------------------------------------------------------- #
SECRET_ERROR = "SELECT * FROM secrets failed at /var/lib/honeypot/alerts.db"


@pytest.mark.parametrize(
    "service_method,path",
    [
        ("query_alerts", "/api/v1/alerts"),
        ("get_alert", "/api/v1/alerts/some-id"),
        ("get_alert_statistics", "/api/v1/alerts/statistics"),
        ("get_top_attacking_ips", "/api/v1/alerts/top-ips"),
    ],
)
def test_server_errors_do_not_leak_internals(client, monkeypatch, service_method, path):
    """A 500 must not hand the caller SQL, file paths or stack detail."""

    def explode(*args, **kwargs):
        raise RuntimeError(SECRET_ERROR)

    monkeypatch.setattr(alerts_module.alert_service, service_method, explode)

    response = client.get(path, headers=auth_header(Role.ADMIN))

    assert response.status_code == 500
    body = str(response.get_json())
    assert response.get_json()["error"] == "Internal server error"
    assert "secrets" not in body
    assert "/var/lib/honeypot" not in body


# --------------------------------------------------------------------------- #
# Auth routes
# --------------------------------------------------------------------------- #
def test_login_issues_a_usable_token(client, isolated_db):
    isolated_db["users"].create_user("analyst-a", "correct-horse-battery", Role.ANALYST)

    response = client.post(
        "/auth/login", json={"username": "analyst-a", "password": "correct-horse-battery"}
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["token_type"] == "Bearer"
    assert payload["user"]["role"] == Role.ANALYST

    # The issued token actually authenticates a subsequent request.
    follow_up = client.get(
        "/api/v1/alerts", headers={"Authorization": f"Bearer {payload['token']}"}
    )
    assert follow_up.status_code == 200


def test_login_rejects_bad_password(client, isolated_db):
    isolated_db["users"].create_user("analyst-b", "correct-horse-battery", Role.ANALYST)

    response = client.post(
        "/auth/login", json={"username": "analyst-b", "password": "wrong"}
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "Invalid credentials"


def test_login_requires_both_fields(client):
    response = client.post("/auth/login", json={"username": "someone"})

    assert response.status_code == 400


def test_whoami_reports_effective_permissions(client):
    response = client.get("/auth/whoami", headers=auth_header(Role.RESPONDER))

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["roles"] == [Role.RESPONDER]
    assert "alerts:resolve" in payload["permissions"]
    assert "users:manage" not in payload["permissions"]
