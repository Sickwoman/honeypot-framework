"""Unit tests for the RBAC matrix and the permission-based Flask decorator.

Covers:
  * the role -> permission matrix and hierarchy in api/rbac.py
  * require_permission() authorization behavior (200 vs 401 vs 403) using a JWT
    minted by the real JWTManager (no DB, no server needed).
"""
import pytest
from flask import Flask, jsonify

from api.auth import jwt_manager
from api.decorators import require_permission
from api.rbac import (
    ROLE_PERMISSIONS,
    Permission,
    Role,
    has_all_permissions,
    has_permission,
    is_valid_role,
    permissions_for,
)


# --------------------------------------------------------------------------- #
# RBAC matrix
# --------------------------------------------------------------------------- #
def test_all_roles_present():
    assert set(ROLE_PERMISSIONS) == set(Role.ALL)


def test_hierarchy_is_strictly_increasing():
    """observer < analyst < responder < admin (each a superset of the prior)."""
    observer = ROLE_PERMISSIONS[Role.OBSERVER]
    analyst = ROLE_PERMISSIONS[Role.ANALYST]
    responder = ROLE_PERMISSIONS[Role.RESPONDER]
    admin = ROLE_PERMISSIONS[Role.ADMIN]

    assert observer < analyst < responder < admin


def test_observer_is_read_only():
    perms = ROLE_PERMISSIONS[Role.OBSERVER]
    assert Permission.ALERTS_READ in perms
    assert Permission.STATS_READ in perms
    assert Permission.ALERTS_DELETE not in perms
    assert Permission.ALERTS_CREATE not in perms


def test_analyst_can_create_but_not_modify():
    perms = ROLE_PERMISSIONS[Role.ANALYST]
    assert Permission.ALERTS_CREATE in perms
    assert Permission.INCIDENTS_CREATE in perms
    assert Permission.ALERTS_DELETE not in perms
    assert Permission.USERS_MANAGE not in perms


def test_responder_can_modify_but_not_manage_users():
    perms = ROLE_PERMISSIONS[Role.RESPONDER]
    assert Permission.ALERTS_DELETE in perms
    assert Permission.ALERTS_RESOLVE in perms
    assert Permission.USERS_MANAGE not in perms


def test_admin_has_everything():
    admin = ROLE_PERMISSIONS[Role.ADMIN]
    for role_perms in ROLE_PERMISSIONS.values():
        assert role_perms <= admin
    assert Permission.USERS_MANAGE in admin


def test_is_valid_role():
    assert is_valid_role(Role.ADMIN)
    assert not is_valid_role("superuser")
    assert not is_valid_role("")


def test_permissions_for_unions_and_ignores_unknown():
    assert permissions_for([Role.OBSERVER]) == ROLE_PERMISSIONS[Role.OBSERVER]
    # Unknown roles contribute nothing.
    assert permissions_for(["bogus"]) == set()
    # Union of two roles = the higher one here (hierarchy).
    assert permissions_for([Role.OBSERVER, Role.RESPONDER]) == \
        set(ROLE_PERMISSIONS[Role.RESPONDER])


def test_has_permission_and_has_all():
    assert has_permission([Role.OBSERVER], Permission.ALERTS_READ)
    assert not has_permission([Role.OBSERVER], Permission.ALERTS_DELETE)
    assert has_all_permissions(
        [Role.RESPONDER], [Permission.ALERTS_READ, Permission.ALERTS_DELETE]
    )
    assert not has_all_permissions(
        [Role.ANALYST], [Permission.ALERTS_READ, Permission.ALERTS_DELETE]
    )


# --------------------------------------------------------------------------- #
# require_permission decorator
# --------------------------------------------------------------------------- #
@pytest.fixture
def client():
    app = Flask(__name__)

    @app.route("/read")
    @require_permission(Permission.ALERTS_READ)
    def read():
        return jsonify(ok=True)

    @app.route("/delete", methods=["DELETE"])
    @require_permission(Permission.ALERTS_DELETE)
    def delete():
        return jsonify(ok=True)

    return app.test_client()


def _bearer(role):
    token = jwt_manager.generate_token(user_id="u1", username="tester", roles=[role])
    return {"Authorization": f"Bearer {token}"}


def test_no_credentials_is_401(client):
    assert client.get("/read").status_code == 401


def test_observer_can_read(client):
    resp = client.get("/read", headers=_bearer(Role.OBSERVER))
    assert resp.status_code == 200


def test_observer_cannot_delete(client):
    resp = client.delete("/delete", headers=_bearer(Role.OBSERVER))
    assert resp.status_code == 403
    assert Permission.ALERTS_DELETE in resp.get_json()["missing"]


def test_responder_can_delete(client):
    resp = client.delete("/delete", headers=_bearer(Role.RESPONDER))
    assert resp.status_code == 200


def test_admin_can_delete(client):
    resp = client.delete("/delete", headers=_bearer(Role.ADMIN))
    assert resp.status_code == 200


def test_invalid_token_is_401(client):
    resp = client.get("/read", headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401
