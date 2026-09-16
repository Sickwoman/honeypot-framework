"""Tests for authentication hardening.

Covers the brute-force and credential-handling protections:
  * api/auth.py refuses to import without a JWT signing secret
  * the rate_limit decorator actually throttles (its counter must persist
    across requests, not reset on every call)
  * repeated failed logins lock an account for a cooldown window
  * API keys are persisted, so a key minted by one worker validates on another
"""
import os
import subprocess
import sys
from datetime import datetime, timedelta

import pytest
from flask import Flask, jsonify

from api.auth import APIKeyManager, AuthenticationError
from api.middleware import rate_limit
from api.user_manager import MAX_FAILED_LOGIN_ATTEMPTS, UserError, UserManager

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# --------------------------------------------------------------------------- #
# JWT signing secret
# --------------------------------------------------------------------------- #
def test_auth_module_refuses_to_import_without_jwt_secret(tmp_path):
    """No hardcoded fallback secret: importing must fail loudly instead.

    api/env.py loads a repo-root .env on import (so JWT_SECRET_KEY can be set
    there, not just in the real environment) -- point HONEYPOT_ENV_FILE at an
    empty file that is guaranteed not to exist, so this test doesn't depend on
    whether a real .env happens to be checked out on the machine running it.
    """
    env = {k: v for k, v in os.environ.items() if k != "JWT_SECRET_KEY"}
    env["PYTHONPATH"] = REPO_ROOT
    env["HONEYPOT_ENV_FILE"] = str(tmp_path / "no-such.env")

    result = subprocess.run(
        [sys.executable, "-c", "import api.auth"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
    )

    assert result.returncode != 0
    assert "JWT_SECRET_KEY" in result.stderr


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
@pytest.fixture
def limited_client():
    app = Flask(__name__)

    @app.route("/limited", methods=["POST"])
    @rate_limit(max_requests=3, window_seconds=60)
    def limited():
        return jsonify(ok=True)

    return app.test_client()


def test_rate_limit_blocks_after_threshold(limited_client):
    for _ in range(3):
        assert limited_client.post("/limited").status_code == 200

    # The 4th request in the window must be rejected -- a limiter rebuilt per
    # request would let this through forever.
    response = limited_client.post("/limited")
    assert response.status_code == 429
    assert "Rate limit" in response.get_json()["error"]


# --------------------------------------------------------------------------- #
# Account lockout
# --------------------------------------------------------------------------- #
@pytest.fixture
def user_manager(tmp_path):
    return UserManager(db_path=str(tmp_path / "users.db"))


def test_lockout_after_repeated_failed_logins(user_manager):
    user_manager.create_user("analyst1", "correct-horse-battery", "analyst")

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        assert user_manager.verify_credentials("analyst1", "wrong") is None

    # Correct credentials are refused while the lockout window is open.
    assert user_manager.verify_credentials("analyst1", "correct-horse-battery") is None


def test_successful_login_resets_failure_counter(user_manager):
    user_manager.create_user("analyst2", "correct-horse-battery", "analyst")

    assert user_manager.verify_credentials("analyst2", "wrong") is None
    assert user_manager.verify_credentials("analyst2", "correct-horse-battery") is not None
    assert user_manager.get_by_username("analyst2")["failed_login_attempts"] == 0


def test_lockout_expires_after_cooldown(user_manager):
    stale = (datetime.utcnow() - timedelta(days=1)).isoformat()
    user = {"failed_login_attempts": MAX_FAILED_LOGIN_ATTEMPTS, "updated_at": stale}

    assert not user_manager.is_locked_out(user)


def test_invalid_role_is_rejected(user_manager):
    from api.user_manager import UserError

    with pytest.raises(UserError):
        user_manager.create_user("nobody", "pw", "superuser")


# --------------------------------------------------------------------------- #
# API key persistence
# --------------------------------------------------------------------------- #
def test_api_key_validates_across_manager_instances(tmp_path):
    """Keys must live in the DB: with multiple API workers, the process that
    validates a key is usually not the one that minted it."""
    db_path = str(tmp_path / "keys.db")
    UserManager(db_path=db_path)  # bootstraps the schema (api_keys table)

    minting_worker = APIKeyManager(db_path=db_path)
    api_key, _ = minting_worker.generate_api_key("u1", "svc", roles=["analyst"])

    other_worker = APIKeyManager(db_path=db_path)
    key_info = other_worker.validate_api_key(api_key)

    assert key_info["user_id"] == "u1"
    assert key_info["roles"] == ["analyst"]


def test_revoked_api_key_is_rejected(tmp_path):
    db_path = str(tmp_path / "keys.db")
    UserManager(db_path=db_path)

    manager = APIKeyManager(db_path=db_path)
    api_key, _ = manager.generate_api_key("u1", "svc", roles=["analyst"])
    assert manager.revoke_api_key(api_key) is True

    with pytest.raises(AuthenticationError):
        APIKeyManager(db_path=db_path).validate_api_key(api_key)


def test_unknown_api_key_is_rejected(tmp_path):
    db_path = str(tmp_path / "keys.db")
    UserManager(db_path=db_path)

    with pytest.raises(AuthenticationError):
        APIKeyManager(db_path=db_path).validate_api_key("hf_api_not_a_real_key")


# --------------------------------------------------------------------------- #
# Bootstrap admin creation under concurrency
# --------------------------------------------------------------------------- #
def test_ensure_default_admin_is_idempotent(user_manager, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "bootstrap-password-for-tests")

    first = user_manager.ensure_default_admin()
    second = user_manager.ensure_default_admin()

    assert first is not None
    assert second is None, "a second call must not create a duplicate admin"
    assert user_manager.count_users() == 1


def test_ensure_default_admin_survives_losing_the_startup_race(user_manager, monkeypatch):
    """Two gunicorn workers boot together against an empty database.

    count_users() and the INSERT are not atomic, so both workers can pass the
    'no users yet' check and both try to create 'admin'. The loser used to get
    UNIQUE constraint failed, which killed the worker during module import and
    took down part of the API on every cold start.

    Forcing count_users() to keep reporting 0 after the row exists reproduces
    that window exactly.
    """
    monkeypatch.setenv("ADMIN_PASSWORD", "bootstrap-password-for-tests")
    user_manager.ensure_default_admin()

    monkeypatch.setattr(type(user_manager), "count_users", lambda self: 0)

    assert user_manager.ensure_default_admin() is None
    # Must not raise, and must not leave a second admin behind.
    assert user_manager.get_by_username("admin") is not None
    admins = [u for u in user_manager.list_users() if u["username"] == "admin"]
    assert len(admins) == 1


def test_ensure_default_admin_still_raises_on_a_real_failure(user_manager, monkeypatch):
    """A genuine creation failure must not be swallowed by the race handling."""
    monkeypatch.setenv("ADMIN_PASSWORD", "bootstrap-password-for-tests")
    monkeypatch.setattr(
        type(user_manager), "create_user",
        lambda self, **kwargs: (_ for _ in ()).throw(UserError("disk is full")),
    )

    with pytest.raises(UserError):
        user_manager.ensure_default_admin()
