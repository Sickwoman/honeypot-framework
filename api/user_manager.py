#!/usr/bin/env python3

################################################################################
# Honeypot Framework - User Manager
# DB-backed user accounts for RBAC: the missing link between database/schema.sql
# (the `users` table) and the JWT/auth layer (api/auth.py).
#
# Uses the same raw-sqlite3 + sqlite3.Row pattern as api/alerts_service.py's
# AlertService, and the same schema bootstrap.
################################################################################

import logging
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import bcrypt

from api.config import get_config
from api.rbac import Role, is_valid_role

logger = logging.getLogger(__name__)

# Brute-force protection: after MAX_FAILED_LOGIN_ATTEMPTS consecutive failures
# an account stops accepting logins for LOCKOUT_MINUTES. The counter is stored
# in users.failed_login_attempts and cleared by a successful login.
MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", 5))
LOCKOUT_MINUTES = int(os.getenv("ACCOUNT_LOCKOUT_MINUTES", 15))


class UserError(Exception):
    """Raised for user-management failures (duplicate username, bad role, etc.)."""
    pass


class UserManager:
    """CRUD + authentication for RBAC user accounts (the `users` table)."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_config().get("ALERTS_DB_PATH")
        self._ensure_database()

    # ------------------------------------------------------------------ #
    # Infrastructure
    # ------------------------------------------------------------------ #
    def _ensure_database(self):
        """Create the DB (and the users table via schema.sql) if missing."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        schema_path = "database/schema.sql"
        if os.path.exists(schema_path):
            with sqlite3.connect(self.db_path) as conn:
                with open(schema_path, "r") as f:
                    conn.executescript(f.read())
                conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------ #
    # Password hashing (bcrypt)
    # ------------------------------------------------------------------ #
    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def _check_password(password: str, password_hash: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------------ #
    # CRUD
    # ------------------------------------------------------------------ #
    def create_user(self, username: str, password: str, role: str,
                    email: str = None, full_name: str = None,
                    created_by: str = None) -> str:
        """Create a user. Returns the new user id. Raises UserError on a bad
        role or a duplicate username/email."""
        if not username or not password:
            raise UserError("username and password are required")
        if not is_valid_role(role):
            raise UserError(f"invalid role '{role}' (expected one of {Role.ALL})")

        user_id = str(uuid.uuid4())
        password_hash = self.hash_password(password)
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO users (
                        id, username, email, password_hash, full_name, role,
                        enabled, created_at, updated_at, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                    """,
                    (user_id, username, email, password_hash, full_name, role,
                     datetime.utcnow(), datetime.utcnow(), created_by),
                )
                conn.commit()
        except sqlite3.IntegrityError as e:
            raise UserError(f"user already exists: {e}") from e

        return user_id

    def get_by_username(self, username: str) -> Optional[Dict]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            return dict(row) if row else None

    def list_users(self) -> List[Dict]:
        """Return all users WITHOUT password hashes."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, username, email, full_name, role, enabled,
                       last_login, failed_login_attempts, created_at
                FROM users ORDER BY created_at
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def count_users(self) -> int:
        with self._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #
    @staticmethod
    def is_locked_out(user: Dict) -> bool:
        """True while an account is inside its lockout window after too many
        consecutive failed logins."""
        if (user.get("failed_login_attempts") or 0) < MAX_FAILED_LOGIN_ATTEMPTS:
            return False

        last_attempt = user.get("updated_at")
        if not last_attempt:
            return True
        if isinstance(last_attempt, str):
            try:
                last_attempt = datetime.fromisoformat(last_attempt)
            except ValueError:
                return True

        return datetime.utcnow() - last_attempt < timedelta(minutes=LOCKOUT_MINUTES)

    def verify_credentials(self, username: str, password: str) -> Optional[Dict]:
        """Validate username+password. On success returns the user dict (minus
        the hash) and records the login; on failure returns None and records a
        failed attempt. Disabled and locked-out accounts always fail."""
        user = self.get_by_username(username)
        if not user or not user.get("enabled"):
            return None

        if self.is_locked_out(user):
            logger.warning("Rejected login for locked-out account: %s", username)
            return None

        if not self._check_password(password, user["password_hash"]):
            self.record_failed_login(user["id"])
            return None

        self.record_login(user["id"])
        user.pop("password_hash", None)
        user.pop("mfa_secret", None)
        return user

    def record_login(self, user_id: str):
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE users
                SET last_login = ?, failed_login_attempts = 0, updated_at = ?
                WHERE id = ?
                """,
                (datetime.utcnow(), datetime.utcnow(), user_id),
            )
            conn.commit()

    def record_failed_login(self, user_id: str):
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE users
                SET failed_login_attempts = failed_login_attempts + 1, updated_at = ?
                WHERE id = ?
                """,
                (datetime.utcnow(), user_id),
            )
            conn.commit()

    # ------------------------------------------------------------------ #
    # Bootstrap
    # ------------------------------------------------------------------ #
    def ensure_default_admin(self) -> Optional[str]:
        """Create a bootstrap admin the first time the app starts (empty users
        table). Username/password come from ADMIN_USERNAME / ADMIN_PASSWORD; if
        no password is set, a strong random one is generated and logged ONCE so
        the operator can reset it. Returns the new admin id, or None if users
        already exist."""
        if self.count_users() > 0:
            return None

        username = os.getenv("ADMIN_USERNAME", "admin")
        password = os.getenv("ADMIN_PASSWORD")
        generated = False
        if not password:
            password = secrets.token_urlsafe(18)
            generated = True

        user_id = self.create_user(
            username=username, password=password, role=Role.ADMIN,
            full_name="Bootstrap Administrator", created_by="system",
        )

        if generated:
            logger.warning(
                "No ADMIN_PASSWORD set -- generated a bootstrap admin. "
                "username=%s password=%s  (CHANGE THIS IMMEDIATELY)",
                username, password,
            )
        else:
            logger.info("Bootstrap admin created: username=%s", username)

        return user_id
