#!/usr/bin/env python3

################################################################################
# Honeypot Framework - JWT Authentication Module
# Handles API authentication, token generation, and validation
################################################################################

import os
import jwt
import json
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from functools import wraps
from flask import request, jsonify, g

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY is not set. Refusing to start with no JWT signing "
        "secret -- set it in .env (see .env.example) or the environment."
    )
ALGORITHM = "HS256"
TOKEN_EXPIRATION_HOURS = int(os.getenv("TOKEN_EXPIRATION_HOURS", 24))
API_KEY_LENGTH = 32

# JWT issuer/audience claims. generate_token() sets these and validate_token()
# verifies them, so they must stay in sync (kept here as the single source).
TOKEN_ISSUER = "honeypot-framework"
TOKEN_AUDIENCE = "honeypot-api"

class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    pass


class JWTManager:
    """Manage JWT token generation and validation"""
    
    def __init__(self, secret_key: str = SECRET_KEY, algorithm: str = ALGORITHM):
        self.secret_key = secret_key
        self.algorithm = algorithm
    
    def generate_token(self, user_id: str, username: str, roles: list = None, 
                      expiration_hours: int = TOKEN_EXPIRATION_HOURS) -> str:
        """
        Generate JWT token
        
        Args:
            user_id: Unique user identifier
            username: Username
            roles: List of roles (e.g., ['analyst', 'responder'])
            expiration_hours: Token expiration in hours
            
        Returns:
            JWT token string
        """
        if roles is None:
            roles = []
        
        now = datetime.utcnow()
        expiration = now + timedelta(hours=expiration_hours)
        
        payload = {
            "sub": user_id,
            "username": username,
            "roles": roles,
            "iat": now,
            "exp": expiration,
            "iss": TOKEN_ISSUER,
            "aud": TOKEN_AUDIENCE
        }
        
        try:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            return token
        except Exception as e:
            raise AuthenticationError(f"Failed to generate token: {str(e)}")
    
    def validate_token(self, token: str) -> Dict:
        """
        Validate JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload
            
        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=TOKEN_AUDIENCE,
                issuer=TOKEN_ISSUER,
                options={"verify_signature": True},
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    def refresh_token(self, token: str, expiration_hours: int = TOKEN_EXPIRATION_HOURS) -> str:
        """
        Refresh an existing valid token
        
        Args:
            token: Current JWT token
            expiration_hours: New expiration in hours
            
        Returns:
            New JWT token
        """
        try:
            payload = self.validate_token(token)
            new_token = self.generate_token(
                user_id=payload["sub"],
                username=payload["username"],
                roles=payload.get("roles", []),
                expiration_hours=expiration_hours
            )
            return new_token
        except AuthenticationError:
            raise


class APIKeyManager:
    """Manage API keys for service-to-service authentication.

    Keys are stored hashed in the `api_keys` table (database/schema.sql) so
    they survive restarts and are visible to every API worker process.
    """

    def __init__(self, db_path: str = None):
        self._db_path = db_path

    def _get_connection(self) -> sqlite3.Connection:
        db_path = self._db_path
        if not db_path:
            # Resolved lazily so this class can be instantiated at import
            # time, before api.config.init_config() runs.
            from api.config import get_config
            db_path = get_config().get("ALERTS_DB_PATH")

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _hash(api_key: str) -> str:
        return hashlib.sha256(api_key.encode()).hexdigest()

    def generate_api_key(self, user_id: str, username: str, roles: list = None,
                        expires_in_days: int = 90) -> Tuple[str, Dict]:
        """
        Generate API key

        Args:
            user_id: User identifier
            username: Username
            roles: List of roles
            expires_in_days: Expiration in days

        Returns:
            Tuple of (api_key, key_info)
        """
        if roles is None:
            roles = []

        api_key = f"hf_api_{secrets.token_urlsafe(24)}"
        key_hash = self._hash(api_key)

        key_info = {
            "user_id": user_id,
            "username": username,
            "roles": roles,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=expires_in_days),
            "last_used": None,
            "revoked": False
        }

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO api_keys
                    (key_hash, user_id, username, roles, created_at, expires_at, revoked)
                VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (key_hash, user_id, username, json.dumps(roles),
                 key_info["created_at"].isoformat(), key_info["expires_at"].isoformat()),
            )
            conn.commit()

        return api_key, key_info

    def validate_api_key(self, api_key: str) -> Dict:
        """
        Validate API key

        Args:
            api_key: API key string

        Returns:
            Key information if valid

        Raises:
            AuthenticationError: If key is invalid
        """
        key_hash = self._hash(api_key)

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)
            ).fetchone()

            if row is None:
                raise AuthenticationError("Invalid API key")

            if row["revoked"]:
                raise AuthenticationError("API key has been revoked")

            expires_at = datetime.fromisoformat(row["expires_at"])
            if expires_at < datetime.utcnow():
                raise AuthenticationError("API key has expired")

            last_used = datetime.utcnow()
            conn.execute(
                "UPDATE api_keys SET last_used = ? WHERE key_hash = ?",
                (last_used.isoformat(), key_hash),
            )
            conn.commit()

        return {
            "user_id": row["user_id"],
            "username": row["username"],
            "roles": json.loads(row["roles"] or "[]"),
            "created_at": row["created_at"],
            "expires_at": expires_at,
            "last_used": last_used,
            "revoked": False,
        }

    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET revoked = 1 WHERE key_hash = ?",
                (self._hash(api_key),),
            )
            conn.commit()
            return cursor.rowcount > 0


# Initialize managers
jwt_manager = JWTManager()
api_key_manager = APIKeyManager()


def resolve_request_identity():
    """
    Authenticate the current Flask request and populate the request context.

    Resolves either an ``X-API-Key`` header or a bearer JWT in the
    ``Authorization`` header, and on success sets ``g.user_id``,
    ``g.username``, ``g.roles`` and ``g.auth_method``.

    Shared by :func:`require_auth` (role checks) and
    ``api.decorators.require_permission`` (permission checks) so both paths use
    identical authentication logic.

    Raises:
        AuthenticationError: If no/invalid credentials are supplied.
    """
    # Check for API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        key_info = api_key_manager.validate_api_key(api_key)
        g.user_id = key_info["user_id"]
        g.username = key_info["username"]
        g.roles = key_info["roles"]
        g.auth_method = "api_key"
        return

    # Check for JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise AuthenticationError("Missing authentication")

    try:
        token = auth_header.split(" ")[1]
    except IndexError:
        raise AuthenticationError("Invalid authorization header")

    payload = jwt_manager.validate_token(token)
    g.user_id = payload["sub"]
    g.username = payload["username"]
    g.roles = payload.get("roles", [])
    g.auth_method = "jwt"


def login_required(f):
    """Flask decorator requiring authentication only (no specific
    permission) -- for endpoints like /auth/whoami and /auth/refresh that
    any authenticated user may call. Endpoints that need authorization
    should use api.decorators.require_permission against the RBAC matrix
    in api/rbac.py instead of a role name, so there's a single place
    (ROLE_PERMISSIONS) that governs what each role can do."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            resolve_request_identity()
            return f(*args, **kwargs)
        except AuthenticationError as e:
            return jsonify({"error": str(e)}), 401
        except Exception:
            return jsonify({"error": "Authentication failed"}), 401

    return decorated_function


# Real login/refresh/api-key/user-management endpoints are registered from
# api/auth_routes.py (a Flask Blueprint) onto the app in api/alerts_service.py.
