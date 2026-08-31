#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Authentication & User Routes
# A Flask Blueprint providing DB-backed login (replacing the placeholder in
# api/auth.py's __main__ block), token refresh, whoami, service API keys, and
# admin-only user management. Registered on the app in api/alerts_service.py.
################################################################################

from datetime import datetime

from flask import Blueprint, request, jsonify, g

from api.auth import (
    jwt_manager,
    api_key_manager,
    login_required,
    TOKEN_EXPIRATION_HOURS,
)
from api.decorators import require_permission
from api.rbac import Permission
from api.user_manager import UserManager, UserError
from api.middleware import AuditLogger

auth_bp = Blueprint("auth", __name__)

user_manager = UserManager()
audit_logger = AuditLogger()


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    """Validate credentials against the users table and issue a JWT."""
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    user = user_manager.verify_credentials(username, password)
    if not user:
        audit_logger.log_operation(
            operation="login_failed", resource_type="user", resource_id=username,
            action="login", user_id=username, status="failure",
        )
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt_manager.generate_token(
        user_id=user["id"], username=user["username"], roles=[user["role"]],
    )
    audit_logger.log_operation(
        operation="login", resource_type="user", resource_id=user["id"],
        action="login", user_id=user["id"], status="success",
        details={"role": user["role"]},
    )
    return jsonify({
        "token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_EXPIRATION_HOURS * 3600,
        "user": {"username": user["username"], "role": user["role"]},
    })


@auth_bp.route("/auth/refresh", methods=["POST"])
@login_required
def refresh():
    """Refresh the caller's JWT."""
    auth_header = request.headers.get("Authorization", "")
    try:
        token = auth_header.split(" ")[1]
    except IndexError:
        return jsonify({"error": "Invalid authorization header"}), 401

    new_token = jwt_manager.refresh_token(token)
    return jsonify({
        "token": new_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_EXPIRATION_HOURS * 3600,
    })


@auth_bp.route("/auth/whoami", methods=["GET"])
@login_required
def whoami():
    """Return the authenticated caller's identity, roles, and effective perms."""
    from api.rbac import permissions_for
    return jsonify({
        "user_id": g.user_id,
        "username": g.username,
        "roles": g.roles,
        "permissions": sorted(permissions_for(g.roles)),
        "auth_method": g.auth_method,
    })


@auth_bp.route("/auth/api-key", methods=["POST"])
@require_permission(Permission.APIKEY_CREATE)
def create_api_key():
    """Issue a service API key that inherits the caller's roles."""
    api_key, key_info = api_key_manager.generate_api_key(
        user_id=g.user_id, username=g.username, roles=g.roles,
    )
    audit_logger.log_operation(
        operation="api_key_created", resource_type="api_key", resource_id=g.user_id,
        action="create", user_id=g.user_id, status="success",
    )
    return jsonify({
        "api_key": api_key,
        "expires_at": key_info["expires_at"].isoformat(),
    }), 201


################################################################################
# User administration (admin only)
################################################################################

@auth_bp.route("/api/v1/users", methods=["POST"])
@require_permission(Permission.USERS_MANAGE)
def create_user():
    """Create a new user account."""
    data = request.get_json(silent=True) or {}
    try:
        user_id = user_manager.create_user(
            username=data.get("username"),
            password=data.get("password"),
            role=data.get("role"),
            email=data.get("email"),
            full_name=data.get("full_name"),
            created_by=g.user_id,
        )
    except UserError as e:
        return jsonify({"error": str(e)}), 400

    audit_logger.log_operation(
        operation="user_created", resource_type="user", resource_id=user_id,
        action="create", user_id=g.user_id, status="success",
        details={"username": data.get("username"), "role": data.get("role")},
    )
    return jsonify({"id": user_id, "created_at": datetime.utcnow().isoformat()}), 201


@auth_bp.route("/api/v1/users", methods=["GET"])
@require_permission(Permission.USERS_READ)
def list_users():
    """List all users (without password hashes)."""
    return jsonify({"users": user_manager.list_users()})
