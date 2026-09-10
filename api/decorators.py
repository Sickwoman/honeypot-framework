#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Authorization Decorators
# Fine-grained, permission-based endpoint guards built on top of the RBAC
# matrix (api/rbac.py) and the shared request authenticator (api/auth.py).
################################################################################

from functools import wraps

from flask import g, jsonify

from api.auth import (
    AuthenticationError,
    # Re-exported so callers can import all guards from one place.
    login_required,
    resolve_request_identity,
)
from api.rbac import has_permission

__all__ = [
    "require_permission",
    "login_required",
]


def require_permission(*permissions):
    """
    Flask decorator that authenticates the request and then authorizes it
    against one or more fine-grained permissions (see ``api.rbac.Permission``).

    The caller must hold EVERY permission listed (logical AND). Authentication
    reuses :func:`api.auth.resolve_request_identity`, so both API-key and JWT
    credentials work and ``g.user_id`` / ``g.username`` / ``g.roles`` are
    populated for the wrapped view.

    Example::

        @app.route("/api/v1/alerts")
        @require_permission(Permission.ALERTS_READ)
        def list_alerts():
            ...

    Responses:
        401 if authentication fails; 403 if authenticated but missing a
        required permission.
    """
    if not permissions:
        raise ValueError("require_permission needs at least one permission")

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                resolve_request_identity()
            except AuthenticationError as e:
                return jsonify({"error": str(e)}), 401
            except Exception:
                return jsonify({"error": "Authentication failed"}), 401

            roles = getattr(g, "roles", []) or []
            missing = [p for p in permissions if not has_permission(roles, p)]
            if missing:
                return jsonify({
                    "error": "Insufficient permissions",
                    "required": list(permissions),
                    "missing": missing,
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator
