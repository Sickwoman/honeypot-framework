#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Role-Based Access Control (RBAC)
# Canonical roles, fine-grained permissions, and the role -> permission matrix.
#
# Pure logic -- deliberately free of any Flask/DB import so it can be unit
# tested in isolation and reused anywhere (decorators, auth routes, CLI tools).
################################################################################

from typing import Iterable, Set


class Role:
    """Canonical role names. Match database/schema.sql users.role and the
    vocabulary in api/auth.py / config/kibana-security.yml."""

    ADMIN = "admin"
    ANALYST = "analyst"
    RESPONDER = "responder"
    OBSERVER = "observer"

    ALL = (ADMIN, RESPONDER, ANALYST, OBSERVER)


class Permission:
    """Fine-grained permissions guarding individual API actions.

    Naming convention: "<resource>:<action>"."""

    # Alerts
    ALERTS_READ = "alerts:read"
    ALERTS_CREATE = "alerts:create"
    ALERTS_UPDATE = "alerts:update"
    ALERTS_ACKNOWLEDGE = "alerts:acknowledge"
    ALERTS_RESOLVE = "alerts:resolve"
    ALERTS_DELETE = "alerts:delete"

    # Statistics / dashboards
    STATS_READ = "stats:read"

    # Incidents
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_CREATE = "incidents:create"
    INCIDENTS_UPDATE = "incidents:update"
    INCIDENTS_CLOSE = "incidents:close"

    # Service accounts
    APIKEY_CREATE = "apikey:create"

    # User administration
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"


# ---------------------------------------------------------------------------
# Role -> permission matrix.
#
# Built HIERARCHICALLY: OBSERVER < ANALYST < RESPONDER < ADMIN. Each higher
# role inherits every permission of the one below it, so the tiers below only
# list the permissions each role ADDS. This mirrors the roadmap
# (IMPROVEMENTS-AND-FEATURES.md:200-204):
#   OBSERVER  - view-only access to dashboards
#   ANALYST   - view alerts, create incidents, run queries
#   RESPONDER - modify alerts, acknowledge, close incidents
#   ADMIN     - full access, incl. user administration
# ---------------------------------------------------------------------------
_OBSERVER_PERMS: Set[str] = {
    Permission.ALERTS_READ,
    Permission.STATS_READ,
    Permission.INCIDENTS_READ,
}

_ANALYST_PERMS: Set[str] = _OBSERVER_PERMS | {
    Permission.ALERTS_CREATE,
    Permission.INCIDENTS_CREATE,
    Permission.APIKEY_CREATE,
}

_RESPONDER_PERMS: Set[str] = _ANALYST_PERMS | {
    Permission.ALERTS_UPDATE,
    Permission.ALERTS_ACKNOWLEDGE,
    Permission.ALERTS_RESOLVE,
    Permission.ALERTS_DELETE,
    Permission.INCIDENTS_UPDATE,
    Permission.INCIDENTS_CLOSE,
}

_ADMIN_PERMS: Set[str] = _RESPONDER_PERMS | {
    Permission.USERS_READ,
    Permission.USERS_MANAGE,
}

ROLE_PERMISSIONS = {
    Role.OBSERVER: frozenset(_OBSERVER_PERMS),
    Role.ANALYST: frozenset(_ANALYST_PERMS),
    Role.RESPONDER: frozenset(_RESPONDER_PERMS),
    Role.ADMIN: frozenset(_ADMIN_PERMS),
}


def is_valid_role(role: str) -> bool:
    """Return True if `role` is one of the canonical roles."""
    return role in ROLE_PERMISSIONS


def permissions_for(roles: Iterable[str]) -> Set[str]:
    """Union of all permissions granted by the given roles.

    Unknown roles contribute nothing (they are ignored rather than raising),
    so a token carrying a stale/typo'd role simply has no permissions.
    """
    granted: Set[str] = set()
    for role in roles or []:
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return granted


def has_permission(roles: Iterable[str], permission: str) -> bool:
    """Return True if any of `roles` grants `permission`."""
    return permission in permissions_for(roles)


def has_all_permissions(roles: Iterable[str], permissions: Iterable[str]) -> bool:
    """Return True if `roles` together grant every one of `permissions`."""
    granted = permissions_for(roles)
    return all(p in granted for p in permissions)
