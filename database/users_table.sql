-- Honeypot Framework - Users & Roles Schema (RBAC)
-- Standalone, idempotent definition of the `users` table used by RBAC.
--
-- This mirrors the `users` table in database/schema.sql exactly (CREATE TABLE
-- IF NOT EXISTS), so running either file -- or both, in any order -- is safe.
-- It exists as a focused reference for the RBAC feature; the running app loads
-- database/schema.sql at startup (api/user_manager.py::_ensure_database).
--
-- Roles (see api/rbac.py and docs/RBAC-POLICY.md):
--   admin     - full access, incl. user administration
--   responder - modify alerts, acknowledge, resolve, close incidents
--   analyst   - view alerts, create incidents, run queries
--   observer  - view-only access to dashboards
--
-- No seed rows are committed here: the bootstrap admin is created at runtime by
-- UserManager.ensure_default_admin() from ADMIN_USERNAME / ADMIN_PASSWORD, so
-- no password hash ever lives in source control.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,

    -- Profile
    full_name TEXT,
    role TEXT NOT NULL,                         -- Role: admin, analyst, responder, observer

    -- Status
    enabled BOOLEAN DEFAULT 1,
    last_login DATETIME,
    failed_login_attempts INTEGER DEFAULT 0,

    -- Audit
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,

    -- MFA
    mfa_enabled BOOLEAN DEFAULT 0,
    mfa_secret TEXT                             -- Encrypted MFA secret
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
