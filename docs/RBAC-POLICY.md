# RBAC Policy

Role-Based Access Control for the Honeypot Framework REST API (`api/`).

Users authenticate against the `users` table and receive a JWT that carries
their role. Every protected endpoint declares the **permission** it needs; a
request is allowed only if the caller's role grants that permission.

## Roles

| Role | Intent |
|------|--------|
| `observer`  | View-only access to alerts, statistics, and incidents. |
| `analyst`   | Observer + create alerts/incidents and mint service API keys. |
| `responder` | Analyst + modify/acknowledge/resolve/delete alerts, update/close incidents. |
| `admin`     | Full access, including user administration. |

Roles are **hierarchical**: `observer ⊂ analyst ⊂ responder ⊂ admin`. Each role
inherits every permission of the one below it. The single source of truth is
[`api/rbac.py`](../api/rbac.py) (`ROLE_PERMISSIONS`).

## Permissions

| Permission | observer | analyst | responder | admin |
|------------|:--:|:--:|:--:|:--:|
| `alerts:read`        | ✅ | ✅ | ✅ | ✅ |
| `stats:read`         | ✅ | ✅ | ✅ | ✅ |
| `incidents:read`     | ✅ | ✅ | ✅ | ✅ |
| `playbooks:read`     | ✅ | ✅ | ✅ | ✅ |
| `alerts:create`      |    | ✅ | ✅ | ✅ |
| `incidents:create`   |    | ✅ | ✅ | ✅ |
| `apikey:create`      |    | ✅ | ✅ | ✅ |
| `playbooks:write`    |    | ✅ | ✅ | ✅ |
| `alerts:update`      |    |    | ✅ | ✅ |
| `alerts:acknowledge` |    |    | ✅ | ✅ |
| `alerts:resolve`     |    |    | ✅ | ✅ |
| `alerts:delete`      |    |    | ✅ | ✅ |
| `incidents:update`   |    |    | ✅ | ✅ |
| `incidents:close`    |    |    | ✅ | ✅ |
| `playbooks:execute`  |    |    | ✅ | ✅ |
| `users:read`         |    |    |    | ✅ |
| `users:manage`       |    |    |    | ✅ |

## Endpoint → permission map

| Method & path | Permission |
|---------------|------------|
| `GET  /api/v1/alerts`                     | `alerts:read` |
| `GET  /api/v1/alerts/<id>`                | `alerts:read` |
| `GET  /api/v1/alerts/statistics`          | `stats:read` |
| `GET  /api/v1/alerts/top-ips`             | `stats:read` |
| `POST /api/v1/alerts`                     | `alerts:create` |
| `PUT  /api/v1/alerts/<id>`                | `alerts:update` |
| `POST /api/v1/alerts/<id>/acknowledge`    | `alerts:acknowledge` |
| `POST /api/v1/alerts/<id>/resolve`        | `alerts:resolve` |
| `DELETE /api/v1/alerts/<id>`              | `alerts:delete` |
| `GET  /api/v1/correlations`               | `stats:read` |
| `GET  /api/v1/playbooks`                  | `playbooks:read` |
| `GET  /api/v1/playbooks/<id>`             | `playbooks:read` |
| `GET  /api/v1/playbooks/<id>/history`     | `playbooks:read` |
| `POST /api/v1/playbooks`                  | `playbooks:write` |
| `PUT  /api/v1/playbooks/<id>`             | `playbooks:write` |
| `DELETE /api/v1/playbooks/<id>`           | `playbooks:write` |
| `POST /api/v1/playbooks/<id>/execute`     | `playbooks:execute` |
| `POST /auth/api-key`                      | `apikey:create` |
| `POST /api/v1/users`                      | `users:manage` |
| `GET  /api/v1/users`                      | `users:read` |
| `POST /auth/login`, `/auth/refresh`, `GET /auth/whoami` | authenticated (login: public) |

Guards are applied with the `@require_permission(...)` decorator from
[`api/decorators.py`](../api/decorators.py). Authentication accepts either a
bearer JWT (`Authorization: Bearer <token>`) or an `X-API-Key` header; both
resolve the caller's roles via `api/auth.py::resolve_request_identity`.

Responses: `401` when authentication fails, `403` when authenticated but
missing a required permission (the body lists the `required` and `missing`
permissions).

## Bootstrapping the first admin

On first startup, when the `users` table is empty, the app creates a bootstrap
admin (`UserManager.ensure_default_admin`):

- `ADMIN_USERNAME` (default `admin`) and `ADMIN_PASSWORD` from the environment.
- If `ADMIN_PASSWORD` is unset, a strong random password is generated and
  **logged once** at WARNING level — copy it from the logs and change it.

```bash
# .env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<a strong password>
```

## Logging in and calling the API

```bash
# 1. Log in -> JWT
TOKEN=$(curl -s -X POST https://localhost:8443/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq -r .token)

# 2. Call a protected endpoint
curl -s https://localhost:8443/api/v1/alerts \
  -H "Authorization: Bearer $TOKEN"

# 3. Inspect your own effective permissions
curl -s https://localhost:8443/auth/whoami \
  -H "Authorization: Bearer $TOKEN"
```

## Managing users (admin only)

```bash
curl -s -X POST https://localhost:8443/api/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"jane","password":"...","role":"analyst","email":"jane@example.com"}'
```

Valid `role` values are `admin`, `responder`, `analyst`, `observer`. Passwords
are stored as bcrypt hashes; all user and alert mutations are recorded through
the audit logger (`api/middleware.py::AuditLogger`) / the `audit_log` table.

## Adding a new permission

1. Add the constant to `Permission` in `api/rbac.py`.
2. Grant it to the appropriate tier(s) in the `_*_PERMS` sets.
3. Guard the endpoint with `@require_permission(Permission.YOUR_PERM)`.
4. Update this table and `tests/test_rbac.py`.
