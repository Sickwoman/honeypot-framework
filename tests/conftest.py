"""Pytest configuration: make the repo root importable as `api.*`."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# api/auth.py refuses to import without a JWT signing secret (it errors
# rather than falling back to a hardcoded default). Tests don't need a real
# .env file, so provide one here before any test module imports api.auth.
os.environ.setdefault("JWT_SECRET_KEY", "pytest-only-test-secret-not-for-production")

# Importing api.alerts_service has side effects: it builds an AlertService and
# bootstraps an admin user, both of which create directories under the
# configured paths. Those default to root-owned system locations
# (/var/lib/honeypot, /var/log/honeypot), so without these overrides the whole
# suite fails to even import as an unprivileged user -- and would otherwise
# write to real system paths on a developer machine.
_TEST_STATE_DIR = os.path.join(tempfile.gettempdir(), "honeypot-framework-tests")
os.makedirs(_TEST_STATE_DIR, exist_ok=True)
os.environ.setdefault("ALERTS_DB_PATH", os.path.join(_TEST_STATE_DIR, "alerts.db"))
os.environ.setdefault("LOG_DIR", os.path.join(_TEST_STATE_DIR, "logs"))
