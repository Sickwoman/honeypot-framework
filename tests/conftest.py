"""Pytest configuration: make the repo root importable as `api.*`."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# api/auth.py refuses to import without a JWT signing secret (it errors
# rather than falling back to a hardcoded default). Tests don't need a real
# .env file, so provide one here before any test module imports api.auth.
os.environ.setdefault("JWT_SECRET_KEY", "pytest-only-test-secret-not-for-production")
