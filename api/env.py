#!/usr/bin/env python3

################################################################################
# Honeypot Framework - .env bootstrap
#
# Importing this module loads the repo-root .env into os.environ, once.
#
# This has to happen before any module reads os.getenv at import time --
# api/auth.py refuses to import without JWT_SECRET_KEY, and api/config.py's
# ConfigManager is constructed too late to help it. Under Docker Compose the
# env vars are injected directly so nothing here matters, but when running
# locally (pytest, flask run, a script) the documented "set it in .env" flow
# only works because of this module.
################################################################################

import os
import sqlite3
from pathlib import Path

from dotenv import load_dotenv

# Repo root: this file is <root>/api/env.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent

_loaded = False


def load_env(override: bool = False) -> Path | None:
    """
    Load the repo-root .env into os.environ.

    Idempotent -- repeated imports and calls are cheap no-ops. Real environment
    variables win by default (override=False), so Docker/CI/shell settings are
    never clobbered by a stale checked-out .env.

    Returns the path that was loaded, or None if there is no .env.
    """
    global _loaded
    if _loaded and not override:
        return None

    env_file = Path(os.getenv("HONEYPOT_ENV_FILE") or PROJECT_ROOT / ".env")
    _loaded = True

    if not env_file.is_file():
        return None

    load_dotenv(env_file, override=override)
    return env_file


SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"


def apply_schema(db_path: str) -> None:
    """
    Apply database/schema.sql to `db_path`. Safe to call repeatedly -- every
    statement in the schema is CREATE ... IF NOT EXISTS.

    Resolved from the repo root, not the current working directory. This used
    to be the relative string "database/schema.sql", so starting the API from
    anywhere but the repo root silently created an empty database and then
    failed later with "no such table: users".
    """
    if not SCHEMA_PATH.is_file():
        raise RuntimeError(f"Database schema not found at {SCHEMA_PATH}")

    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.commit()


# Load on import -- that is the entire point of the module.
load_env()
