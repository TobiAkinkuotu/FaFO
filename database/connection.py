import sqlite3
from pathlib import Path

from app_config.settings import DATABASE_PATH
from database import init_db as db_init


def _ensure_database_initialized(db_path: str | Path):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if not db_path.exists():
        db_init.init_db()
        return

    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        )
        if cursor.fetchone() is None:
            db_init.init_db()
    finally:
        conn.close()


def get_db_connection(db_path=None):
    """Return a shared SQLite connection configured for the app."""
    db_path = str(db_path) if db_path is not None else str(DATABASE_PATH)
    _ensure_database_initialized(db_path)
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn
