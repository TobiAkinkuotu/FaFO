import sqlite3

from config.settings import DATABASE_PATH


def get_db_connection(db_path=None):
    """Return a shared SQLite connection configured for the app."""
    db_path = str(db_path) if db_path is not None else str(DATABASE_PATH)
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn
