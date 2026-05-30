import sqlite3
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config.settings import DATABASE_PATH

def init_db():
    print(f"Initializing database at {DATABASE_PATH}...")
    
    # Ensure database directory exists
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # 1. USERS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        username     TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role         TEXT NOT NULL CHECK(role IN ('submitter','reviewer','lawyer','admin')),
        email        TEXT,
        is_active    BOOLEAN DEFAULT 1,
        failed_logins INTEGER DEFAULT 0,
        locked_until  DATETIME,
        created_at   DATETIME DEFAULT (datetime('now','utc'))
    );
    """)

    # 2. INCIDENTS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id  TEXT PRIMARY KEY,
        category     TEXT NOT NULL,
        severity     TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
        source_url   TEXT,
        target       TEXT,
        description  TEXT,
        status       TEXT DEFAULT 'pending' CHECK(status IN ('pending','under_review','approved','closed','escalated')),
        priority     INTEGER DEFAULT 3,
        tags         TEXT,
        created_by   INTEGER REFERENCES users(id),
        reviewed_by  INTEGER REFERENCES users(id),
        created_at   DATETIME DEFAULT (datetime('now','utc')),
        updated_at   DATETIME
    );
    """)

    # 3. EVIDENCE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        evidence_id  TEXT PRIMARY KEY,
        incident_id  TEXT REFERENCES incidents(incident_id),
        filename     TEXT NOT NULL,
        original_name TEXT,
        file_type    TEXT,
        file_extension TEXT,
        file_size    INTEGER,
        file_hash    TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        metadata     TEXT,
        uploaded_by  INTEGER REFERENCES users(id),
        uploaded_at  DATETIME DEFAULT (datetime('now','utc'))
    );
    """)

    # 4. OCR_RESULTS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ocr_results (
        ocr_id          TEXT PRIMARY KEY,
        incident_id     TEXT REFERENCES incidents(incident_id),
        evidence_id     TEXT REFERENCES evidence(evidence_id),
        extracted_text  TEXT,
        confidence_score REAL,
        detected_urls   TEXT,
        detected_usernames TEXT,
        detected_threats   TEXT,
        created_at      DATETIME DEFAULT (datetime('now','utc'))
    );
    """)

    # 5. AI_ANALYSIS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ai_analysis (
        analysis_id        TEXT PRIMARY KEY,
        incident_id        TEXT REFERENCES incidents(incident_id),
        suggested_category TEXT,
        suggested_severity TEXT,
        threat_score       REAL,
        ai_confidence      REAL,
        analysis_method    TEXT,
        analysis_status    TEXT DEFAULT 'completed',
        analysis_details   TEXT,
        keyword_flags      TEXT,
        similar_incidents  TEXT,
        reviewed_by_human  BOOLEAN DEFAULT 0,
        approved_by        INTEGER REFERENCES users(id),
        reviewer_notes     TEXT,
        created_at         DATETIME DEFAULT (datetime('now','utc')),
        updated_at         DATETIME
    );
    """)

    # 6. VIDEO_METADATA
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS video_metadata (
        video_id      TEXT PRIMARY KEY,
        incident_id   TEXT REFERENCES incidents(incident_id),
        evidence_id   TEXT REFERENCES evidence(evidence_id),
        duration      REAL,
        codec         TEXT,
        resolution    TEXT,
        frame_rate    REAL,
        bitrate       INTEGER,
        thumbnail_path TEXT,
        frame_count   INTEGER,
        processed_at  DATETIME DEFAULT (datetime('now','utc'))
    );
    """)

    # 7. AUDIT_LOGS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        log_id        TEXT PRIMARY KEY,
        user_id       INTEGER REFERENCES users(id),
        username      TEXT,
        action        TEXT NOT NULL,
        target_type   TEXT,
        target_id     TEXT,
        ip_address    TEXT,
        user_agent    TEXT,
        metadata_json TEXT,
        timestamp     DATETIME DEFAULT (datetime('now','utc')),
        details       TEXT
    );
    """)

    # 8. NOTIFICATIONS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        notification_id TEXT PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(id),
        type            TEXT NOT NULL,
        title           TEXT NOT NULL,
        message         TEXT NOT NULL,
        target_type     TEXT,
        target_id       TEXT,
        channel         TEXT DEFAULT 'IN_APP',
        is_read         BOOLEAN DEFAULT 0,
        created_at      DATETIME DEFAULT (datetime('now','utc'))
    );
    """)

    # 9. COMMUNICATIONS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS communications (
        message_id  TEXT PRIMARY KEY,
        incident_id TEXT REFERENCES incidents(incident_id),
        user_id     INTEGER REFERENCES users(id),
        sender_name TEXT,
        message     TEXT NOT NULL,
        is_alert    BOOLEAN DEFAULT 0,
        timestamp   DATETIME DEFAULT (datetime('now','utc'))
    );
    """)

    # 10. SESSIONS (for secure session management)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT NOT NULL UNIQUE,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT (datetime('now','utc')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 11. LOGIN_ATTEMPTS (for brute-force protection)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        success BOOLEAN NOT NULL,
        ip_address TEXT,
        attempted_at DATETIME DEFAULT (datetime('now','utc'))
    );
    """)

    # Indexes for auth/session performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempted_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, is_read)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target_type, target_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, timestamp)")

    conn.commit()
    conn.close()
    print("Database initialization complete.")

if __name__ == "__main__":
    init_db()
