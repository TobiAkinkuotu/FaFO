import sqlite3

import pytest

import app_config.settings as settings
import database.connection as db_connection
import database.init_db as db_init
import modules.auth as auth
import modules.dashboard as dashboard
import modules.incident_manager as incident_manager
import modules.notifications as notifications


def _init_temp_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_fafo.db"
    monkeypatch.setattr(db_init, "DATABASE_PATH", db_file)
    monkeypatch.setattr(dashboard, "DATABASE_PATH", db_file)
    monkeypatch.setattr(incident_manager, "DATABASE_PATH", db_file)
    monkeypatch.setattr(auth, "DATABASE_PATH", db_file)
    db_init.init_db()
    return db_file


def test_build_incident_payload_normalizes_schema_values():
    payload = incident_manager.build_incident_payload(
        raw_severity="High",
        category="Cyberbullying",
        source_url="https://example.test",
        description="Needs review",
        created_by=7,
    )

    assert payload["severity"] == "high"
    assert payload["status"] == "pending"
    assert payload["priority"] == 3
    assert payload["created_by"] == 7
    assert payload["incident_id"]
    assert payload["created_at"].endswith("Z") or "+" in payload["created_at"]


def test_build_incident_payload_defaults_to_session_user(monkeypatch):
    monkeypatch.setattr(incident_manager.st, "session_state", {"user_id": 42})

    payload = incident_manager.build_incident_payload(
        raw_severity="Medium",
        category="Harassment",
        description="Default user test",
        created_by=None,
    )

    assert payload["created_by"] == 42
    assert payload["priority"] == 2
    assert payload["severity"] == "medium"


def test_fetch_recent_incidents_uses_existing_columns(tmp_path, monkeypatch):
    db_file = _init_temp_db(tmp_path, monkeypatch)

    conn = sqlite3.connect(db_file)
    conn.execute(
        "INSERT INTO incidents (incident_id, category, severity, source_url, target, description, status, priority, tags, created_by, reviewed_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "inc-001",
            "Cyberbullying",
            "high",
            "https://example.test",
            "student",
            "Test incident",
            "pending",
            3,
            "",
            7,
            None,
            "2026-05-29T10:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    rows = dashboard.fetch_recent_incidents(limit=10)

    assert len(rows) == 1
    assert rows[0]["incident_id"] == "inc-001"
    assert rows[0]["status"] == "pending"
    assert rows[0]["severity"] == "high"


def test_fetch_recent_incidents_returns_empty_list_for_empty_db(tmp_path, monkeypatch):
    _init_temp_db(tmp_path, monkeypatch)

    rows = dashboard.fetch_recent_incidents(limit=10)

    assert rows == []


def test_notify_ai_analysis_ready_creates_owner_notification(tmp_path, monkeypatch):
    db_file = tmp_path / "test_notifications.db"
    monkeypatch.setattr(settings, "DATABASE_PATH", db_file)
    monkeypatch.setattr(db_connection, "DATABASE_PATH", db_file)
    monkeypatch.setattr(db_init, "DATABASE_PATH", db_file)
    db_init.init_db()

    conn = sqlite3.connect(db_file)
    conn.execute(
        "INSERT INTO users (id, username, password_hash, role, email, is_active) VALUES (?, ?, ?, ?, ?, ?)",
        (7, "owner", "hash", "submitter", "owner@example.test", 1),
    )
    conn.execute(
        "INSERT INTO incidents (incident_id, category, severity, source_url, target, description, status, priority, tags, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("inc-900", "harassment", "medium", "", "victim", "test", "pending", 3, "", "owner"),
    )
    conn.commit()
    conn.close()

    captured = []
    monkeypatch.setattr(notifications, "create_notification", lambda *args, **kwargs: captured.append((args, kwargs)) or "NTF_TEST")

    notifications.notify_ai_analysis_ready("inc-900", "harassment", "high")

    assert captured
    assert captured[0][0][0] == 7
    assert captured[0][0][1].value == "AI_ANALYSIS_READY"
    assert "AI classified incident inc-900" in captured[0][0][3]


def test_authentication_locks_out_user_after_too_many_failed_attempts(tmp_path, monkeypatch):
    _init_temp_db(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "MAX_LOGIN_ATTEMPTS", 2)
    monkeypatch.setattr(auth, "LOCKOUT_MINUTES", 1)

    conn = sqlite3.connect(tmp_path / "test_fafo.db")
    conn.execute(
        "INSERT INTO users (username, password_hash, role, email, is_active) VALUES (?, ?, ?, ?, ?)",
        ("alice", auth.get_password_hash("correct-password"), "submitter", "alice@example.test", 1),
    )
    conn.commit()
    conn.close()

    first = auth.authenticate_user("alice", "wrong-password")
    second = auth.authenticate_user("alice", "wrong-password")

    assert first[0] is None
    assert "1 attempt" in first[1]
    assert second[0] is None
    assert "locked for 1 minute" in second[1]

    conn = sqlite3.connect(tmp_path / "test_fafo.db")
    row = conn.execute("SELECT failed_logins, locked_until FROM users WHERE username = ?", ("alice",)).fetchone()
    conn.close()

    assert row[0] == 2
    assert row[1] is not None


def test_authentication_returns_user_role(tmp_path, monkeypatch):
    _init_temp_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(tmp_path / "test_fafo.db")
    conn.execute(
        "INSERT INTO users (username, password_hash, role, email, is_active) VALUES (?, ?, ?, ?, ?)",
        ("lawyer_user", auth.get_password_hash("secret"), "lawyer", "lawyer@example.test", 1),
    )
    conn.commit()
    conn.close()

    user_dict, err_msg = auth.authenticate_user("lawyer_user", "secret")
    assert err_msg is None
    assert user_dict is not None
    assert user_dict["role"] == "lawyer"
    assert user_dict["username"] == "lawyer_user"


def test_create_user_rejects_invalid_role(tmp_path, monkeypatch):
    _init_temp_db(tmp_path, monkeypatch)
    success, message = auth.create_user("newuser", "pass123", "invalid_role", "newuser@example.test")
    assert success is False
    assert "Invalid role" in message
