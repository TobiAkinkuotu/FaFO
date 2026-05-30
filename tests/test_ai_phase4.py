import sqlite3

import config.settings as settings
import database.connection as db_connection
import database.init_db as db_init
import modules.ai_classifier as ai_classifier
import modules.evidence_ui as evidence_ui
import modules.incident_manager as incident_manager


def _init_temp_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_ai_phase4.db"
    monkeypatch.setattr(settings, "DATABASE_PATH", db_file)
    monkeypatch.setattr(db_connection, "DATABASE_PATH", db_file)
    monkeypatch.setattr(db_init, "DATABASE_PATH", db_file)
    monkeypatch.setattr(ai_classifier, "DATABASE_PATH", db_file)
    monkeypatch.setattr(evidence_ui, "DATABASE_PATH", db_file)
    monkeypatch.setattr(incident_manager, "DATABASE_PATH", db_file)
    db_init.init_db()
    return db_file


def test_classify_with_keywords_returns_safe_fallback(tmp_path, monkeypatch):
    _init_temp_db(tmp_path, monkeypatch)

    result = ai_classifier.classify_with_keywords("I will kill you and leak your address")

    assert result["category"] in ai_classifier.INCIDENT_CATEGORIES
    assert result["severity"] in ai_classifier.SEVERITY_LEVELS
    assert result["method"] == "keyword_fallback"
    assert result["threat_score"] >= 0


def test_store_and_get_ai_analysis_persists_results(tmp_path, monkeypatch):
    db_file = _init_temp_db(tmp_path, monkeypatch)

    conn = sqlite3.connect(db_file)
    conn.execute(
        "INSERT INTO incidents (incident_id, category, severity, source_url, target, description, status, priority, tags, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("inc-101", "harassment", "medium", "", "victim", "test", "pending", 3, "", 1),
    )
    conn.commit()
    conn.close()

    analysis_id = ai_classifier.store_ai_analysis(
        "inc-101",
        {"category": "threats", "severity": "high", "threat_score": 0.6, "confidence": 0.8, "keyword_matches": {"kill": 1}},
    )

    stored = ai_classifier.get_ai_analysis("inc-101")

    assert analysis_id.startswith("AI_")
    assert stored["category"] == "threats"
    assert stored["severity"] == "high"
    assert stored["confidence"] == 0.8


def test_ensure_ai_analysis_schema_creates_missing_table(tmp_path, monkeypatch):
    db_file = _init_temp_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_file)
    conn.execute("DROP TABLE IF EXISTS ai_analysis")
    conn.commit()
    conn.close()

    ai_classifier.ensure_ai_analysis_schema()

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(ai_analysis)")
    columns = [row[1] for row in cursor.fetchall()]
    conn.close()

    assert "analysis_method" in columns
    assert "analysis_status" in columns
    assert "analysis_details" in columns


def test_ensure_evidence_schema_adds_metadata_column(tmp_path, monkeypatch):
    db_file = _init_temp_db(tmp_path, monkeypatch)

    conn = sqlite3.connect(db_file)
    conn.execute("DROP TABLE IF EXISTS evidence")
    conn.commit()
    conn.close()

    evidence_ui.ensure_evidence_schema()

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(evidence)")
    columns = [row[1] for row in cursor.fetchall()]
    conn.close()

    assert "metadata" in columns


def test_ensure_ocr_results_schema_creates_missing_table(tmp_path, monkeypatch):
    db_file = _init_temp_db(tmp_path, monkeypatch)

    conn = sqlite3.connect(db_file)
    conn.execute("DROP TABLE IF EXISTS ocr_results")
    conn.commit()
    conn.close()

    evidence_ui.ensure_ocr_results_schema()

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(ocr_results)")
    columns = [row[1] for row in cursor.fetchall()]
    conn.close()

    assert "extracted_text" in columns
    assert "confidence_score" in columns


def test_run_ai_analysis_for_incident_creates_pending_and_completed_rows(tmp_path, monkeypatch):
    db_file = _init_temp_db(tmp_path, monkeypatch)

    conn = sqlite3.connect(db_file)
    conn.execute(
        "INSERT INTO incidents (incident_id, category, severity, source_url, target, description, status, priority, tags, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("inc-303", "harassment", "medium", "", "victim", "I will dox you and threaten harm.", "pending", 3, "", 1),
    )
    conn.commit()
    conn.close()

    def fake_classify_incident(incident_id, text, use_ai=True):
        result = ai_classifier.classify_with_keywords(text)
        ai_classifier.store_ai_analysis(incident_id, result, status="completed")
        return result

    monkeypatch.setattr(ai_classifier, "classify_incident", fake_classify_incident)

    ai_classifier.run_ai_analysis_for_incident("inc-303")

    conn = sqlite3.connect(db_file)
    rows = conn.execute("SELECT analysis_status, suggested_category FROM ai_analysis WHERE incident_id = ? ORDER BY created_at ASC", ("inc-303",)).fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0][0] == "pending"
    assert rows[1][0] == "completed"
    assert rows[1][1] in ai_classifier.INCIDENT_CATEGORIES


def test_process_incident_classification_updates_incident_and_persists_analysis(tmp_path, monkeypatch):
    db_file = _init_temp_db(tmp_path, monkeypatch)

    conn = sqlite3.connect(db_file)
    conn.execute(
        "INSERT INTO users (id, username, password_hash, role, email, is_active) VALUES (?, ?, ?, ?, ?, ?)",
        (1, "system", "hash", "admin", "system@example.test", 1),
    )
    conn.execute(
        "INSERT INTO incidents (incident_id, category, severity, source_url, target, description, status, priority, tags, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("inc-202", "pending", "low", "", "target", "example", "pending", 3, "", 1),
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(
        incident_manager,
        "classify_incident",
        lambda incident_id, text, use_ai=True: ai_classifier.classify_incident(incident_id, text, use_ai=False),
    )

    result = incident_manager.process_incident_classification("inc-202", "This includes personal address")

    assert result["category"] == "doxxing"
    assert result["severity"] in ai_classifier.SEVERITY_LEVELS

    conn = sqlite3.connect(db_file)
    updated = conn.execute("SELECT category, severity FROM incidents WHERE incident_id = ?", ("inc-202",)).fetchone()
    analysis = conn.execute("SELECT suggested_category, suggested_severity FROM ai_analysis WHERE incident_id = ?", ("inc-202",)).fetchone()
    conn.close()

    assert updated[0] == "doxxing"
    assert updated[1] == result["severity"]
    assert analysis == ("doxxing", result["severity"])
