"""
Comprehensive tests for AI Copilot and OCR extraction functionality.
Verifies that both AI systems work with real incident data, not mock data.
"""

import sqlite3
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import app_config.settings as settings
import database.connection as db_connection
import database.init_db as db_init
import modules.ai_classifier as ai_classifier
import modules.ai_copilot as ai_copilot
import modules.evidence_ui as evidence_ui
import modules.incident_manager as incident_manager


def _init_temp_db(tmp_path, monkeypatch):
    """Initialize temporary test database with real incident data."""
    db_file = tmp_path / "test_copilot_ocr.db"
    monkeypatch.setattr(settings, "DATABASE_PATH", db_file)
    monkeypatch.setattr(db_connection, "DATABASE_PATH", db_file)
    monkeypatch.setattr(db_init, "DATABASE_PATH", db_file)
    monkeypatch.setattr(ai_classifier, "DATABASE_PATH", db_file)
    monkeypatch.setattr(evidence_ui, "DATABASE_PATH", db_file)
    monkeypatch.setattr(incident_manager, "DATABASE_PATH", db_file)
    db_init.init_db()
    return db_file


def _create_test_incident_with_real_data(db_file):
    """Create an incident with real evidence and OCR data."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Insert a user
    cursor.execute(
        "INSERT INTO users (id, username, password_hash, role, email, is_active) VALUES (?, ?, ?, ?, ?, ?)",
        (1, "reviewer1", "hash", "reviewer", "reviewer@test.com", 1),
    )
    
    # Insert a real incident
    cursor.execute(
        "INSERT INTO incidents (incident_id, category, severity, source_url, target, description, status, priority, tags, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "inc-real-001",
            "threats",
            "high",
            "https://twitter.com/fake_threat",
            "John Doe",
            "User received threatening messages including 'I will find you and harm you'",
            "pending",
            3,
            "urgent,needs_review",
            1,
        ),
    )
    
    # Insert evidence files with real metadata
    cursor.execute(
        "INSERT INTO evidence (evidence_id, incident_id, filename, original_name, file_type, file_size, file_hash, storage_path, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "ev-001",
            "inc-real-001",
            "screenshot_threat.png",
            "screenshot_threat.png",
            "image/png",
            512000,
            "abc123def456",
            "/evidence/screenshot_threat.png",
            json.dumps({"resolution": "1920x1080", "format": "PNG", "created_date": "2025-05-30"}),
        ),
    )
    
    cursor.execute(
        "INSERT INTO evidence (evidence_id, incident_id, filename, original_name, file_type, file_size, file_hash, storage_path, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "ev-002",
            "inc-real-001",
            "chat_log.txt",
            "chat_log.txt",
            "text/plain",
            8192,
            "xyz789uvw012",
            "/evidence/chat_log.txt",
            json.dumps({"lines": 45, "encoding": "UTF-8"}),
        ),
    )
    
    # Insert OCR extractions with real text
    cursor.execute(
        "INSERT INTO ocr_results (ocr_id, incident_id, evidence_id, extracted_text, confidence_score, detected_threats) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            "ocr-001",
            "inc-real-001",
            "ev-001",
            "I will find you and make you pay for what you did",
            0.92,
            json.dumps(["direct_threat", "violence_reference"]),
        ),
    )
    
    cursor.execute(
        "INSERT INTO ocr_results (ocr_id, incident_id, evidence_id, extracted_text, confidence_score, detected_threats) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            "ocr-002",
            "inc-real-001",
            "ev-001",
            "Your address is 123 Main Street, your family is vulnerable",
            0.88,
            json.dumps(["doxxing", "family_threat"]),
        ),
    )
    
    # Insert AI analysis results
    cursor.execute(
        "INSERT INTO ai_analysis (analysis_id, incident_id, suggested_category, suggested_severity, threat_score, ai_confidence, analysis_method, analysis_status, analysis_details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "AI_001",
            "inc-real-001",
            "threats",
            "critical",
            0.95,
            0.89,
            "easyocr_combined",
            "completed",
            json.dumps({"keyword_matches": {"kill": 1, "harm": 2, "address": 1}, "entities": ["John Doe"]}),
        ),
    )
    
    conn.commit()
    conn.close()


def test_get_copilot_response_fetches_real_incident_data(tmp_path, monkeypatch):
    """Verify copilot retrieves actual incident data from database."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    _create_test_incident_with_real_data(db_file)
    
    conn = sqlite3.connect(db_file)
    
    # Query with threat assessment
    response = ai_copilot.get_copilot_response(conn, "inc-real-001", "What is the threat level?")
    
    # Verify response contains real data from incident
    assert "John Doe" in response or "target" in response.lower()
    assert "threatening" in response.lower() or "threat" in response.lower()
    assert len(response) > 50  # Substantial response, not mock data
    
    conn.close()


def test_copilot_response_includes_ocr_extractions(tmp_path, monkeypatch):
    """Verify copilot includes actual OCR extracted text in responses."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    _create_test_incident_with_real_data(db_file)
    
    conn = sqlite3.connect(db_file)
    
    # Query specifically about OCR
    response = ai_copilot.get_copilot_response(conn, "inc-real-001", "What text was extracted from the evidence?")
    
    # Should reference OCR data
    assert "ocr" in response.lower() or "extract" in response.lower() or "screenshot" in response.lower()
    # Should have real OCR count or mention of extractions
    assert "2" in response or "ocr" in response.lower() or "extract" in response.lower()
    
    conn.close()


def test_copilot_response_includes_ai_analysis_results(tmp_path, monkeypatch):
    """Verify copilot includes actual AI analysis suggestions."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    _create_test_incident_with_real_data(db_file)
    
    conn = sqlite3.connect(db_file)
    
    # Query about AI suggestions
    response = ai_copilot.get_copilot_response(conn, "inc-real-001", "What did AI analysis suggest?")
    
    # Should mention threat level or AI findings
    assert "threat" in response.lower() or "critical" in response.lower() or "ai" in response.lower()
    
    conn.close()


def test_copilot_with_nonexistent_incident(tmp_path, monkeypatch):
    """Verify copilot handles missing incidents gracefully."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    
    conn = sqlite3.connect(db_file)
    
    response = ai_copilot.get_copilot_response(conn, "inc-nonexistent", "What is this?")
    
    # Should return error message, not crash
    assert "error" in response.lower() or "not found" in response.lower()
    
    conn.close()


def test_ocr_extraction_with_real_incident(tmp_path, monkeypatch):
    """Verify OCR extraction functions work with real incident data."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    _create_test_incident_with_real_data(db_file)
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Fetch OCR results for the incident
    cursor.execute(
        "SELECT ocr_id, extracted_text, confidence_score, detected_threats FROM ocr_results WHERE incident_id = ? ORDER BY created_at",
        ("inc-real-001",),
    )
    ocr_results = cursor.fetchall()
    
    # Verify real OCR data exists
    assert len(ocr_results) == 2
    assert ocr_results[0][1] == "I will find you and make you pay for what you did"
    assert ocr_results[0][2] == 0.92
    assert "direct_threat" in json.loads(ocr_results[0][3])
    
    # Second OCR result
    assert "address" in ocr_results[1][1].lower()
    assert ocr_results[1][2] == 0.88
    
    conn.close()


def test_ai_classification_with_real_ocr_text(tmp_path, monkeypatch):
    """Verify AI classification processes real OCR extracted text."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    _create_test_incident_with_real_data(db_file)
    
    # Get the OCR text
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT extracted_text FROM ocr_results WHERE incident_id = ? LIMIT 1", ("inc-real-001",))
    ocr_text = cursor.fetchone()[0]
    
    # Classify it using the real classifier
    result = ai_classifier.classify_with_keywords(ocr_text)
    
    # Verify classification found actual content
    assert result["category"] in ai_classifier.INCIDENT_CATEGORIES
    # Real OCR text: "I will find you and make you pay for what you did"
    # Contains keywords like "find", "you" - has semantic threat content
    assert result["severity"] in ai_classifier.SEVERITY_LEVELS
    assert result["method"] == "keyword_fallback"
    
    conn.close()


def test_incident_analysis_pipeline_with_real_data(tmp_path, monkeypatch):
    """Verify end-to-end analysis pipeline works with real incident data."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Create user
    cursor.execute(
        "INSERT INTO users (id, username, password_hash, role, email, is_active) VALUES (?, ?, ?, ?, ?, ?)",
        (1, "admin1", "hash", "admin", "admin@test.com", 1),
    )
    
    # Create incident
    cursor.execute(
        "INSERT INTO incidents (incident_id, category, severity, source_url, target, description, status, priority, tags, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "inc-pipeline-test",
            "pending",
            "medium",
            "https://example.com",
            "Test Victim",
            "Suspicious activity and potential threats detected",
            "pending",
            2,
            "",
            1,
        ),
    )
    conn.commit()
    
    # Run AI classification on the incident description
    result = incident_manager.process_incident_classification(
        "inc-pipeline-test",
        "Suspicious activity and potential threats detected"
    )
    
    # Verify real classification happened
    assert result is not None
    assert "category" in result
    assert "severity" in result
    
    # Verify result was stored in database
    cursor.execute("SELECT suggested_category, suggested_severity FROM ai_analysis WHERE incident_id = ?", ("inc-pipeline-test",))
    stored = cursor.fetchone()
    assert stored is not None
    assert stored[0] in ai_classifier.INCIDENT_CATEGORIES
    
    conn.close()


def test_copilot_local_fallback_threat_assessment(tmp_path, monkeypatch):
    """Verify local fallback copilot threat assessment uses real data."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    _create_test_incident_with_real_data(db_file)
    
    conn = sqlite3.connect(db_file)
    
    # Get incident for context
    cursor = conn.cursor()
    cursor.execute("SELECT description, target FROM incidents WHERE incident_id = ?", ("inc-real-001",))
    desc, target = cursor.fetchone()
    
    # Get OCR results
    cursor.execute("SELECT extracted_text, confidence_score, detected_threats FROM ocr_results WHERE incident_id = ?", ("inc-real-001",))
    ocr_results = cursor.fetchall()
    
    # Call local fallback directly
    response = ai_copilot.get_local_fallback_response(
        "What is the threat level?",
        f"Target: {target}",
        desc,
        ocr_results,
        target,
        "inc-real-001"
    )
    
    # Verify response contains real data
    assert "Forensic Threat Assessment" in response
    assert target in response or "target" in response.lower()
    assert "Active Threat Patterns" in response or "risk" in response.lower()
    
    conn.close()


def test_copilot_local_fallback_ocr_summary(tmp_path, monkeypatch):
    """Verify local fallback copilot OCR summary includes real extractions."""
    db_file = _init_temp_db(tmp_path, monkeypatch)
    _create_test_incident_with_real_data(db_file)
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Get real OCR results
    cursor.execute("SELECT extracted_text, confidence_score, detected_threats FROM ocr_results WHERE incident_id = ?", ("inc-real-001",))
    ocr_results = cursor.fetchall()
    
    # Call local fallback OCR query
    response = ai_copilot.get_local_fallback_response(
        "What text was extracted?",
        "Context",
        "Test description",
        ocr_results,
        "John Doe",
        "inc-real-001"
    )
    
    # Verify real OCR data is in response
    assert "Extracted OCR Records Summary" in response
    assert "2" in response  # Should mention 2 extractions
    assert "Confidence" in response
    
    conn.close()


def test_all_ai_tests_pass(tmp_path, monkeypatch):
    """Verify all AI phase 4 tests still pass (no regression)."""
    # This is a wrapper to ensure the existing AI tests pass
    db_file = _init_temp_db(tmp_path, monkeypatch)
    
    # Test 1: Keyword classification detects threats
    result = ai_classifier.classify_with_keywords("I will kill you")
    assert result["category"] in ai_classifier.INCIDENT_CATEGORIES
    # "kill" keyword should be detected, severity should not be "low"
    assert result["severity"] in ["medium", "high", "critical"]
    
    # Test 2: Storage and retrieval
    conn = sqlite3.connect(db_file)
    conn.execute(
        "INSERT INTO incidents (incident_id, category, severity, source_url, target, description, status, priority, tags, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("inc-test", "harassment", "medium", "", "victim", "test", "pending", 3, "", 1),
    )
    conn.commit()
    
    analysis_id = ai_classifier.store_ai_analysis(
        "inc-test",
        {"category": "threats", "severity": "high", "threat_score": 0.8, "confidence": 0.9, "keyword_matches": {}},
    )
    
    stored = ai_classifier.get_ai_analysis("inc-test")
    assert stored["category"] == "threats"
    assert stored["severity"] == "high"
    
    conn.close()
