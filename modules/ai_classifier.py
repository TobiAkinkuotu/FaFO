import json
import os
import logging
import requests
from datetime import datetime, timezone
from typing import Dict, Optional

from app_config.settings import DATABASE_PATH
from database.connection import get_db_connection
from modules.audit_logger import log_action
from modules.notifications import notify_ai_analysis_ready

logger = logging.getLogger(__name__)

try:
    import spacy
except Exception:
    spacy = None

SentenceTransformer = None

def _load_sentence_transformer():
    global SentenceTransformer
    try:
        from sentence_transformers import SentenceTransformer as ST
        SentenceTransformer = ST
    except Exception:
        SentenceTransformer = None

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
except Exception:
    TfidfVectorizer = None
    LogisticRegression = None

# Note: In a production environment, models would be pre-trained and loaded from disk.
# This implementation provides the architectural shell described in the plan.

try:
    if spacy:
        nlp = spacy.load("en_core_web_sm")
    else:
        nlp = None
except OSError:
    # Fallback if model not downloaded
    nlp = None

INCIDENT_CATEGORIES = [
    "cyberbullying", "harassment", "defamation", "threats", "hate_speech",
    "doxxing", "impersonation", "stalking", "reputation_attacks", "fraud",
    "scam_activity", "privacy_violation", "coordinated_harassment"
]

SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

THREAT_KEYWORDS = {
    "threats": ["kill", "hurt", "harm", "attack", "destroy", "die", "death", "murder"],
    "doxxing": ["address", "phone number", "personal info", "leak", "expose", "dox"],
    "hate_speech": ["hate", "racist", "slur", "discriminate", "bigot", "nazi"],
    "harassment": ["harass", "bully", "torment", "stalk", "obsess", "follow"],
    "defamation": ["lie", "false", "rumor", "slander", "defame", "smear"],
    "fraud": ["scam", "fraud", "fake", "money", "payment", "steal", "cheat"],
}


class IncidentAnalyzer:
    def __init__(self):
        # Initialize semantic embedder lazily and safely
        _load_sentence_transformer()
        try:
            if SentenceTransformer:
                self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
            else:
                self.embedder = None
        except Exception:
            self.embedder = None

        self.categories = [
            "Cyberbullying", "Harassment", "Defamation", "Threats", 
            "Hate Speech", "Doxxing", "Fraud", "Privacy Violation"
        ]
        
    def analyze_incident(self, description: str, ocr_text: str) -> dict:
        combined_text = f"{description}\n{ocr_text}"
        
        # 1. Named Entity Recognition
        entities = []
        if nlp:
            doc = nlp(combined_text)
            entities = [{"text": ent.text, "label": ent.label_} for ent in doc.ents]
            
        # 2. Threat Scoring (Heuristic for MVP)
        threat_score = self._calculate_threat_score(combined_text)
        
        # 3. Categorization (Heuristic/Keyword-based for MVP shell)
        suggested_category = self._suggest_category(combined_text)
        
        # 4. Severity Prediction
        severity = "high" if threat_score > 0.7 else "medium" if threat_score > 0.3 else "low"
        
        return {
            "suggested_category": suggested_category,
            "suggested_severity": severity,
            "threat_score": threat_score,
            "ai_confidence": 85.0,  # Mock confidence
            "entities": entities
        }

    def _calculate_threat_score(self, text: str) -> float:
        text = text.lower()
        high_risk = ["kill", "die", "bomb", "shoot", "address", "dox"]
        score = sum(0.2 for word in high_risk if word in text)
        return min(1.0, score)
        
    def _suggest_category(self, text: str) -> str:
        text = text.lower()
        if any(w in text for w in ["kill", "die", "shoot"]):
            return "Threats"
        elif any(w in text for w in ["address", "phone", "dox"]):
            return "Doxxing"
        return "Harassment"

def classify_with_keywords(text: str) -> Dict:
    """Fallback keyword-based classification when AI is unavailable."""
    text_lower = text.lower()
    scores = {cat: 0 for cat in INCIDENT_CATEGORIES}

    for category, keywords in THREAT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text_lower:
                scores[category] += 1

    max_score = max(scores.values())
    if max_score == 0:
        primary_category = "harassment"
        confidence = 0.3
    else:
        primary_category = max(scores, key=scores.get)
        confidence = min(0.7, 0.3 + (max_score * 0.1))

    threat_score = sum(scores.values())
    if threat_score >= 5:
        severity = "critical"
    elif threat_score >= 3:
        severity = "high"
    elif threat_score >= 1:
        severity = "medium"
    else:
        severity = "low"

    reasoning = "Keyword-based fallback classification."
    if keyword_matches := {k: v for k, v in scores.items() if v > 0}:
        reasoning += f" Detected keyword groups: {keyword_matches}."
    else:
        reasoning += " No meaningful keywords were found, defaulting to harassment heuristics."

    return {
        "category": primary_category,
        "severity": severity,
        "threat_score": min(1.0, threat_score / 10),
        "confidence": confidence,
        "method": "keyword_fallback",
        "keyword_matches": keyword_matches,
        "reasoning": reasoning,
    }


def classify_with_transformer(text: str) -> Optional[Dict]:
    """Use Hugging Face transformers if available."""
    try:
        from transformers import pipeline

        if not hasattr(classify_with_transformer, "classifier"):
            classify_with_transformer.classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli", device=-1)

        result = classify_with_transformer.classifier(text[:1024], candidate_labels=INCIDENT_CATEGORIES, multi_label=False)
        primary_category = result["labels"][0]
        confidence = result["scores"][0]

        severity_map = {
            "threats": "critical",
            "doxxing": "high",
            "hate_speech": "high",
            "coordinated_harassment": "high",
            "harassment": "medium",
            "cyberbullying": "medium",
            "defamation": "medium",
            "impersonation": "medium",
            "stalking": "medium",
            "reputation_attacks": "low",
            "fraud": "medium",
            "scam_activity": "medium",
            "privacy_violation": "medium",
        }
        severity = severity_map.get(primary_category, "medium")

        return {
            "category": primary_category,
            "severity": severity,
            "threat_score": confidence,
            "confidence": confidence,
            "method": "transformer",
            "all_scores": dict(zip(result["labels"], result["scores"])),
            "reasoning": "Zero-shot transformer classification updated from semantic model output.",
        }
    except Exception as exc:
        logger.info("Transformers unavailable or failed: %s", exc)
        return None


def classify_with_gemini(text: str) -> Optional[Dict]:
    """Use Gemini if API key is available."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None

    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        prompt = (
            "Analyze this incident description and classify it.\n\n"
            f"Description: {text[:2000]}\n\n"
            "Respond with ONLY JSON: {\"category\": \"...\", \"severity\": \"...\", \"threat_score\": 0.0, \"confidence\": 0.0, \"reasoning\": \"...\"}"
        )
        payload = {
            "content": [
                {"type": "text", "text": prompt}
            ],
            "temperature": 0.1,
            "candidate_count": 1,
            "max_output_tokens": 400,
        }
        res = requests.post(url, headers=headers, json=payload, timeout=20)
        if res.status_code != 200:
            logger.error("Gemini classification failed: %s %s", res.status_code, res.text)
            return None
        data = res.json()
        text_response = None
        if isinstance(data.get("candidates"), list) and data["candidates"]:
            text_response = data["candidates"][0].get("content", {}).get("text")
        if not text_response:
            return None
        result = json.loads(text_response)
        return {
            "category": result.get("category", "harassment"),
            "severity": result.get("severity", "medium"),
            "threat_score": float(result.get("threat_score", 0.0)),
            "confidence": float(result.get("confidence", 0.0)),
            "reasoning": result.get("reasoning", ""),
            "method": "gemini",
        }
    except Exception as exc:
        logger.error("Gemini classification error: %s", exc)
        return None


def classify_with_openai(text: str) -> Optional[Dict]:
    """Use OpenAI if API key is available."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    try:
        import openai

        client = openai.OpenAI(api_key=api_key)
        prompt = f"""Analyze this incident description and classify it.\n\nDescription: {text[:2000]}\n\nRespond with ONLY JSON: {{\"category\": \"...\", \"severity\": \"...\", \"threat_score\": 0.0, \"confidence\": 0.0}}"""
        response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": prompt}], temperature=0.1, max_tokens=300)
        content = response.choices[0].message.content
        result = json.loads(content)
        return {
            "category": result.get("category", "harassment"),
            "severity": result.get("severity", "medium"),
            "threat_score": float(result.get("threat_score", 0.0)),
            "confidence": float(result.get("confidence", 0.0)),
            "reasoning": result.get("reasoning", "No reasoning provided by OpenAI."),
            "method": "openai",
        }
    except Exception as exc:
        logger.error("OpenAI classification error: %s", exc)
        return None


def classify_incident(incident_id: str, text: str, use_ai: bool = True) -> Dict:
    """Best available classification, with keyword fallback."""
    result = None

    if use_ai and os.getenv("GEMINI_API_KEY"):
        result = classify_with_gemini(text)
    if result is None and use_ai and os.getenv("OPENAI_API_KEY"):
        result = classify_with_openai(text)
    if result is None and use_ai:
        result = classify_with_transformer(text)
    if result is None:
        result = classify_with_keywords(text)

    if result["category"] not in INCIDENT_CATEGORIES:
        result["category"] = "harassment"
    if result["severity"] not in SEVERITY_LEVELS:
        result["severity"] = "medium"

    if "reasoning" not in result:
        result["reasoning"] = "No reasoning provided."

    store_ai_analysis(incident_id, result, status="completed")
    try:
        notify_ai_analysis_ready(incident_id, result.get("category", "harassment"), result.get("severity", "medium"))
    except Exception:
        logger.warning("Notification hook skipped for AI classification.")
    log_action(1, "system", "AI_CLASSIFICATION", "incident", incident_id, details=f"Category: {result['category']}, Severity: {result['severity']}, Method: {result['method']}")
    return result


def ensure_ai_analysis_schema():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ai_analysis'")
    if cursor.fetchone() is None:
        cursor.execute(
            "CREATE TABLE ai_analysis ("
            "analysis_id TEXT PRIMARY KEY,"
            "incident_id TEXT REFERENCES incidents(incident_id),"
            "suggested_category TEXT,"
            "suggested_severity TEXT,"
            "threat_score REAL,"
            "ai_confidence REAL,"
            "analysis_method TEXT,"
            "analysis_status TEXT DEFAULT 'completed',"
            "analysis_details TEXT,"
            "keyword_flags TEXT,"
            "similar_incidents TEXT,"
            "reviewed_by_human BOOLEAN DEFAULT 0,"
            "approved_by INTEGER REFERENCES users(id),"
            "reviewer_notes TEXT,"
            "created_at DATETIME DEFAULT (datetime('now','utc')),"
            "updated_at DATETIME"
            ")"
        )

    cursor.execute("PRAGMA table_info(ai_analysis)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    extra_columns = {
        "analysis_method": "TEXT",
        "analysis_status": "TEXT DEFAULT 'completed'",
        "analysis_details": "TEXT",
        "keyword_flags": "TEXT",
        "similar_incidents": "TEXT",
        "reviewed_by_human": "BOOLEAN DEFAULT 0",
        "approved_by": "INTEGER REFERENCES users(id)",
        "reviewer_notes": "TEXT",
        "created_at": "DATETIME DEFAULT (datetime('now','utc'))",
        "updated_at": "DATETIME",
    }

    for column_name, column_def in extra_columns.items():
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE ai_analysis ADD COLUMN {column_name} {column_def}")

    conn.commit()
    conn.close()


def store_ai_analysis(incident_id: str, analysis: Dict, status: str = "completed") -> str:
    """Store AI analysis result in database."""
    ensure_ai_analysis_schema()
    conn = get_db_connection()
    cursor = conn.cursor()

    analysis_id = f"AI_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
    cursor.execute("""
        INSERT INTO ai_analysis (
            analysis_id, incident_id, suggested_category, suggested_severity,
            threat_score, ai_confidence, analysis_method, analysis_status,
            analysis_details, keyword_flags, similar_incidents,
            reviewed_by_human, approved_by, reviewer_notes,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        analysis_id,
        incident_id,
        analysis.get("category", "harassment"),
        analysis.get("severity", "medium"),
        float(analysis.get("threat_score", 0.0)),
        float(analysis.get("confidence", 0.0)),
        analysis.get("method", "heuristic"),
        status,
        analysis.get("reasoning", ""),
        json.dumps(analysis.get("keyword_matches", {})),
        json.dumps(analysis.get("similar_incidents", [])),
        False,
        None,
        "",
        datetime.now(timezone.utc).isoformat(),
        datetime.now(timezone.utc).isoformat(),
    ))
    conn.commit()
    conn.close()
    return analysis_id


def get_ai_analysis(incident_id: str) -> Optional[Dict]:
    """Get latest AI analysis for incident."""
    ensure_ai_analysis_schema()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT analysis_id, suggested_category, suggested_severity,
               threat_score, ai_confidence, analysis_method, analysis_status,
               analysis_details, reviewed_by_human, reviewer_notes,
               created_at
        FROM ai_analysis
        WHERE incident_id = ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (incident_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "analysis_id": row[0],
        "category": row[1],
        "severity": row[2],
        "threat_score": row[3],
        "confidence": row[4],
        "method": row[5],
        "status": row[6],
        "details": row[7],
        "reviewed": bool(row[8]),
        "reviewer_notes": row[9],
        "created_at": row[10],
    }


def approve_ai_analysis(analysis_id: str, reviewer_id: int, notes: str = "") -> bool:
    """Mark AI analysis as reviewed by human."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE ai_analysis
            SET reviewed_by_human = 1,
                approved_by = ?,
                reviewer_notes = ?,
                updated_at = ?
            WHERE analysis_id = ?
        """, (reviewer_id, notes, datetime.now(timezone.utc).isoformat(), analysis_id))
        conn.commit()
        return True
    except Exception as exc:
        logger.error("Failed to approve AI analysis: %s", exc)
        return False
    finally:
        conn.close()


def run_ai_analysis_for_incident(incident_id: str):
    """
    Fetch description and OCR texts, run AI classification, and store the result.
    """
    import sqlite3
    from app_config.settings import DATABASE_PATH
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT description FROM incidents WHERE incident_id = ?", (incident_id,))
    res = cursor.fetchone()
    if not res:
        conn.close()
        return
    description = res[0] or ""
    
    cursor.execute("SELECT extracted_text FROM ocr_results WHERE incident_id = ?", (incident_id,))
    ocr_texts = [row[0] for row in cursor.fetchall() if row[0]]
    combined_text = description + "\n\n" + "\n".join(ocr_texts)

    pending_analysis = classify_with_keywords(combined_text)
    pending_analysis["reasoning"] = (
        "Queued for deeper AI review. This is a preliminary keyword-derived summary while the full analysis completes. "
        f"Keyword matches: {json.dumps(pending_analysis.get('keyword_matches', {}))}"
    )
    store_ai_analysis(incident_id, pending_analysis, status="pending")

    try:
        return classify_incident(incident_id, combined_text, use_ai=True)
    except Exception as exc:
        logger.warning("AI analysis refresh failed: %s", exc)
        return pending_analysis
