"""
incident_manager.py — Submit Incident wizard.

3-step wizard: Incident Details → Evidence Upload → Review & Submit
"""

import datetime as dt
import sqlite3
import uuid

import streamlit as st

from app_config.settings import DATABASE_PATH
from database.connection import get_db_connection
from modules.rbac import abort_if_unauthorized
from modules.ai_classifier import classify_incident

# ──────────────────────────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────────────────────────

_CSS = """
<style>
:root {
  --bg-viewport: #0A1118;
  --bg-card: #112236;
  --bg-input: #070C12;
  --accent-blue: #1A73E8;
  --text-primary: #E8F0FE;
  --text-secondary: #9AA0A6;
  --border-color: rgba(255, 255, 255, 0.08);
  --radius-md: 12px;
  --radius-sm: 8px;
}

.stApp {
    background-color: var(--bg-viewport);
}

div[data-testid="stVerticalBlockBorderWrapper"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: var(--radius-md) !important;
    padding: 32px 40px !important;
    max-width: 600px;
    margin: 0 auto;
}

/* Stepper */
.progress-stepper {
    display: flex;
    justify-content: space-between;
    margin-bottom: 40px;
    font-size: 12px;
    font-weight: 600;
}
.step-active { color: var(--accent-blue); }
.step-inactive { color: var(--text-secondary); }

/* Form inputs */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stSelectbox > div > div > div {
    background-color: var(--bg-input) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: var(--radius-sm) !important;
    padding: 0 16px !important;
    font-size: 14px !important;
}

.stTextInput > div > div > input,
.stSelectbox > div > div > div {
    height: 44px !important;
    min-height: 44px !important;
}

.stTextArea > div > div > textarea {
    height: 120px !important;
    padding: 16px !important;
    resize: none !important;
}

/* Labels */
.stTextInput label,
.stTextArea label,
.stSelectbox label,
div[data-testid="stRadio"] > label {
    font-size: 13px !important;
    color: var(--text-secondary) !important;
    margin-bottom: 8px !important;
    display: block !important;
    font-weight: normal !important;
}

/* ── Severity pills ── */
div[data-testid="stRadio"] > div {
    display: flex;
    flex-direction: row;
    gap: 12px;
    flex-wrap: wrap;
}

/* Each pill label */
div[data-testid="stRadio"] > div > label {
    position: relative;
    display: flex !important;
    justify-content: center !important;
    align-items: center !important;
    min-height: 36px;
    padding: 8px 20px !important;
    flex: 0 1 auto !important;
    border-radius: 100px;
    border: 1px solid var(--border-color);
    background: transparent;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    cursor: pointer;
    margin: 0 !important;
    white-space: nowrap !important;
    overflow: hidden;
}

/* Checked state */
div[data-testid="stRadio"] > div > label[data-checked="true"] {
    background: rgba(30, 142, 62, 0.2) !important;
    border: 1px solid #1E8E3E !important;
    color: #1E8E3E !important;
}

/* ── Native radio input: invisible but clickable ── */
div[data-testid="stRadio"] > div > label input[type="radio"] {
    appearance: none !important;
    -webkit-appearance: none !important;
    position: absolute !important;
    inset: 0 !important;
    width: 100% !important;
    height: 100% !important;
    margin: 0 !important;
    padding: 0 !important;
    opacity: 0 !important;
    z-index: 2 !important;
    cursor: pointer !important;
    border: none !important;
    outline: none !important;
}

/* Focus ring for accessibility */
div[data-testid="stRadio"] > div > label:has(input:focus-visible) {
    outline: 2px solid var(--accent-blue);
    outline-offset: 2px;
}

/* ── Hide Streamlit's default radio circle SVG ── */
div[data-testid="stRadio"] > div > label > div:first-child svg,
div[data-testid="stRadio"] > div > label > div:first-child [data-testid="stIconCheck"] {
    display: none !important;
}

/* Form submit button — FIXED */
button[kind="primaryFormSubmit"] {
    background: var(--accent-blue) !important;
    color: white !important;
    height: 44px !important;
    padding: 0 24px !important;
    border-radius: var(--radius-sm) !important;
    font-weight: 600 !important;
    border: none !important;
    margin-top: 32px !important;
}
button[kind="primaryFormSubmit"]:hover {
    background: #1557b0 !important;
}

/* Regular buttons */
.stButton > button {
    background: var(--accent-blue) !important;
    color: white !important;
    border: none !important;
    border-radius: var(--radius-sm) !important;
    font-weight: 600 !important;
    height: 44px !important;
}
.stButton > button:hover {
    background: #1557b0 !important;
}
</style>
"""

# ──────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────

_INCIDENT_CATEGORIES = [
    "Cyberbullying", "Harassment", "Defamation", "Threats",
    "Hate Speech", "Doxxing", "Impersonation", "Stalking",
    "Reputation Attack", "Fraud / Scam", "Privacy Violation",
    "Coordinated Harassment", "Other",
]

_PRIORITIES = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def build_incident_payload(raw_severity="Low", category="Other", source_url="", target="", description="", created_by=None):
    """Build a normalized incident payload for DB writes and tests."""
    severity = (raw_severity or "Low").lower()
    priority = _PRIORITIES.get(raw_severity) or _PRIORITIES.get((raw_severity or "").title(), 3)

    return {
        "incident_id": str(uuid.uuid4()),
        "category": category,
        "severity": severity,
        "source_url": source_url,
        "target": target,
        "description": description,
        "status": "pending",
        "priority": priority,
        "tags": "",
        "created_by": created_by if created_by is not None else st.session_state.get("user_id", 1),
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

# ──────────────────────────────────────────────────────────────────
# Single-page incident form (refactored)
# ──────────────────────────────────────────────────────────────────

def _render_submission_form():
    with st.container(border=True):
        st.markdown(
            '<div class="progress-stepper">'
            '<span class="step-active">1. Incident Details</span>'
            '<span class="step-inactive">2. Evidence Upload</span>'
            '<span class="step-inactive">3. Review & Submit</span>'
            '</div>',
            unsafe_allow_html=True,
        )

        with st.form("incident_submission_form", clear_on_submit=False):
            st.text_input("Incident Title", placeholder="Brief descriptive title", key="f_title")

            col_a, col_b = st.columns(2)
            with col_a:
                st.text_input("Date (YYYY-MM-DD)", key="f_date", placeholder="YYYY-MM-DD")
            with col_b:
                st.text_input("Time", placeholder="HH:MM", key="f_time")

            st.text_input("Source URL", placeholder="https://...", key="f_source_url")
            st.text_input("Target", placeholder="Who was targeted?", key="f_target")
            st.text_input("Location", placeholder="Where did this occur?", key="f_location")
            st.selectbox("Incident Type", _INCIDENT_CATEGORIES, key="f_category")

            # REMOVED: st.markdown("**Severity**") — duplicate label

            st.radio(
                "Severity",
                options=["Low", "Medium", "High", "Critical"],
                index=0,
                horizontal=True,
                key="f_severity",
            )

            st.text_area(
                "Description",
                placeholder="Full description of the incident...",
                key="f_description",
            )

            col1, col2, col3 = st.columns([1, 1, 1])
            with col3:
                submitted = st.form_submit_button("Next Step >", type="primary", use_container_width=True)

            if submitted:
                _submit_incident()


def _submit_incident():
    errors = []
    if not st.session_state.get("f_title", "").strip():
        errors.append("Incident Title is required.")
    if not st.session_state.get("f_description", "").strip():
        errors.append("Description is required.")

    date_val = st.session_state.get("f_date", "").strip()
    if date_val:
        try:
            dt.datetime.strptime(date_val, "%Y-%m-%d")
        except ValueError:
            errors.append("Date must be in YYYY-MM-DD format (e.g. 2026-05-29).")

    if errors:
        for e in errors:
            st.error(f"⚠️ {e}")
        return

    payload = build_incident_payload(
        raw_severity=st.session_state.get("f_severity", "Low") or "Low",
        category=st.session_state.get("f_category", "Other"),
        source_url=st.session_state.get("f_source_url", "").strip(),
        target=st.session_state.get("f_target", "").strip(),
        description=st.session_state.get("f_description", "").strip(),
        created_by=st.session_state.get("user_id", 1),
    )
    incident_id = payload["incident_id"]

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO incidents
                (incident_id, category, severity, source_url, target,
                 description, status, priority, tags, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                payload["category"],
                payload["severity"],
                payload["source_url"],
                payload["target"],
                payload["description"],
                payload["status"],
                payload["priority"],
                payload["tags"],
                payload["created_by"],
                payload["created_at"],
            ),
        )
        conn.commit()
        conn.close()

        try:
            with st.spinner("📊 Running AI incident heuristics..."):
                process_incident_classification(incident_id, payload["description"])
        except Exception as ai_exc:
            st.warning(f"AI analysis could not complete right now: {ai_exc}")

        for key in ["f_title", "f_location", "f_category", "f_time",
                    "f_date", "f_severity", "f_description", "submit_step"]:
            st.session_state.pop(key, None)

        st.success(f"✅ Incident submitted! ID: `{incident_id}`")
        st.session_state["active_page"] = "Upload Evidence"
        st.session_state["upload_incident_id"] = incident_id
        st.rerun()
    except Exception as exc:
        st.error(f"❌ Database error: {exc}")


def process_incident_classification(incident_id: str, description: str):
    """Run AI classification on an incident and persist the suggested category/severity."""
    result = classify_incident(incident_id, description)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE incidents SET category = ?, severity = ? WHERE incident_id = ?",
        (result["category"], result["severity"], incident_id),
    )
    conn.commit()
    conn.close()
    return result


def render_submission_form():
    abort_if_unauthorized("Submit Incident", st.session_state.get("role"))
    st.markdown(_CSS, unsafe_allow_html=True)
    _render_submission_form()
