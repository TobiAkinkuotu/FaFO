import streamlit as st
import sqlite3
import pandas as pd
import zipfile
import io
import os
from pathlib import Path
from app_config.settings import DATABASE_PATH, EVIDENCE_REPO_PATH
from database.connection import get_db_connection
from modules.audit_logger import log_action

PORTAL_CSS = """
<style>
/* Global */
[data-testid="stAppViewContainer"] { background-color: #0A1118; }
[data-testid="stSidebar"] { background-color: #0A1118; }
.block-container { padding: 0 !important; max-width: 100% !important; }

/* 1. Split Layout Columns Override */
div[data-testid="column"]:nth-child(1) {
    background-color: #112236;
    border-right: 1px solid rgba(255, 255, 255, 0.08);
    padding: 20px !important;
    min-height: 100vh;
}
div[data-testid="column"]:nth-child(2) {
    background-color: #112236;
    padding: 40px !important;
    min-height: 100vh;
}

/* 2. Left Panel */
.left-header {
    font-size: 18px;
    font-weight: 600;
    color: #FFFFFF;
    margin-bottom: 24px;
}
.case-card {
    display: flex;
    flex-direction: column;
    gap: 4px;
    background-color: #0A1118;
    padding: 16px;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    margin-bottom: 12px;
}
.case-card.active {
    border-left: 3px solid #1A73E8;
    background-color: rgba(26, 115, 232, 0.05);
}
.case-id { font-size: 14px; color: #E8F0FE; font-weight: 500; }
.case-date { font-size: 12px; color: #9AA0A6; }

/* 3. Right Panel */
.top-metadata {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
}
.meta-left {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 14px;
    color: #9AA0A6;
}
.meta-left strong { color: #E8F0FE; }
.confidential-badge {
    background-color: rgba(217, 48, 37, 0.1);
    color: #D93025;
    border: 1px solid #D93025;
    padding: 4px 12px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 12px;
}

/* Evidence Package Preview */
.evidence-white-container {
    background-color: #FFFFFF;
    border-radius: 8px;
    padding: 24px;
    margin-top: 24px;
    min-height: 300px;
}
.doc-line {
    height: 12px;
    background-color: #E0E0E0;
    border-radius: 4px;
    margin-bottom: 12px;
}
.doc-line.short { width: 60%; }
.doc-title { color: #000; font-weight: bold; margin-bottom: 16px; }

/* Hide default button styling to overlay on cards */
button[kind="secondary"] {
    width: 100%;
}
.stDownloadButton > button,
button[kind="primary"] {
    background-color: #1A73E8 !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    box-shadow: 0 4px 14px rgba(26, 115, 232, 0.24) !important;
}
.stDownloadButton > button:hover,
button[kind="primary"]:hover {
    background-color: #1558A0 !important;
}
</style>
"""


def _fetch_case_evidence(incident_id: str) -> list[dict]:
    try:
        conn = get_db_connection(str(DATABASE_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT evidence_id, filename, storage_path, file_type, uploaded_at "
            "FROM evidence WHERE incident_id = ? ORDER BY uploaded_at DESC",
            (incident_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "evidence_id": row[0],
                "filename": row[1],
                "storage_path": row[2],
                "file_type": row[3],
                "uploaded_at": row[4],
            }
            for row in rows
        ]
    except Exception as exc:
        st.error(f"Database error: {exc}")
        return []


def _build_case_archive(incident_id: str, evidence_items: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for item in evidence_items:
            path = item.get("storage_path")
            if path and os.path.exists(path):
                archive.write(path, arcname=os.path.basename(path))
    buf.seek(0)
    return buf.read()


def render_lawyer_portal():
    # Role enforcement: lawyers only
    if st.session_state.get("role") != "lawyer":
        st.error("Access denied. This portal is for lawyers only.")
        return

    st.markdown(PORTAL_CSS, unsafe_allow_html=True)
    user_id = st.session_state.get("user_id")
    username = st.session_state.get("username", "unknown")
    log_action(user_id, username, "LAWYER_PORTAL_VIEWED", "lawyer_portal")

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        # Lawyers only see approved incidents with status = 'approved' or 'escalated'
        cases = [dict(r) for r in conn.execute(
            "SELECT i.incident_id, i.status, i.created_at, u.username AS submitter FROM incidents i LEFT JOIN users u ON i.created_by = u.id WHERE i.status IN ('approved', 'escalated') ORDER BY i.created_at DESC"
        ).fetchall()]
        conn.close()
    except Exception as e:
        st.error(f"Database error: {e}")
        return

    left_col, right_col = st.columns([1, 2.5])

    with left_col:
        st.markdown('<div class="left-header">Secure Document Review</div>', unsafe_allow_html=True)
        if not cases:
            st.write("No cases found.")
        else:
            selected_id = st.session_state.get("selected_case_id")
            for case in cases:
                cid = case["incident_id"]
                date_str = str(case.get("created_at", ""))[:10]
                active_cls = "active" if cid == selected_id else ""
                
                card_html = f"""
                <div class="case-card {active_cls}">
                    <div class="case-id">{cid}</div>
                    <div class="case-date">{date_str}</div>
                </div>
                """
                st.markdown(card_html, unsafe_allow_html=True)
                if st.button("View Case", key=f"sel_{cid}", use_container_width=True):
                    st.session_state["selected_case_id"] = cid
                    log_action(user_id, username, "LAWYER_CASE_OPENED", "incident", cid)
                    st.rerun()

    with right_col:
        selected_id = st.session_state.get("selected_case_id")
        if not selected_id:
            st.markdown('<div style="color:#9AA0A6;text-align:center;margin-top:100px;">Select a case to view details</div>', unsafe_allow_html=True)
            return

        selected_case = next((c for c in cases if c["incident_id"] == selected_id), None)
        if not selected_case:
            st.warning("Case not found.")
            return

        date_str = str(selected_case.get("created_at", ""))[:10]
        submitter = selected_case.get("submitter") or "Unknown"

        st.markdown(f"""
        <div class="top-metadata">
            <div class="meta-left">
                <div><strong>Case ID:</strong> {selected_id}</div>
                <div><strong>Submitter:</strong> {submitter}</div>
                <div><strong>Date:</strong> {date_str}</div>
            </div>
            <div class="confidential-badge">CONFIDENTIAL</div>
        </div>
        """, unsafe_allow_html=True)

        evidence_items = _fetch_case_evidence(selected_id)
        if not evidence_items:
            st.markdown('<div class="evidence-white-container">', unsafe_allow_html=True)
            st.markdown('<div class="doc-title">No evidence files have been attached to this case yet.</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            return

        st.markdown('<div class="evidence-white-container">', unsafe_allow_html=True)
        st.markdown('<div class="doc-title">Evidence Package</div>', unsafe_allow_html=True)
        st.markdown('<div style="color:#4A5568;font-size:13px;margin-bottom:16px;">Review the case evidence below and download an archive for secure transfer.</div>', unsafe_allow_html=True)

        file_rows = [
            {
                "File Name": item["filename"],
                "Type": item["file_type"],
                "Uploaded At": str(item["uploaded_at"])[:16],
            }
            for item in evidence_items
        ]
        st.table(file_rows)

        st.markdown('</div>', unsafe_allow_html=True)

        archive_bytes = _build_case_archive(selected_id, evidence_items)
        if archive_bytes:
            st.download_button(
                "Download Evidence Package",
                data=archive_bytes,
                file_name=f"case_{selected_id}_evidence.zip",
                mime="application/zip",
                use_container_width=True,
            )
        else:
            st.warning("Evidence archive could not be generated because one or more files are unavailable.")
