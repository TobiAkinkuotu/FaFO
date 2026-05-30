import streamlit as st
import sqlite3
import uuid
import datetime
import os
import pathlib
import json
from config.settings import DATABASE_PATH, UPLOADS_DIR
from database.connection import get_db_connection
from modules.audit_logger import log_action
from modules.notifications import notify_evidence_uploaded
from modules.rbac import abort_if_unauthorized
from modules.hashing import generate_bytes_hash, generate_file_hashes
from modules.metadata_manager import extract_file_metadata, extract_metadata
from modules.security import validate_file_upload_complete, get_secure_storage_path
from modules.ocr_engine import process_evidence_ocr
from modules.ffmpeg_processor import probe_video, extract_thumbnail
from modules.ai_classifier import run_ai_analysis_for_incident, ensure_ai_analysis_schema

# ──────────────────────────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────────────────────────

EVIDENCE_CSS = """
<style>
/* ── Container Override ──────────────────────────────────────── */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: #112236 !important;
    border-radius: 12px !important;
    padding: 32px !important;
    max-width: 600px;
    margin: 0 auto;
    border: none !important;
}

/* ── Drop-zone override ──────────────────────────────────────── */
[data-testid="stFileUploader"] {
    background: transparent !important;
    margin-bottom: 24px;
}
[data-testid="stFileUploadDropzone"] {
    background: #070C12 !important;
    border: 2px dashed rgba(26, 115, 232, 0.4) !important;
    border-radius: 12px !important;
    height: 200px !important;
    display: flex !important;
    flex-direction: column !important;
    justify-content: center !important;
    align-items: center !important;
    padding: 0 !important;
    transition: all 0.25s ease;
}
[data-testid="stFileUploadDropzone"]:hover {
    border-color: rgba(26, 115, 232, 0.8) !important;
}

[data-testid="stFileUploadDropzone"] svg {
    display: none !important;
}

/* ── Type pills ──────────────────────────────────────────────── */
.type-pills {
    display: flex;
    justify-content: center;
    gap: 8px;
    margin: 24px 0;
}
.type-pill {
    background: rgba(255, 255, 255, 0.05);
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 11px;
    color: #9AA0A6;
}

/* ── Drop-zone custom label ────────────────────────────────────── */
.ev-dropzone-label {
    text-align: center;
    pointer-events: none;
    position: absolute;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 100%;
    height: 100%;
    z-index: 10;
}
.ev-dropzone-label .cloud-icon {
    font-size: 48px;
    color: #1A73E8;
    margin-bottom: 16px;
}
.ev-dropzone-label p.primary {
    color: #E8F0FE;
    font-size: 16px;
    font-weight: 600;
    margin: 0 0 4px 0;
}
.ev-dropzone-label p.secondary {
    color: #9AA0A6;
    font-size: 13px;
    margin: 0;
}

/* ── File list ──────────────────────────────────────────────── */
.ev-file-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
}
.ev-file-row {
    display: flex;
    align-items: center;
    padding: 12px 16px;
    background: #0A1118;
    border-radius: 8px;
    border: 1px solid rgba(255,255,255,0.05);
    transition: all 0.2s ease;
}
.ev-file-row:hover {
    background: #0D141E;
    border-color: rgba(26, 115, 232, 0.3);
}
.ev-file-icon {
    font-size: 20px;
    margin-right: 16px;
}
.ev-file-name {
    font-size: 13px;
    color: #E8F0FE;
    flex: 1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.ev-file-meta {
    font-size: 12px;
    color: #9AA0A6;
    display: flex;
    gap: 16px;
    align-items: center;
}

/* ── Action button ────────────────────────────────────────────── */
.stButton > button {
    width: 100% !important;
    height: 48px !important;
    background: #1A73E8 !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    margin-top: 24px !important;
    color: white !important;
    border: none !important;
}
.stButton > button:hover {
    background: #1557b0 !important;
    box-shadow: 0 4px 12px rgba(26, 115, 232, 0.3);
}
</style>
"""


# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────

def _file_icon(filename: str) -> str:
    ext = pathlib.Path(filename).suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        return "🖼️"
    if ext in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
        return "🎬"
    return "📄"

def _human_size(n_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n_bytes < 1024:
            return f"{n_bytes:.1f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.1f} TB"

def _mime_type_from_extension(filename: str) -> str:
    """Derive MIME type from file extension."""
    ext_to_mime = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp',
        '.mp4': 'video/mp4', '.mov': 'video/quicktime', '.avi': 'video/x-msvideo', '.mkv': 'video/x-matroska', '.webm': 'video/webm',
        '.pdf': 'application/pdf', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.txt': 'text/plain', '.json': 'application/json',
    }
    ext = pathlib.Path(filename).suffix.lower()
    return ext_to_mime.get(ext, 'application/octet-stream')

def ensure_evidence_schema():
    conn = get_db_connection(str(DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence'")
    if cursor.fetchone() is None:
        cursor.execute("""
            CREATE TABLE evidence (
                evidence_id TEXT PRIMARY KEY,
                incident_id TEXT REFERENCES incidents(incident_id),
                filename TEXT NOT NULL,
                original_name TEXT,
                file_type TEXT,
                file_extension TEXT,
                file_size INTEGER,
                file_hash TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                metadata TEXT,
                uploaded_by INTEGER REFERENCES users(id),
                uploaded_at DATETIME DEFAULT (datetime('now','utc'))
            )
        """)

    cursor.execute("PRAGMA table_info(evidence)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    if "metadata" not in existing_columns:
        cursor.execute("ALTER TABLE evidence ADD COLUMN metadata TEXT")
    conn.commit()
    conn.close()


def ensure_ocr_results_schema():
    conn = get_db_connection(str(DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ocr_results'")
    if cursor.fetchone() is None:
        cursor.execute(
            "CREATE TABLE ocr_results ("
            "ocr_id TEXT PRIMARY KEY,"
            "incident_id TEXT REFERENCES incidents(incident_id),"
            "evidence_id TEXT REFERENCES evidence(evidence_id),"
            "extracted_text TEXT,"
            "confidence_score REAL,"
            "detected_urls TEXT,"
            "detected_usernames TEXT,"
            "detected_threats TEXT,"
            "created_at DATETIME DEFAULT (datetime('now','utc'))"
            ")"
        )
    conn.commit()
    conn.close()


def _get_existing_evidence(incident_id: str) -> list:
    ensure_evidence_schema()
    try:
        conn = get_db_connection(str(DATABASE_PATH))
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT evidence_id, filename, file_size, file_type, uploaded_at, file_hash, metadata, storage_path
            FROM   evidence
            WHERE  incident_id = ?
            ORDER  BY uploaded_at DESC
            """,
            (incident_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "evidence_id": r[0],
                "filename":    r[1],
                "file_size":   r[2],
                "file_type":   r[3],
                "uploaded_at": r[4],
                "file_hash":   r[5],
                "metadata":    r[6],
                "storage_path": r[7]
            }
            for r in rows
        ]
    except Exception:
        return []


def _get_incident_details(incident_id: str) -> dict:
    try:
        conn = get_db_connection(str(DATABASE_PATH))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT incident_id, category, severity, source_url, target, description, status, priority, tags FROM incidents WHERE incident_id = ?",
            (incident_id,),
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return {}
        return {
            "incident_id": row[0],
            "category": row[1],
            "severity": row[2],
            "source_url": row[3],
            "target": row[4],
            "description": row[5],
            "status": row[6],
            "priority": row[7],
            "tags": row[8],
        }
    except Exception:
        return {}


def _get_user_incidents(user_id: int) -> list[dict]:
    if user_id is None:
        return []
    try:
        conn = get_db_connection(str(DATABASE_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT incident_id, category, status, created_at FROM incidents WHERE created_by = ? ORDER BY created_at DESC",
            (user_id,),
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def _delete_evidence(evidence_id: str):
    try:
        conn = get_db_connection(str(DATABASE_PATH))
        cursor = conn.cursor()
        cursor.execute("DELETE FROM evidence WHERE evidence_id = ?", (evidence_id,))
        conn.commit()
        conn.close()
    except Exception as exc:
        st.error(f"❌ Could not delete record: {exc}")

def _save_files_hardened(incident_id: str, uploaded_files) -> int:
    """Hardened evidence upload with validation, hashing, metadata, OCR, and video processing."""
    username = st.session_state.get("username", "system")
    user_id = st.session_state.get("user_id", 1)

    conn = None
    success = 0
    deferred_notifications = []
    progress_container = st.empty()

    try:
        ensure_evidence_schema()
        conn = get_db_connection(str(DATABASE_PATH))
        cursor = conn.cursor()

        for file_idx, uf in enumerate(uploaded_files):
            progress_container.progress(
                (file_idx / len(uploaded_files)) if len(uploaded_files) > 0 else 0,
                text=f"Processing {file_idx + 1}/{len(uploaded_files)}: {uf.name}"
            )
            try:
                is_valid, error_msg, category = validate_file_upload_complete(uf)
                if not is_valid:
                    st.error(f"❌ {uf.name}: {error_msg}")
                    continue

                storage_path = get_secure_storage_path(incident_id, uf.name, category)
                data = uf.read()
                with open(storage_path, "wb") as fh:
                    fh.write(data)

                hashes = generate_file_hashes(str(storage_path))
                metadata = extract_metadata(str(storage_path), category)

                evidence_id = f"EVD_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
                mime_type = uf.type or _mime_type_from_extension(uf.name)
                file_extension = pathlib.Path(uf.name).suffix.lower()
                storage_path_str = str(storage_path)
                filename = pathlib.Path(storage_path_str).name if isinstance(storage_path, pathlib.Path) else storage_path_str.split('/')[-1]

                cursor.execute(
                    """
                    INSERT INTO evidence
                        (evidence_id, incident_id, filename, original_name, file_type, file_extension,
                         file_size, file_hash, storage_path, uploaded_by, uploaded_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        incident_id,
                        filename,
                        uf.name,
                        mime_type,
                        file_extension,
                        hashes['file_size'],
                        hashes['sha256'],
                        storage_path_str,
                        user_id,
                        datetime.datetime.now().isoformat(),
                        json.dumps({**metadata, 'md5_hash': hashes['md5'], 'sha256_hash': hashes['sha256']})
                    ),
                )

                if category in ['image', 'document', 'video']:
                    try:
                        with st.spinner(f"🔍 Analyzing {uf.name} for text..."):
                            ocr_results = process_evidence_ocr(storage_path_str, evidence_id, incident_id)
                        if ocr_results and not ocr_results.get('error'):
                            cursor.execute(
                                """
                                INSERT INTO ocr_results
                                    (ocr_id, evidence_id, incident_id, extracted_text, confidence_score,
                                     detected_urls, detected_usernames, detected_threats, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    f"OCR_{os.urandom(4).hex()}",
                                    evidence_id,
                                    incident_id,
                                    ocr_results.get('text', ''),
                                    ocr_results.get('confidence', 0),
                                    json.dumps(ocr_results.get('urls', [])),
                                    json.dumps(ocr_results.get('usernames', [])),
                                    json.dumps(ocr_results.get('threats', [])),
                                    datetime.datetime.now().isoformat(),
                                ),
                            )
                        elif ocr_results and ocr_results.get('error'):
                            st.warning(f"OCR skipped for {uf.name}: {ocr_results['error']}")
                    except Exception as exc:
                        st.warning(f"OCR skipped for {uf.name}: {exc}")

                if category == 'video':
                    try:
                        video_probe = probe_video(pathlib.Path(storage_path_str))
                        if 'error' not in video_probe:
                            thumbnail_path = None
                            try:
                                thumb_base = pathlib.Path('evidence_repository') / incident_id / 'thumbnails'
                                thumb_base.mkdir(parents=True, exist_ok=True)
                                thumbnail_file = thumb_base / f"{evidence_id}.png"
                                if extract_thumbnail(pathlib.Path(storage_path_str), thumbnail_file, time_offset=1.0):
                                    thumbnail_path = str(thumbnail_file)
                            except Exception:
                                pass

                            duration = video_probe.get('duration', 0)
                            frame_rate = video_probe.get('frame_rate') or 24
                            frame_count = int(duration * frame_rate) if duration > 0 else 0

                            cursor.execute(
                                """
                                INSERT INTO video_metadata
                                    (video_id, incident_id, evidence_id, duration, codec, resolution,
                                     frame_rate, bitrate, thumbnail_path, frame_count, processed_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    f"VID_{os.urandom(4).hex()}",
                                    incident_id,
                                    evidence_id,
                                    duration,
                                    video_probe.get('codec', ''),
                                    video_probe.get('resolution', ''),
                                    frame_rate,
                                    video_probe.get('bitrate', 0),
                                    thumbnail_path,
                                    frame_count,
                                    datetime.datetime.now().isoformat(),
                                ),
                            )
                    except Exception as exc:
                        st.warning(f"Video metadata skipped for {uf.name}: {exc}")

                success += 1
                deferred_notifications.append((incident_id, evidence_id, user_id, username))
            except Exception as exc:
                st.error(f"❌ Failed to save {uf.name}: {exc}")

        if success > 0:
            cursor.execute("SELECT status FROM incidents WHERE incident_id = ?", (incident_id,))
            current_status_row = cursor.fetchone()
            if current_status_row and current_status_row[0] == 'pending':
                cursor.execute(
                    "UPDATE incidents SET status = 'under_review', updated_at = ? WHERE incident_id = ?",
                    (datetime.datetime.now().isoformat(), incident_id),
                )
                log_action(user_id, username, "INCIDENT_STATUS_UPDATED", "incident", incident_id)

        conn.commit()
        progress_container.empty()
        conn.close()

        for incident_id, evidence_id, user_id, username in deferred_notifications:
            try:
                log_action(user_id, username, "EVIDENCE_UPLOADED", "evidence", evidence_id)
                notify_evidence_uploaded(incident_id, evidence_id, user_id)
            except Exception:
                pass

        return success
    except Exception as exc:
        st.error(f"❌ DB connection error: {exc}")
        progress_container.empty()
        return 0
    finally:
        if conn is not None:
            conn.close()

# ──────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────

def render_evidence_upload(incident_id: str = None):
    incident_id = incident_id or st.session_state.get("upload_incident_id")
    abort_if_unauthorized("Upload Evidence", st.session_state.get("role"))
    st.markdown(EVIDENCE_CSS, unsafe_allow_html=True)

    user_id = st.session_state.get("user_id")
    if not incident_id:
        if user_id is None:
            st.error("Unable to determine your account. Please log in again.")
            return

        user_incidents = _get_user_incidents(user_id)
        if not user_incidents:
            st.info("No incidents found. Submit an incident first, then attach evidence here.")
            return

        options = [
            f"{row['incident_id']} · {row['category']} · {row['status']} · {str(row.get('created_at', ''))[:10]}"
            for row in user_incidents
        ]
        selected = st.selectbox("Select an incident to attach evidence:", [""] + options, key="upload_incident_select")
        if not selected:
            st.info("Choose an incident from the list to see its uploaded evidence and attach new files.")
            return

        incident_id = selected.split(" · ")[0]
        st.session_state["upload_incident_id"] = incident_id

    with st.container(border=True):
        incident_details = _get_incident_details(incident_id)
        if incident_details:
            st.markdown(f"**Selected Incident:** {incident_id} — {incident_details.get('category','Unknown')} ({incident_details.get('status','pending')})")
            st.markdown(f"**Target:** {incident_details.get('target','—')} | **Severity:** {incident_details.get('severity','—').title()}")
            st.markdown("---")

        st.markdown(
            '<div style="position:relative;">'
            '<div class="ev-dropzone-label">'
            '<span class="cloud-icon">☁️</span>'
            '<p class="primary">Drag &amp; Drop Evidence Files Here</p>'
            '<p class="secondary">or click to browse</p>'
            '</div></div>',
            unsafe_allow_html=True,
        )

        uploaded_files = st.file_uploader(
            "Upload evidence files",
            accept_multiple_files=True,
            label_visibility="collapsed",
            key=f"ev_uploader_{incident_id}",
        )

        supported_types = ["PNG", "JPG", "MP4", "MOV", "PDF", "DOCX"]
        pills_html = '<div class="type-pills">'
        for t in supported_types:
            pills_html += f'<span class="type-pill">{t}</span>'
        pills_html += "</div>"
        st.markdown(pills_html, unsafe_allow_html=True)

        ensure_evidence_schema()
        ensure_ocr_results_schema()
        ensure_ai_analysis_schema()

        existing = _get_existing_evidence(incident_id)
        evidence_count = len(existing) if existing else 0

        conn = get_db_connection(str(DATABASE_PATH))
        cursor = conn.cursor()
        ocr_count = 0
        latest_ai = None

        try:
            cursor.execute("SELECT COUNT(*) FROM ocr_results WHERE incident_id = ?", (incident_id,))
            ocr_count = cursor.fetchone()[0] or 0
        except Exception:
            ocr_count = 0

        try:
            cursor.execute(
                "SELECT analysis_status, suggested_category, suggested_severity, threat_score, ai_confidence FROM ai_analysis WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
                (incident_id,),
            )
            latest_ai = cursor.fetchone()
        except Exception:
            latest_ai = None

        conn.close()

        with st.expander("Pipeline Status", expanded=True):
            st.markdown(f"**Evidence files:** {evidence_count}")
            st.markdown(f"**OCR extractions:** {ocr_count}")
            if latest_ai:
                status, category, severity, threat_score, confidence = latest_ai
                st.markdown(f"**AI status:** {status or 'pending'}")
                st.markdown(f"**AI category:** {category or 'unknown'}")
                st.markdown(f"**AI severity:** {severity or 'unknown'}")
                st.markdown(f"**Threat score:** {float(threat_score or 0):.2f}")
                st.markdown(f"**Confidence:** {float(confidence or 0):.1f}%")
            else:
                st.markdown("**AI status:** pending analysis")

        if existing:
            st.markdown('<div class="ev-file-list">', unsafe_allow_html=True)
            for row in existing:
                icon = _file_icon(row["filename"])
                size = _human_size(row["file_size"]) if row["file_size"] else "—"
                try:
                    dt_str = datetime.datetime.fromisoformat(row["uploaded_at"]).strftime("%m/%d/%Y")
                except Exception:
                    dt_str = row["uploaded_at"] or "—"

                row_html = f"""
                <div class="ev-file-row">
                    <div class="ev-file-icon">{icon}</div>
                    <div class="ev-file-name">{row['filename']}</div>
                    <div class="ev-file-meta">
                        <span>{size}</span>
                        <span>{dt_str}</span>
                    </div>
                </div>
                """
                st.markdown(row_html, unsafe_allow_html=True)
                
                with st.expander(f"Details / Delete: {row['filename']}"):
                    if st.button("🗑️ Delete Evidence", key=f"del_{row['evidence_id']}"):
                        _delete_evidence(row["evidence_id"])
                        if row.get("storage_path") and os.path.exists(row["storage_path"]):
                            os.remove(row["storage_path"])
                        st.success(f"Deleted: {row['filename']}")
                        st.rerun()

            st.markdown('</div>', unsafe_allow_html=True)

        if st.button(
            "Upload All",
            type="primary",
            use_container_width=True,
            disabled=(not uploaded_files),
        ):
            if uploaded_files:
                count = _save_files_hardened(incident_id, uploaded_files)
                if count > 0:
                    try:
                        with st.spinner("🔎 Refreshing AI analysis after evidence upload..."):
                            run_ai_analysis_for_incident(incident_id)
                    except Exception as ai_exc:
                        st.warning(f"AI analysis refresh skipped: {ai_exc}")
                    st.success(f"✅ {count} file(s) uploaded successfully.")
                    st.rerun()
