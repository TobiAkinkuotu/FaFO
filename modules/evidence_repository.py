import streamlit as st
import sqlite3
import json
import os
import pathlib
from datetime import datetime
from config.settings import DATABASE_PATH
from database.connection import get_db_connection
from modules.rbac import abort_if_unauthorized


# ──────────────────────────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────────────────────────

REPO_CSS = """
<style>
/* ── Grid Layout ─────────────────────────────────────────────── */
.ev-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
    padding: 8px 0;
}

/* ── Evidence Card ───────────────────────────────────────────── */
.ev-card {
    background: #112236;
    border: 1px solid #1A3A5C;
    border-radius: 12px;
    padding: 0;
    overflow: hidden;
    cursor: pointer;
    transition: all 0.2s ease;
    position: relative;
}
.ev-card:hover {
    border-color: #1E6DB5;
    box-shadow: 0 4px 20px rgba(30, 109, 181, 0.15);
    transform: translateY(-2px);
}
.ev-card.selected {
    border-color: #1E6DB5;
    box-shadow: 0 0 0 2px rgba(30, 109, 181, 0.3);
}

/* ── Thumbnail Area ──────────────────────────────────────────── */
.ev-thumb {
    width: 100%;
    height: 160px;
    background: #0D1B2A;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
}
.ev-thumb img {
    width: 100%;
    height: 100%;
    object-fit: cover;
}
.ev-thumb .ev-icon {
    font-size: 48px;
    opacity: 0.6;
}
.ev-thumb .ev-badge {
    position: absolute;
    top: 8px;
    right: 8px;
    background: rgba(13, 27, 42, 0.85);
    color: #8BA3BE;
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 4px;
    font-weight: 500;
}

/* ── Card Body ───────────────────────────────────────────────── */
.ev-card-body {
    padding: 14px 16px;
}
.ev-card-title {
    font-size: 14px;
    font-weight: 600;
    color: #EAF1F8;
    margin: 0 0 6px 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.ev-card-meta {
    font-size: 12px;
    color: #8BA3BE;
    background: rgba(13, 27, 42, 0.5);
    padding: 8px 10px;
    border-radius: 8px;
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 8px;
    flex-wrap: wrap;
}
.ev-card-meta span {
    display: inline-flex;
    align-items: center;
    gap: 4px;
}
.ev-card-ocr {
    font-size: 12px;
    color: #EAF1BE;
    background: rgba(13, 27, 42, 0.5);
    padding: 8px 10px;
    border-radius: 6px;
    border-left: 3px solid #1E6DB5;
    max-height: 60px;
    overflow: hidden;
    line-height: 1.4;
}
.ev-card-ocr .ocr-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #1E6DB5;
    margin-bottom: 2px;
}

/* ── Detail Panel ────────────────────────────────────────────────── */
.ev-detail {
    background: #112236;
    border: 1px solid #1A3A5C;
    border-radius: 12px;
    padding: 20px;
    position: sticky;
    top: 20px;
}
.ev-detail h3 {
    margin: 0 0 16px 0;
    font-size: 16px;
    color: #1E6DB5;
}
.ev-detail-section {
    margin-bottom: 20px;
}
.ev-detail-section h4 {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: #8BA3BE;
    margin: 0 0 8px 0;
}
.ev-detail-thumb {
    width: 100%;
    border-radius: 8px;
    margin-bottom: 12px;
}
.ev-detail-ocr {
    background: #0D1B2A;
    border: 1px solid #1A3A5C;
    border-radius: 8px;
    padding: 12px;
    font-size: 13px;
    color: #EAF1F8;
    line-height: 1.5;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
}
.ev-detail-meta {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
}
.ev-detail-meta-item {
    background: rgba(13, 27, 42, 0.5);
    padding: 8px 10px;
    border-radius: 6px;
}
.ev-detail-meta-item .label {
    font-size: 10px;
    color: #8BA3BE;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 2px;
}
.ev-detail-meta-item .value {
    font-size: 13px;
    color: #EAF1F8;
    font-weight: 500;
}

/* ── Empty State ─────────────────────────────────────────────── */
.ev-empty {
    text-align: center;
    padding: 60px 20px;
    color: #8BA3BE;
}
.ev-empty .icon {
    font-size: 48px;
    margin-bottom: 16px;
    opacity: 0.4;
}

/* ── Filter Bar ──────────────────────────────────────────────── */
.ev-filter-bar {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
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
    if ext in {".pdf"}:
        return "📄"
    if ext in {".doc", ".docx"}:
        return "📝"
    return "📎"


def _human_size(n_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n_bytes < 1024:
            return f"{n_bytes:.1f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.1f} TB"


def _format_date(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y · %H:%M")
    except Exception:
        return iso_str or "—"


def _fetch_evidence(filters: dict = None) -> list:
    """Fetch evidence with joined OCR and video metadata."""
    try:
        conn = get_db_connection(str(DATABASE_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT 
                e.evidence_id,
                e.incident_id,
                e.filename,
                e.original_name,
                e.file_type,
                e.file_size,
                e.uploaded_at,
                e.storage_path,
                e.metadata,
                o.extracted_text AS ocr_text,
                o.confidence_score AS ocr_confidence,
                o.detected_urls,
                o.detected_threats,
                v.duration AS video_duration,
                v.resolution AS video_resolution,
                v.thumbnail_path
            FROM evidence e
            LEFT JOIN ocr_results o ON e.evidence_id = o.evidence_id
            LEFT JOIN video_metadata v ON e.evidence_id = v.evidence_id
            WHERE 1=1
        """
        params = []

        if filters:
            if filters.get("incident_id"):
                query += " AND e.incident_id = ?"
                params.append(filters["incident_id"])
            if filters.get("file_type"):
                query += " AND e.file_type LIKE ?"
                params.append(f"%{filters['file_type']}%")
            if filters.get("search"):
                query += """ AND (
                    e.filename LIKE ? 
                    OR e.original_name LIKE ? 
                    OR o.extracted_text LIKE ?
                )"""
                term = f"%{filters['search']}%"
                params.extend([term, term, term])

        query += " ORDER BY e.uploaded_at DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [dict(r) for r in rows]

    except Exception as exc:
        st.error(f"Database error: {exc}")
        return []


def _ocr_snippet(text: str, max_len: int = 120) -> str:
    """Return a truncated OCR snippet with ellipsis."""
    if not text:
        return ""
    text = text.strip().replace("\n", " ")
    if len(text) > max_len:
        return text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


# ──────────────────────────────────────────────────────────────────
# Components
# ──────────────────────────────────────────────────────────────────

def _render_card(ev: dict, selected: bool) -> None:
    """Render a single evidence card."""
    card_class = "ev-card selected" if selected else "ev-card"
    ext = pathlib.Path(ev.get("filename", "")).suffix.lower()
    is_video = ext in {".mp4", ".mov", ".avi", ".mkv", ".webm"}
    is_image = ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}

    thumb_html = f'<div class="ev-thumb">'
    thumb_path = ev.get("thumbnail_path")
    if thumb_path and os.path.exists(thumb_path):
        thumb_html += f'<img src="file://{thumb_path}" alt="thumbnail">'
    else:
        icon = "🎬" if is_video else ("🖼️" if is_image else "📄")
        thumb_html += f'<div class="ev-icon">{icon}</div>'
    thumb_html += f'<span class="ev-badge">{ext.lstrip(".") or "file"}</span></div>'

    title = ev.get("original_name") or ev.get("filename") or "Untitled"
    size = _human_size(ev.get("file_size", 0))
    date_str = _format_date(ev.get("uploaded_at", ""))
    ocr_text = _ocr_snippet(ev.get("ocr_text", ""))
    incident = ev.get("incident_id", "—")

    ocr_html = ""
    if ocr_text:
        ocr_html = (
            '<div class="ev-card-ocr">'
            '<div class="ocr-label">Extracted Text</div>'
            f'{ocr_text}'
            '</div>'
        )

    card_html = (
        f'<div class="{card_class}" id="card_{ev["evidence_id"]}">'  # noqa: W605
        f'{thumb_html}'
        '<div class="ev-card-body">'
        f'<div class="ev-card-title" title="{title}">{title}</div>'
        '<div class="ev-card-meta">'
        f'<span>📁 {incident}</span>'
        f'<span>📦 {size}</span>'
        f'<span>📅 {date_str.split("·")[0].strip()}</span>'
        '</div>'
        f'{ocr_html}'
        '</div>'
        '</div>'
    )
    st.markdown(card_html, unsafe_allow_html=True)


def _render_detail_panel(ev: dict) -> None:
    """Render the right-hand detail panel for selected evidence."""
    if not ev:
        st.markdown(
            '<div class="ev-empty">'
            '<div class="icon">📂</div>'
            '<div>Select evidence to view details</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    title = ev.get("original_name") or ev.get("filename") or "Untitled"
    ext = pathlib.Path(ev.get("filename", "")).suffix.lower()
    is_video = ext in {".mp4", ".mov", ".avi", ".mkv", ".webm"}

    st.markdown(f'<div class="ev-detail">', unsafe_allow_html=True)
    st.markdown(f"<h3>📎 {title}</h3>", unsafe_allow_html=True)

    thumb_path = ev.get("thumbnail_path")
    if thumb_path and os.path.exists(thumb_path):
        st.image(thumb_path, use_container_width=True)
    elif is_video:
        st.markdown("🎬 *Video preview not available*")

    meta = ev.get("metadata", "{}")
    try:
        meta_dict = json.loads(meta) if isinstance(meta, str) else meta
    except Exception:
        meta_dict = {}

    st.markdown('<div class="ev-detail-section"><h4>Metadata</h4>', unsafe_allow_html=True)
    st.markdown('<div class="ev-detail-meta">', unsafe_allow_html=True)

    meta_items = [
        ("Incident", ev.get("incident_id", "—")),
        ("Type", ev.get("file_type", "—")),
        ("Size", _human_size(ev.get("file_size", 0))),
        ("Uploaded", _format_date(ev.get("uploaded_at", ""))),
    ]

    if ev.get("video_duration"):
        meta_items.append(("Duration", f"{ev['video_duration']:.1f}s"))
    if ev.get("video_resolution"):
        meta_items.append(("Resolution", ev["video_resolution"]))
    if ev.get("ocr_confidence") is not None:
        try:
            confidence_value = float(ev.get("ocr_confidence", 0))
            meta_items.append(("OCR Confidence", f"{confidence_value * 100:.0f}%"))
        except Exception:
            meta_items.append(("OCR Confidence", str(ev.get("ocr_confidence", "—"))))

    for label, value in meta_items:
        st.markdown(
            '<div class="ev-detail-meta-item">'
            f'<div class="label">{label}</div>'
            f'<div class="value">{value}</div>'
            '</div>',
            unsafe_allow_html=True,
        )

    st.markdown('</div></div>', unsafe_allow_html=True)

    ocr_full = ev.get("ocr_text", "")
    if ocr_full:
        st.markdown('<div class="ev-detail-section"><h4>OCR Extracted Text</h4>', unsafe_allow_html=True)
        st.markdown(f'<div class="ev-detail-ocr">{ocr_full}</div>', unsafe_allow_html=True)

        urls = ev.get("detected_urls", "[]")
        try:
            url_list = json.loads(urls) if isinstance(urls, str) else urls
        except Exception:
            url_list = []
        if url_list:
            st.markdown('<div style="margin-top:8px;"><span style="font-size:11px;color:#8BA3BE;">🔗 Detected URLs:</span></div>', unsafe_allow_html=True)
            for url in url_list[:5]:
                st.markdown(f'<div style="font-size:12px;color:#1E6DB5;">{url}</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────
# Public Entry Point
# ──────────────────────────────────────────────────────────────────

def render_evidence_repository():
    abort_if_unauthorized("Evidence Repository", st.session_state.get("role"))
    st.markdown(REPO_CSS, unsafe_allow_html=True)

    st.markdown('<h1 style="color:#1E6DB5;margin-bottom:4px;">Evidence Repository</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:#8BA3BE;margin-bottom:24px;">Browse, search, and review all uploaded evidence</p>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        search_term = st.text_input("🔍 Search", placeholder="filename, incident ID, or OCR text...", label_visibility="collapsed")
    with col2:
        type_filter = st.selectbox("Type", ["All", "Video", "Image", "Document"], label_visibility="collapsed")
    with col3:
        sort_order = st.selectbox("Sort", ["Newest First", "Oldest First"], label_visibility="collapsed")

    type_map = {"All": None, "Video": "video", "Image": "image", "Document": "application"}
    filters = {
        "search": search_term if search_term else None,
        "file_type": type_map.get(type_filter),
    }

    evidence_list = _fetch_evidence(filters)

    if sort_order == "Oldest First":
        evidence_list.reverse()

    if not evidence_list:
        st.markdown("""
        <div class="ev-empty">
            <div class="icon">📭</div>
            <div>No evidence found matching your criteria</div>
        </div>
        """, unsafe_allow_html=True)
        return

    left_col, right_col = st.columns([3, 2])

    with left_col:
        st.markdown('<div class="ev-grid">', unsafe_allow_html=True)
        for ev in evidence_list:
            _render_card(ev, selected=(st.session_state.get("selected_evidence") == ev["evidence_id"]))
            if st.button("View Details", key=f"select_{ev['evidence_id']}", use_container_width=True):
                st.session_state["selected_evidence"] = ev["evidence_id"]
                st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    with right_col:
        selected_id = st.session_state.get("selected_evidence")
        selected_ev = next((e for e in evidence_list if e["evidence_id"] == selected_id), None)
        _render_detail_panel(selected_ev)
