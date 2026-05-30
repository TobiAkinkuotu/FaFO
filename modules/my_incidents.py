"""
my_incidents.py — Submitter's personal incident view.
Shows only incidents created by the currently logged-in user.
"""

import streamlit as st
import sqlite3
import pandas as pd
from app_config.settings import DATABASE_PATH
from modules.rbac import abort_if_unauthorized

# ── Colour tokens ──────────────────────────────────────────────────────────────
BG     = "#0D1B2A"
CARD   = "#112236"
BLUE   = "#1E6DB5"
BORDER = "#1A3A5C"
TEXT   = "#EAF1F8"
MUTED  = "#8BA3BE"

STATUS_COLOURS = {
    "pending":      {"text": "#FFC857", "bg": "#3D2A00"},
    "under_review": {"text": "#FFC857", "bg": "#3D2A00"},
    "approved":     {"text": "#4DD89A", "bg": "#0F3625"},
    "closed":       {"text": "#8BA3BE", "bg": "#1A2A3A"},
    "escalated":    {"text": "#FF6B6B", "bg": "#3D0F0F"},
}

SEVERITY_COLOURS = {
    "critical": "#E67E22",
    "high":     "#C0392B",
    "medium":   "#D4AC0D",
    "low":      "#27AE60",
}


def _badge(status: str) -> str:
    s = (status or "").lower()
    c = STATUS_COLOURS.get(s, {"text": BLUE, "bg": "#0A1E2E"})
    label = status.replace("_", " ").title() if status else "Unknown"
    return (
        f'<span style="background:{c["bg"]};color:{c["text"]};'
        f'font-size:11px;font-weight:600;padding:3px 10px;border-radius:20px;'
        f'border:1px solid {c["text"]}55;white-space:nowrap;">'
        f'{label}</span>'
    )


def _sev_colour(severity: str) -> str:
    return SEVERITY_COLOURS.get((severity or "").lower(), MUTED)


def render_my_incidents():
    abort_if_unauthorized("My Incidents", st.session_state.get("role"))
    username = st.session_state.get("username", "")
    user_id  = st.session_state.get("user_id")

    # ── CSS ───────────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
      .my-inc-header {
        font-size: 22px; font-weight: 700; color: #EAF1F8;
        margin-bottom: 4px;
      }
      .my-inc-sub {
        font-size: 13px; color: #8BA3BE; margin-bottom: 24px;
      }
      .inc-card {
        background: #112236;
        border: 1px solid #1A3A5C;
        border-left: 4px solid #1E6DB5;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 12px;
        transition: border-color 0.2s;
      }
      .inc-card:hover { border-left-color: #60AAFF; }
      .inc-card-id {
        font-family: monospace; font-size: 12px;
        color: #60AAFF; margin-bottom: 4px;
      }
      .inc-card-title {
        font-size: 15px; font-weight: 600;
        color: #EAF1F8; margin-bottom: 8px;
      }
      .inc-card-meta {
        font-size: 12px; color: #8BA3BE;
        display: flex; gap: 20px; flex-wrap: wrap;
      }
      .no-incidents {
        background: #112236; border: 1px dashed #1A3A5C;
        border-radius: 12px; padding: 48px; text-align: center;
        color: #4A6D8A; font-size: 14px;
      }
      .stat-pill {
        background: #0D1B2A; border: 1px solid #1A3A5C;
        border-radius: 8px; padding: 12px 20px;
        text-align: center;
      }
      .stat-pill-num { font-size: 28px; font-weight: 700; color: #EAF1F8; }
      .stat-pill-label { font-size: 11px; color: #8BA3BE; margin-top: 2px; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="my-inc-header">📋 My Incidents</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="my-inc-sub">All incidents submitted by <strong style="color:#EAF1F8">{username}</strong></div>',
        unsafe_allow_html=True,
    )

    # ── Fetch user's incidents ─────────────────────────────────────────────────
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(
            """SELECT incident_id, category, status, severity, created_at,
                      source_url, target, description
               FROM incidents
               WHERE created_by = ?
               ORDER BY created_at DESC""",
            (user_id if user_id is not None else 0,)
        ).fetchall()]

        # Evidence counts per incident
        ev_counts = {}
        if rows:
            ids = tuple(r["incident_id"] for r in rows)
            placeholder = ",".join("?" * len(ids))
            ev_rows = conn.execute(
                f"SELECT incident_id, COUNT(*) as cnt FROM evidence WHERE incident_id IN ({placeholder}) GROUP BY incident_id",
                ids
            ).fetchall()
            ev_counts = {r[0]: r[1] for r in ev_rows}

        conn.close()
    except Exception as e:
        st.error(f"Database error: {e}")
        return

    # ── Summary stats ──────────────────────────────────────────────────────────
    total    = len(rows)
    open_c   = sum(1 for r in rows if (r.get("status") or "").lower() in ("pending", "under_review", "approved", "escalated"))
    closed_c = sum(1 for r in rows if (r.get("status") or "").lower() == "closed")
    evidence_c = sum(ev_counts.values())

    c1, c2, c3, c4 = st.columns(4)
    for col, num, label in [
        (c1, total,    "Total Submitted"),
        (c2, open_c,   "Open / Pending"),
        (c3, closed_c, "Closed"),
        (c4, evidence_c, "Evidence Files"),
    ]:
        col.markdown(f"""
        <div class="stat-pill">
          <div class="stat-pill-num">{num}</div>
          <div class="stat-pill-label">{label}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<div style='margin-top:24px;'></div>", unsafe_allow_html=True)

    # ── Filter bar ─────────────────────────────────────────────────────────────
    f1, f2, f3 = st.columns([2, 1, 1])
    with f1:
        search = st.text_input("🔍 Search", placeholder="Search by ID, title, or type…", label_visibility="collapsed")
    with f2:
        status_filter = st.selectbox("Status", ["All", "pending", "under_review", "approved", "closed", "escalated"], key="mi_status")
    with f3:
        sev_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"], key="mi_sev")

    st.markdown("<div style='margin-top:12px;'></div>", unsafe_allow_html=True)

    # ── Apply filters ──────────────────────────────────────────────────────────
    filtered = rows
    if search:
        q = search.lower()
        filtered = [r for r in filtered if
                    q in (r.get("incident_id") or "").lower() or
                    q in (r.get("category") or "").lower() or
                    q in (r.get("target") or "").lower()]
    if status_filter != "All":
        filtered = [r for r in filtered if (r.get("status") or "").lower() == status_filter]
    if sev_filter != "All":
        filtered = [r for r in filtered if (r.get("severity") or "").lower() == sev_filter]

    # ── Render cards ───────────────────────────────────────────────────────────
    if not filtered:
        st.markdown("""
        <div class="no-incidents">
          <div style="font-size:40px;margin-bottom:12px;">📭</div>
          No incidents found.<br>
          <span style="font-size:12px;">Try adjusting your filters or submit your first incident.</span>
        </div>""", unsafe_allow_html=True)
        return

    for r in filtered:
        inc_id    = r.get("incident_id", "—")
        # Use description first line as a title (we store [Title] at the top)
        raw_desc  = r.get("description") or ""
        if raw_desc.startswith("["):
            title = raw_desc.split("]")[0].lstrip("[")
        else:
            title = r.get("category") or "Untitled Incident"
        status    = r.get("status", "pending")
        severity  = r.get("severity", "—")
        date_str  = str(r.get("created_at", ""))[:10]
        target    = r.get("target") or "—"
        ev_count  = ev_counts.get(inc_id, 0)
        sev_col   = _sev_colour(severity)

        card_html = f"""
        <div class="inc-card">
          <div class="inc-card-id">{inc_id}</div>
          <div class="inc-card-title">{title}</div>
          <div class="inc-card-meta">
            <span>{_badge(status)}</span>
            <span style="color:{sev_col};font-weight:600;">⚡ {severity.capitalize() if severity else '—'}</span>
            <span>📅 {date_str}</span>
            <span>🎯 {target}</span>
            <span>📎 {ev_count} evidence file(s)</span>
          </div>
        </div>"""
        st.markdown(card_html, unsafe_allow_html=True)

        # Expand button for description
        with st.expander(f"View details — {inc_id}", expanded=False):
            desc = r.get("description") or "No description provided."
            st.markdown(
                f'<div style="background:{BG};border:1px solid {BORDER};border-radius:8px;'
                f'padding:14px;color:{MUTED};font-size:13px;line-height:1.7;">{desc}</div>',
                unsafe_allow_html=True,
            )
            c_a, c_b = st.columns(2)
            with c_a:
                if st.button("📎 Upload Evidence", key=f"ev_btn_{inc_id}", use_container_width=True):
                    st.session_state["active_page"] = "Upload Evidence"
                    st.session_state["upload_incident_id"] = inc_id
                    st.rerun()
