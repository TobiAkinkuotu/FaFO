import streamlit as st
import sqlite3
import pandas as pd
from config.settings import DATABASE_PATH
from database.connection import get_db_connection
from modules.export_manager import render_export_panel
from modules.audit_logger import log_action
from modules.ai_classifier import ensure_ai_analysis_schema
from modules.rbac import abort_if_unauthorized

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


# ─── Colour tokens ────────────────────────────────────────────────────────────
BG       = "#0A1118"
CARD     = "#112236"
BLUE     = "#1A73E8"
BORDER   = "#1A3A5C"
TEXT     = "#E8F0FE"
MUTED    = "#8BA3BE"

STATUS_COLOURS = {
    "confirmed": {"text": "#1A7A4A", "bg": "#0A2E1C"},
    "disputed":  {"text": "#C0392B", "bg": "#2E0A0A"},
    "pending":   {"text": "#D4AC0D", "bg": "#2E280A"},
    "open":      {"text": "#1E6DB5", "bg": "#0A1E2E"},
    "closed":    {"text": "#8BA3BE", "bg": "#1A2A3A"},
    "critical":  {"text": "#E67E22", "bg": "#2E1A0A"},
}


def _status_badge(status: str) -> str:
    s = (status or "").lower()
    colours = STATUS_COLOURS.get(s, {"text": BLUE, "bg": "#0A1E2E"})
    return (
        f'<span style="background:{colours["bg"]};color:{colours["text"]};'
        f'font-size:11px;font-weight:600;padding:3px 10px;border-radius:20px;'
        f'border:1px solid {colours["text"]}33;white-space:nowrap;">'
        f'{status.capitalize() if status else "Unknown"}</span>'
    )


def _db_query(query: str, params=(), fetchone=False):
    """Execute a query and return results, handling missing tables gracefully."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute(query, params)
        result = cursor.fetchone() if fetchone else cursor.fetchall()
        conn.close()
        return result
    except Exception:
        return None if fetchone else []


def _db_df(query: str, params=()):
    """Return a DataFrame from a query, empty DataFrame on error."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def fetch_recent_incidents(limit: int = 20):
    """Return recent incidents using only real schema columns."""
    try:
        conn = get_db_connection(str(DATABASE_PATH))
        conn.row_factory = sqlite3.Row
        # Join with users to get the submitting username for display
        rows = [dict(row) for row in conn.execute(
            "SELECT i.incident_id, i.created_at, i.status, i.severity, i.created_by, u.username as submitted_by "
            "FROM incidents i LEFT JOIN users u ON i.created_by = u.id "
            "ORDER BY i.created_at DESC LIMIT ?",
            (limit,),
        )]
        conn.close()
        return rows
    except Exception:
        return []


def render_dashboard():
    abort_if_unauthorized("Dashboard", st.session_state.get("role"))
    # ── CSS injected once per render ──────────────────────────────────────────
    st.markdown("""
    <style>
      .metric-card {
        background: #112236;
        border-radius: 12px;
        padding: 20px 24px;
        border-left: 3px solid #1A73E8;
        min-height: 110px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        box-shadow: 0 2px 16px rgba(0,0,0,0.25);
      }
      .metric-top {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #8BA3BE;
        font-size: 13px;
        font-weight: 500;
        margin-bottom: 8px;
      }
      .metric-icon { font-size: 18px; }
      .metric-value {
        font-size: 36px;
        font-weight: 700;
        color: #E8F0FE;
        line-height: 1;
        margin-bottom: 6px;
      }
      .metric-trend-green {
        font-size: 12px;
        color: #27AE60;
        font-weight: 500;
      }
      .metric-trend-amber {
        font-size: 12px;
        color: #D4AC0D;
        font-weight: 500;
      }
      .section-header {
        font-size: 18px;
        font-weight: 700;
        color: #E8F0FE;
        margin: 28px 0 14px 0;
        padding-bottom: 8px;
        border-bottom: 1px solid #1A3A5C;
      }
      .incidents-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        background: #112236;
        border-radius: 12px;
        overflow: hidden;
        font-size: 13px;
      }
      .incidents-table thead tr {
        background: #0A1118;
      }
      .incidents-table thead th {
        color: #8BA3BE;
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid #1A3A5C;
      }
      .incidents-table tbody tr {
        background: #112236;
        transition: background 0.15s ease;
      }
      .incidents-table tbody tr:nth-child(even) {
        background: #152840;
      }
      .incidents-table tbody tr:hover {
        background: #1A3A5C;
      }
      .incidents-table tbody td {
        color: #E8F0FE;
        padding: 11px 16px;
        border-bottom: 1px solid #1A2A3A;
        vertical-align: middle;
      }
      .inc-id {
        font-family: monospace;
        color: #1A73E8;
        font-size: 12px;
        font-weight: 600;
      }
      .chart-container {
        background: #112236;
        border-radius: 12px;
        padding: 6px;
        border: 1px solid #1A3A5C;
      }
    </style>
    """, unsafe_allow_html=True)

    # State management for detail view
    if "selected_incident" not in st.session_state:
        st.session_state["selected_incident"] = None

    if st.session_state["selected_incident"] is None:
        _render_overview()
    else:
        _render_detail_view(st.session_state["selected_incident"])


def _render_overview():
    # ── 1. Metric KPI cards ───────────────────────────────────────────────────
    total_row    = _db_query("SELECT COUNT(*) FROM incidents", fetchone=True)
    open_row     = _db_query("SELECT COUNT(*) FROM incidents WHERE status IN ('pending','under_review','approved','escalated')", fetchone=True)
    evidence_row = _db_query("SELECT COUNT(*) FROM evidence", fetchone=True)
    pending_row  = _db_query("SELECT COUNT(*) FROM incidents WHERE status IN ('pending','under_review')", fetchone=True)

    total    = total_row[0]    if total_row    else 0
    open_c   = open_row[0]     if open_row     else 0
    evidence = evidence_row[0] if evidence_row else 0
    pending  = pending_row[0]  if pending_row  else 0

    cards = [
        {"icon": "📋", "label": "Total Incidents",  "value": total,    "trend": f"▲ {total} records",    "cls": "metric-trend-green"},
        {"icon": "📂", "label": "Open Cases",        "value": open_c,   "trend": f"▲ Active cases",        "cls": "metric-trend-green"},
        {"icon": "🗂️",  "label": "Evidence Files",   "value": evidence, "trend": f"▲ Files indexed",       "cls": "metric-trend-green"},
        {"icon": "⏳",  "label": "Pending Review",   "value": pending,  "trend": "Pending",                 "cls": "metric-trend-amber"},
    ]

    cols = st.columns(4)
    for col, card in zip(cols, cards):
        with col:
            st.markdown(f"""
            <div class="metric-card">
              <div class="metric-top">
                <span class="metric-icon">{card['icon']}</span>
                <span>{card['label']}</span>
              </div>
              <div class="metric-value">{card['value']:,}</div>
              <div class="{card['cls']}">{card['trend']}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)

    # ── 2. Charts row ─────────────────────────────────────────────────────────
    chart_left, chart_right = st.columns([6, 4])

    with chart_left:
        st.markdown('<div class="section-header">📊 Incidents by Month</div>', unsafe_allow_html=True)
        df_monthly = _db_df(
            "SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count "
            "FROM incidents GROUP BY month ORDER BY month DESC LIMIT 12"
        )

        if PLOTLY_AVAILABLE:
            if not df_monthly.empty:
                df_monthly = df_monthly.iloc[::-1].reset_index(drop=True)
                fig = go.Figure()
                fig.add_trace(go.Bar(
                    x=df_monthly["month"],
                    y=df_monthly["count"],
                    marker_color=BLUE,
                    marker_line_width=0,
                    hovertemplate="<b>%{x}</b><br>Incidents: %{y}<extra></extra>",
                ))
                fig.update_layout(
                    paper_bgcolor=CARD,
                    plot_bgcolor=CARD,
                    font=dict(color=TEXT, family="Inter, sans-serif", size=12),
                    margin=dict(l=12, r=12, t=12, b=12),
                    xaxis=dict(
                        showgrid=False, zeroline=False,
                        tickfont=dict(color=MUTED, size=11),
                        linecolor=BORDER,
                    ),
                    yaxis=dict(
                        showgrid=False, zeroline=False,
                        tickfont=dict(color=MUTED, size=11),
                        linecolor=BORDER,
                    ),
                    bargap=0.35,
                    height=260,
                )
                st.markdown('<div class="chart-container">', unsafe_allow_html=True)
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="chart-container" style="display:flex;align-items:center;justify-content:center;height:260px;color:{MUTED};font-size:13px;">
                  No incident data yet
                </div>""", unsafe_allow_html=True)
        else:
            st.info("Install plotly (`python3 -m pip install plotly`) to enable charts.")

    with chart_right:
        st.markdown('<div class="section-header">🍩 Cases by Status</div>', unsafe_allow_html=True)
        df_status = _db_df("SELECT status, COUNT(*) as count FROM incidents GROUP BY status")

        if PLOTLY_AVAILABLE:
            if not df_status.empty:
                status_colour_map = {
                    "approved":     "#27AE60",
                    "escalated":    "#C0392B",
                    "critical":     "#E67E22",
                    "pending":      "#D4AC0D",
                    "under_review": "#8E44AD",
                    "closed":       MUTED,
                }
                colours = [status_colour_map.get(s.lower(), BLUE) for s in df_status["status"]]
                fig2 = go.Figure(go.Pie(
                    labels=df_status["status"].str.capitalize(),
                    values=df_status["count"],
                    hole=0.55,
                    marker=dict(colors=colours, line=dict(color=BG, width=2)),
                    textfont=dict(size=11, color=TEXT),
                    hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
                ))
                fig2.update_layout(
                    paper_bgcolor=CARD,
                    plot_bgcolor=CARD,
                    font=dict(color=TEXT, family="Inter, sans-serif", size=12),
                    margin=dict(l=12, r=12, t=12, b=12),
                    showlegend=True,
                    legend=dict(
                        font=dict(color=TEXT, size=11),
                        bgcolor="rgba(0,0,0,0)",
                        orientation="v",
                        x=1.02, y=0.5,
                    ),
                    height=260,
                )
                st.markdown('<div class="chart-container">', unsafe_allow_html=True)
                st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="chart-container" style="display:flex;align-items:center;justify-content:center;height:260px;color:{MUTED};font-size:13px;">
                  No incident data yet
                </div>""", unsafe_allow_html=True)
        else:
            st.info("Install plotly to enable charts.")

    # ── 3. Recent Incidents table ──────────────────────────────────────────────
    st.markdown('<div class="section-header">🗃️ Recent Incidents</div>', unsafe_allow_html=True)

    df_recent = pd.DataFrame(fetch_recent_incidents(20))

    if df_recent.empty:
        st.markdown(f"""
        <div style="background:{CARD};border-radius:12px;padding:32px;text-align:center;color:{MUTED};font-size:14px;border:1px solid {BORDER};">
          No incidents recorded yet. Submit the first incident to get started.
        </div>""", unsafe_allow_html=True)
    else:
        # Use a DataFrame display instead of raw HTML to avoid Streamlit escaping
        display_df = df_recent.copy()
        display_df["Date"] = display_df["created_at"].astype(str).str[:10].fillna("—")
        display_df["Incident ID"] = display_df["incident_id"].fillna("—")
        display_df["Status"] = display_df["status"].fillna("—")
        display_df["Priority"] = display_df["severity"].fillna("—").apply(lambda s: str(s).capitalize())
        # Use the joined username (`submitted_by`) when available, fallback to id
        display_df["Submitted By"] = display_df.get("submitted_by")
        if display_df["Submitted By"] is None:
            display_df["Submitted By"] = display_df["created_by"].fillna("—")
        else:
            display_df["Submitted By"] = display_df["Submitted By"].fillna("—")
        display_df = display_df[["Incident ID", "Date", "Status", "Priority", "Submitted By"]]

        st.dataframe(display_df, use_container_width=True, hide_index=True)

    st.markdown("<div style='margin-top:24px;'></div>", unsafe_allow_html=True)

    # ── 4. Incident selector for detail view ──────────────────────────────────
    if not df_recent.empty:
        st.markdown('<div class="section-header">🔍 Inspect Incident</div>', unsafe_allow_html=True)
        col_sel, col_btn = st.columns([4, 1])
        with col_sel:
            selected_id = st.selectbox(
                "Select an Incident ID to view full details:",
                [""] + df_recent["incident_id"].tolist(),
                label_visibility="collapsed",
            )
        with col_btn:
            if st.button("View Details →", use_container_width=True) and selected_id:
                st.session_state["selected_incident"] = selected_id
                st.rerun()


# ─── Detail View (preserved from original) ────────────────────────────────────
def _render_detail_view(incident_id: str):
    conn = get_db_connection(str(DATABASE_PATH))

    try:
        if st.button("← Back to Dashboard"):
            st.session_state["selected_incident"] = None
            st.rerun()

        st.title(f"Case File: {incident_id}")

        cursor = conn.cursor()
        cursor.execute(
            "SELECT category, severity, status, target, description, source_url, created_at "
            "FROM incidents WHERE incident_id = ?",
            (incident_id,)
        )
        incident = cursor.fetchone()

        if not incident:
            st.error("Incident not found.")
            return

        category, severity, status, target, description, url, created_at = incident

        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"**Submitted:** {created_at} | **Target:** {target} | **URL:** {url}")
        with col2:
            statuses = ["pending", "under_review", "approved", "closed", "escalated"]
            idx = statuses.index(status) if status in statuses else 0
            new_status = st.selectbox("Status", statuses, index=idx)
            if new_status != status:
                cursor.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (new_status, incident_id))
                conn.commit()
                log_action(
                    st.session_state.get("user_id", 1),
                    st.session_state.get("username", "system"),
                    "INCIDENT_UPDATED", "incident", incident_id
                )
                st.success("Status updated!")
                st.rerun()

        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
            "Overview", "Evidence Vault", "Forensics & OCR",
            "AI Investigator Copilot", "Export", "Internal Discussion",
            "Chain of Custody"
        ])

        with tab1:
            st.subheader("Description")
            st.write(description)
            st.write("---")
            st.subheader("AI Analysis")
            ensure_ai_analysis_schema()

            ai_df = pd.read_sql_query(
                "SELECT analysis_id, suggested_category, suggested_severity, "
                "threat_score, ai_confidence, analysis_method, analysis_status, "
                "analysis_details, reviewed_by_human, reviewer_notes, created_at "
                "FROM ai_analysis WHERE incident_id = ? "
                "ORDER BY created_at DESC",
                conn, params=(incident_id,)
            )
            if not ai_df.empty:
                latest = ai_df.iloc[0]
                status_label = latest["analysis_status"] or "unknown"
                if status_label != "completed":
                    st.warning(f"AI analysis is currently {status_label}. Full results may be pending.")
                else:
                    st.success("✅ AI analysis completed.")

                st.markdown("#### AI Summary")
                st.write(f"**Suggested Category:** {latest['suggested_category']}")
                st.write(f"**Suggested Severity:** {latest['suggested_severity']}")
                st.write(f"**Threat Score:** {latest['threat_score']:.2f}")
                st.write(f"**Confidence:** {latest['ai_confidence']:.1f}%")
                st.write(f"**Model:** {latest['analysis_method'] or 'heuristic'}")
                st.write(f"**Status:** {status_label.capitalize()}")

                short_details = (latest["analysis_details"] or "").strip().split("\n")[0]
                st.info(short_details or "AI reasoning summary is not available yet.")

                with st.expander("Expand AI reasoning and full details"):
                    if latest["analysis_details"]:
                        st.write(latest["analysis_details"])
                    else:
                        st.write("No additional AI details are available yet.")

                if latest["analysis_status"] == "completed":
                    if not latest["reviewed_by_human"]:
                        if st.button("Approve AI Findings"):
                            cursor.execute(
                                "UPDATE ai_analysis SET reviewed_by_human = 1, approved_by = ? WHERE analysis_id = ?",
                                (st.session_state.get("user_id", 1), latest["analysis_id"])
                            )
                            conn.commit()
                            log_action(
                                st.session_state.get("user_id", 1),
                                st.session_state.get("username", "system"),
                                "AI_ANALYSIS_APPROVED", "incident", incident_id
                            )
                            st.success("AI Findings approved and added to official record.")
                            st.rerun()
                    else:
                        st.success("✅ AI Findings have been reviewed and approved by a human.")
                else:
                    st.info("Human review is locked until AI analysis reaches completion.")

                if len(ai_df) > 1:
                    with st.expander("AI analysis history"):
                        history_df = ai_df.copy()
                        history_df["created_at"] = pd.to_datetime(history_df["created_at"])
                        st.dataframe(history_df[["created_at", "analysis_method", "analysis_status", "suggested_category", "suggested_severity", "threat_score", "ai_confidence"]], use_container_width=True)
            else:
                st.info("No AI analysis is available yet. The system will analyze the incident after submission and evidence upload.")

        with tab2:
            st.subheader("Uploaded Evidence")
            ev_df = pd.read_sql_query(
                "SELECT filename, file_type, file_size, file_hash, uploaded_at FROM evidence WHERE incident_id = ?",
                conn, params=(incident_id,)
            )
            if not ev_df.empty:
                st.dataframe(ev_df, use_container_width=True)
            else:
                st.write("No evidence uploaded yet.")

        with tab3:
            st.subheader("OCR & Technical Extractions")
            ocr_df = pd.read_sql_query(
                "SELECT extracted_text, confidence_score, detected_threats FROM ocr_results WHERE incident_id = ?",
                conn, params=(incident_id,)
            )
            if not ocr_df.empty:
                for idx, row in ocr_df.iterrows():
                    with st.expander(f"OCR Extraction {idx+1} (Confidence: {row['confidence_score']:.2f})"):
                        st.write(row["extracted_text"])
                        if row["detected_threats"] and row["detected_threats"] != "[]":
                            st.warning(f"Threats Detected: {row['detected_threats']}")
            else:
                st.write("No OCR extractions found.")

        with tab4:
            st.subheader("AI Case Investigator Copilot")
            st.write("Ask the FAFO AI Copilot about this case, evidence files, OCR extractions, and threat factors.")

            from modules.ai_copilot import get_copilot_response
            chat_key = f"chat_{incident_id}"
            if chat_key not in st.session_state:
                st.session_state[chat_key] = [
                    {
                        "role": "assistant",
                        "content": (
                            f"Hello, I am the FAFO Case Investigator Copilot. I have analyzed the evidence and "
                            f"metadata for case {incident_id}. Ask me any questions about the threat level, "
                            f"extracted text, entities, or legal relevance of this incident."
                        )
                    }
                ]

            for msg in st.session_state[chat_key]:
                with st.chat_message(msg["role"]):
                    st.write(msg["content"])

            if prompt := st.chat_input("Query the evidence (e.g. 'What threats were found in OCR?', 'Identify key entities')"):
                with st.chat_message("user"):
                    st.write(prompt)
                st.session_state[chat_key].append({"role": "user", "content": prompt})
                with st.spinner("Analyzing case data..."):
                    response = get_copilot_response(conn, incident_id, prompt)
                with st.chat_message("assistant"):
                    st.write(response)
                st.session_state[chat_key].append({"role": "assistant", "content": response})
                st.rerun()

        with tab5:
            render_export_panel(incident_id)

        with tab6:
            st.subheader("Internal Team Discussion")
            st.write("Secure, timestamped notes and chat for the incident review team.")

            from modules.communication import get_communications, add_communication

            messages = get_communications(incident_id)
            for msg in messages:
                with st.chat_message("assistant" if msg["is_alert"] else "user"):
                    st.write(f"**{msg['sender_name']}** ({msg['timestamp']})")
                    st.write(msg["message"])

            if chat_msg := st.chat_input("Add a note or message to this case..."):
                user_id = st.session_state.get("user_id", 1)
                sender_name = st.session_state.get("username", "system")
                add_communication(incident_id, user_id, sender_name, chat_msg)
                log_action(user_id, sender_name, "COMMUNICATION_ADDED", "incident", incident_id)
                st.rerun()

        with tab7:
            st.subheader("Chain of Custody")
            st.write("Immutable audit trail for all access, edits, and file hashes related to this case.")

            # 1. Audit Logs for this incident
            st.markdown("**Incident Audit Trail**")
            logs_df = pd.read_sql_query(
                "SELECT timestamp, u.username, action, target_id FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id WHERE target_type = 'incident' AND target_id = ? ORDER BY timestamp DESC",
                conn, params=(incident_id,)
            )
            if not logs_df.empty:
                st.dataframe(logs_df, use_container_width=True)
            else:
                st.write("No audit logs found for this incident.")

            st.write("---")

            # 2. Evidence Hashes
            st.markdown("**Cryptographic Hashes (SHA-256)**")
            hashes_df = pd.read_sql_query(
                "SELECT filename, file_hash, uploaded_at, u.username as uploaded_by FROM evidence e LEFT JOIN users u ON e.uploaded_by = u.id WHERE incident_id = ?",
                conn, params=(incident_id,)
            )
            if not hashes_df.empty:
                st.dataframe(hashes_df, use_container_width=True)
            else:
                st.write("No evidence hashes found.")
    finally:
        conn.close()
