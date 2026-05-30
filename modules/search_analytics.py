import streamlit as st
import sqlite3
import pandas as pd
import zipfile
import io
from pathlib import Path
from config.settings import DATABASE_PATH
from modules.rbac import abort_if_unauthorized

# ---------------------------------------------------------------------------
# Theme CSS (Matching Page 5 specs exactly)
# ---------------------------------------------------------------------------

THEME_CSS = """
<style>
/* Reset and background */
[data-testid="stAppViewContainer"] { background-color: #0A1118; }
[data-testid="stSidebar"] { background-color: #0A1118; }

/* 1. Container */
.search-export-container {
    width: 100%;
    background-color: #112236;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
}

/* Override Streamlit padding to fit container styling better */
.block-container { padding-top: 2rem; padding-bottom: 2rem; }

/* 2. Search & Filters Bar */
/* Top Row (Search) */
div[data-testid="stTextInput"] input {
    height: 48px !important;
    background-color: #070C12 !important;
    color: #E8F0FE !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    border-radius: 8px !important;
    padding: 0 16px 0 40px !important; /* space for search icon if needed */
    font-size: 14px;
}

/* Bottom Row (Filters) */
div[data-testid="stSelectbox"] > div {
    height: 40px !important;
    background-color: #070C12 !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    border-radius: 6px !important;
    font-size: 13px !important;
    color: #9AA0A6 !important;
    min-height: 40px !important;
}

/* Date Input (Using Text Input instead of Date Input as requested) */
div[data-testid="stTextInput"] label, div[data-testid="stSelectbox"] label {
    font-size: 13px !important;
    color: #9AA0A6 !important;
    margin-bottom: 4px !important;
}

/* 3. Data Table */
.data-table-wrapper {
    width: 100%;
    overflow-x: auto;
    margin-top: 24px;
}
.data-table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Inter', sans-serif;
    color: #E8F0FE;
    font-size: 14px;
}
.data-table th {
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    padding: 12px 16px;
    text-align: left;
    font-weight: 600;
    color: #9AA0A6;
    font-size: 13px;
}
.data-table tbody tr:nth-child(odd) { background-color: #112236; }
.data-table tbody tr:nth-child(even) { background-color: #142840; }
.data-table td {
    padding: 12px 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

/* Status Badges */
.status-badge {
    padding: 4px 8px;
    border-radius: 100px;
    font-size: 12px;
    font-weight: 600;
    display: inline-block;
    text-align: center;
}
.status-open { background-color: rgba(26, 115, 232, 0.2); color: #1A73E8; border: 1px solid #1A73E8; }
.status-closed { background-color: rgba(30, 142, 62, 0.2); color: #1E8E3E; border: 1px solid #1E8E3E; }
.status-pending { background-color: rgba(244, 180, 0, 0.2); color: #F4B400; border: 1px solid #F4B400; }
.status-default { background-color: rgba(255, 255, 255, 0.1); color: #E8F0FE; border: 1px solid rgba(255, 255, 255, 0.2); }

/* Custom Checkbox */
.custom-checkbox {
    width: 16px;
    height: 16px;
    background-color: #070C12;
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 4px;
    display: inline-block;
}

/* 4. Export Footer */
.export-footer {
    display: flex;
    justify-content: flex-end;
    gap: 16px;
    margin-top: 24px;
}
</style>
"""

def _status_badge(status: str) -> str:
    s = (status or "").lower()
    if s == "open":
        return f'<span class="status-badge status-open">Open</span>'
    elif s == "closed":
        return f'<span class="status-badge status-closed">Closed</span>'
    elif s in ("pending", "under_review", "escalated"):
        return f'<span class="status-badge status-pending">{s.replace("_", " ").title()}</span>'
    else:
        return f'<span class="status-badge status-default">{s.replace("_", " ").title()}</span>'

def render_search_analytics():
    st.markdown(THEME_CSS, unsafe_allow_html=True)
    
    st.markdown('<div class="search-export-container">', unsafe_allow_html=True)

    # 1. & 2. Search & Filters Bar
    search_query = st.text_input(
        "Search",
        placeholder="🔍 Search...",
        label_visibility="collapsed"
    )

    f1, f2, f3, f4, f5 = st.columns(5)
    with f1:
        date_from = st.text_input("Date From (YYYY-MM-DD)", placeholder="2025-01-01", key="sa_date_from")
    with f2:
        date_to = st.text_input("Date To (YYYY-MM-DD)", placeholder="2025-12-31", key="sa_date_to")
    with f3:
        status_filter = st.selectbox("Status", ["All", "pending", "open", "closed", "escalated", "under_review", "approved"], key="sa_status")
    with f4:
        severity_filter = st.selectbox("Severity", ["All", "low", "medium", "high", "critical"], key="sa_severity")
    with f5:
        type_filter = st.selectbox("Incident Type", ["All", "Cyberbullying", "Harassment", "Defamation", "Threats", "Hate Speech", "Doxxing", "Fraud", "Privacy Violation"], key="sa_type")

    # DB Query
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row

        query = """
            SELECT DISTINCT
                i.incident_id, i.severity, i.status, i.created_at, i.category, u.username AS submitted_by
            FROM incidents i
            LEFT JOIN users u ON i.created_by = u.id
            WHERE 1=1
        """
        params: list = []

        if search_query:
            like = f"%{search_query}%"
            query += " AND (i.incident_id LIKE ? OR i.description LIKE ? OR u.username LIKE ? OR i.category LIKE ?)"
            params.extend([like, like, like, like])

        if status_filter != "All":
            query += " AND i.status = ?"
            params.append(status_filter)

        if severity_filter != "All":
            query += " AND i.severity = ?"
            params.append(severity_filter)

        if type_filter != "All":
            query += " AND i.category = ?"
            params.append(type_filter)

        if date_from:
            query += " AND DATE(i.created_at) >= ?"
            params.append(str(date_from))

        if date_to:
            query += " AND DATE(i.created_at) <= ?"
            params.append(str(date_to))

        query += " ORDER BY i.created_at DESC"
        cursor = conn.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
    except Exception as e:
        st.error(f"Database error: {e}")
        return

    # 3. Data Table
    if rows:
        df_result = pd.DataFrame(rows)
        df_result["Date"] = df_result["created_at"].astype(str).str[:10].fillna("—")
        df_result["Severity"] = df_result["severity"].fillna("—").str.capitalize()
        df_result["Assigned To"] = df_result["submitted_by"].fillna("—")
        df_result["Status"] = df_result["status"].fillna("—").str.replace("_", " ").str.capitalize()
        df_result["Case ID"] = df_result["incident_id"].fillna("—")
        display_df = df_result[["Case ID", "Date", "Severity", "Assigned To", "Status"]]

        st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.info("No results found.")

    # 4. Export Footer
    st.markdown('<div class="export-footer">', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1, 3])
    with col1:
        if rows:
            df_export = pd.DataFrame(rows)
            csv_data = df_export.to_csv(index=False).encode("utf-8")
            st.download_button(label="Export CSV", data=csv_data, file_name="export.csv", mime="text/csv", use_container_width=True)
        else:
            st.button("Export CSV", disabled=True, use_container_width=True)
    with col2:
        st.button("Export PDF", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)
