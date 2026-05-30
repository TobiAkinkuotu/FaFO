import streamlit as st
import sqlite3
import pandas as pd
from config.settings import DATABASE_PATH
from database.connection import get_db_connection
from modules.auth import create_user
from modules.rbac import abort_if_unauthorized

ADMIN_CSS = """
<style>
/* Global */
[data-testid="stAppViewContainer"] { background-color: #0A1118; }
[data-testid="stSidebar"] { background-color: #0A1118; }
.block-container { padding: 32px !important; max-width: 100% !important; }

/* 1. Layout Overrides */
div[data-testid="column"]:nth-child(1) {
    max-width: 200px !important;
}
/* Gap handled by Streamlit column spacing roughly, but we can override if needed */

/* 2. Left Tabs */
.vertical-menu-item {
    height: 40px;
    padding: 0 16px;
    display: flex;
    align-items: center;
    font-size: 14px;
    color: #9AA0A6;
    border-radius: 6px;
    margin-bottom: 8px;
    background-color: transparent;
}
.vertical-menu-item.active {
    background-color: #1A73E8;
    color: #FFFFFF;
}

/* 3. Main Area */
.main-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
}
.main-title {
    font-size: 20px;
    font-weight: 600;
    color: #E8F0FE;
}

/* Table */
.admin-table {
    width: 100%;
    border-collapse: collapse;
    color: #E8F0FE;
    font-size: 14px;
}
.admin-table th {
    text-align: left;
    padding: 12px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    color: #9AA0A6;
    font-weight: 500;
}
.admin-table td {
    padding: 12px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}
.admin-table tr:hover {
    background-color: rgba(255, 255, 255, 0.02);
}

/* Badges */
.role-badge {
    padding: 4px 8px;
    border-radius: 100px;
    font-size: 12px;
    font-weight: 600;
}
.role-admin { background-color: rgba(217, 48, 37, 0.1); color: #D93025; }
.role-reviewer { background-color: rgba(26, 115, 232, 0.1); color: #1A73E8; }
.role-other { background-color: rgba(255, 255, 255, 0.1); color: #E8F0FE; }

.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 100px;
    font-size: 12px;
    font-weight: 500;
    background-color: rgba(255, 255, 255, 0.05);
}
.dot { width: 8px; height: 8px; border-radius: 50%; }
.dot-active { background-color: #1E8E3E; }
.dot-inactive { background-color: #9AA0A6; }

/* Buttons */
.action-btn {
    background-color: transparent;
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #E8F0FE;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 12px;
    cursor: pointer;
    margin-right: 8px;
}
</style>
"""

def render_admin_panel():
    abort_if_unauthorized("Admin Panel", st.session_state.get("role"))
    st.markdown(ADMIN_CSS, unsafe_allow_html=True)

    if "admin_tab" not in st.session_state:
        st.session_state.admin_tab = "Users"

    left_col, right_col = st.columns([1, 4])

    with left_col:
        tabs = ["Users", "Audit Logs", "System Config"]
        for tab in tabs:
            active_cls = "active" if st.session_state.admin_tab == tab else ""
            st.markdown(f'<div class="vertical-menu-item {active_cls}">{tab}</div>', unsafe_allow_html=True)
            if st.button(f"Go {tab}", key=f"btn_{tab}", use_container_width=True):
                st.session_state.admin_tab = tab
                st.rerun()

    with right_col:
        if st.session_state.admin_tab == "Users":
            st.markdown("""
            <div class="main-header">
                <div class="main-title">Users</div>
            </div>
            """, unsafe_allow_html=True)

            with st.expander("Add New User", expanded=False):
                with st.form("create_user_form"):
                    c1, c2 = st.columns(2)
                    with c1:
                        new_username = st.text_input("Username", key="new_user_username")
                        new_email = st.text_input("Email", key="new_user_email")
                    with c2:
                        new_role = st.selectbox("Role", ["submitter", "reviewer", "lawyer", "admin"], index=0, key="new_user_role")
                        new_password = st.text_input("Password", type="password", key="new_user_password")

                    if st.form_submit_button("Create User"):
                        success, message = create_user(new_username.strip(), new_password, new_role, new_email.strip())
                        if success:
                            st.success(message)
                        else:
                            st.error(message)

            try:
                conn = get_db_connection(str(DATABASE_PATH))
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT username, email, role, status, last_login FROM users ORDER BY username"
                ).fetchall()
                conn.close()
                users = [dict(r) for r in rows]
            except Exception:
                users = []

            if users:
                df_users = pd.DataFrame(users)
                df_users["Role"] = df_users["role"].fillna("—").str.capitalize()
                df_users["Status"] = df_users["status"].fillna("—").str.capitalize()
                df_users["Last Login"] = df_users["last_login"].fillna("—")
                df_users["Username"] = df_users["username"].fillna("—")
                df_users["Email"] = df_users["email"].fillna("—")
                display_users = df_users[["Username", "Email", "Role", "Status", "Last Login"]]
                st.dataframe(display_users, use_container_width=True, hide_index=True)
            else:
                st.info("No users found in the database.")

        elif st.session_state.admin_tab == "Audit Logs":
            st.markdown('<div class="main-title">Audit Logs</div>', unsafe_allow_html=True)
            try:
                conn = get_db_connection(str(DATABASE_PATH))
                logs_df = pd.read_sql_query(
                    "SELECT timestamp AS Timestamp, username AS User, action AS Action, target_type AS TargetType, target_id AS TargetID "
                    "FROM audit_logs ORDER BY timestamp DESC LIMIT 200",
                    conn,
                )
                conn.close()
                if logs_df.empty:
                    st.info("No audit logs found.")
                else:
                    st.dataframe(logs_df, use_container_width=True, hide_index=True)
            except Exception as exc:
                st.error(f"Database error: {exc}")
        
        elif st.session_state.admin_tab == "System Config":
            st.markdown('<div class="main-title">System Configuration</div>', unsafe_allow_html=True)
            try:
                conn = get_db_connection(str(DATABASE_PATH))
                cursor = conn.cursor()
                total_users = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                active_users = cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
                total_incidents = cursor.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                total_evidence = cursor.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
                active_sessions = cursor.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
                role_counts = pd.read_sql_query(
                    "SELECT role AS Role, COUNT(*) AS Count FROM users GROUP BY role",
                    conn,
                )
                conn.close()

                summary_df = pd.DataFrame([
                    {"Metric": "Total Users", "Value": total_users},
                    {"Metric": "Active Users", "Value": active_users},
                    {"Metric": "Total Incidents", "Value": total_incidents},
                    {"Metric": "Total Evidence Files", "Value": total_evidence},
                    {"Metric": "Active Sessions", "Value": active_sessions},
                ])
                st.dataframe(summary_df, use_container_width=True, hide_index=True)
                if not role_counts.empty:
                    st.markdown("**Users by Role**")
                    st.dataframe(role_counts, use_container_width=True, hide_index=True)
            except Exception as exc:
                st.error(f"Database error: {exc}")
