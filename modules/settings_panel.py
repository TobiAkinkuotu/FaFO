"""
settings_panel.py — System settings configuration for Admins.
"""

import streamlit as st
import sqlite3
import json
from config.settings import DATABASE_PATH
from modules.auth import logout_user

# ── CSS ───────────────────────────────────────────────────────────────────
SETTINGS_CSS = """
<style>
.settings-header { font-size:22px; font-weight:700; color:#EAF1F8; margin-bottom:4px; }
.settings-sub    { font-size:13px; color:#8BA3BE; margin-bottom:24px; }
.settings-card {
    background: #112236; border: 1px solid #1A3A5C; border-radius: 10px;
    padding: 20px; margin-bottom: 16px;
}
.settings-card-title {
    font-size: 16px; font-weight: 600; color: #EAF1F8; margin-bottom: 12px;
    display: flex; align-items: center; gap: 8px;
}
.settings-hint { font-size: 12px; color: #8BA3BE; margin-bottom: 16px; }
.settings-account-row {
    display: grid;
    grid-template-columns: minmax(140px, 180px) 1fr;
    gap: 8px 16px;
    font-size: 14px;
    color: #E8F0FE;
    margin-top: 12px;
}
.settings-account-label { color: #8BA3BE; }
.settings-signout {
    width: 100%;
    background: #D93025;
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 12px 16px;
    font-weight: 700;
    cursor: pointer;
    margin-top: 18px;
}
.settings-signout:hover { background: #B22A20; }
</style>
"""


def _get_current_user_info():
    user_id = st.session_state.get("user_id")
    if not user_id:
        return {
            "username": st.session_state.get("username", "Unknown"),
            "role": st.session_state.get("role", "Unknown"),
            "email": "Unknown",
            "status": "Unknown",
        }

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT username, role, email, status FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            username, role, email, status = row
            return {
                "username": username or st.session_state.get("username", "Unknown"),
                "role": role or st.session_state.get("role", "Unknown"),
                "email": email or "Unknown",
                "status": status or "Unknown",
            }
    except Exception:
        pass

    return {
        "username": st.session_state.get("username", "Unknown"),
        "role": st.session_state.get("role", "Unknown"),
        "email": "Unknown",
        "status": "Unknown",
    }


def render_settings_panel():
    st.markdown(SETTINGS_CSS, unsafe_allow_html=True)
    st.markdown('<div class="settings-header">⚙️ System Settings</div>', unsafe_allow_html=True)
    st.markdown('<div class="settings-sub">Configure platform thresholds, storage limits, and notifications.</div>', unsafe_allow_html=True)

    account = _get_current_user_info()
    st.markdown(f"""
    <div class="settings-card">
        <div class="settings-card-title">👤 Account</div>
        <div class="settings-account-row">
            <div class="settings-account-label">Username</div><div>{account['username']}</div>
            <div class="settings-account-label">Role</div><div>{account['role'].capitalize()}</div>
            <div class="settings-account-label">Email</div><div>{account['email']}</div>
            <div class="settings-account-label">Account Status</div><div>{account['status'].capitalize()}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("Sign out", key="settings_signout", use_container_width=True):
        logout_user(st.session_state)
        st.experimental_rerun()

    # In a real app, these would be loaded from DB or .env and updated there.
    # For this demo, we'll store them in session_state or a simple config table.
    
    # Init default settings if not exist
    if "app_settings" not in st.session_state:
        st.session_state["app_settings"] = {
            "session_timeout_mins": 30,
            "max_upload_mb": 50,
            "enable_email_notifs": False,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_user": "",
            "smtp_pass": ""
        }
        
    s = st.session_state["app_settings"]

    # Security & Limits
    st.markdown("""
    <div class="settings-card">
        <div class="settings-card-title">🔒 Security & Limits</div>
        <div class="settings-hint">Control session durations and file upload restrictions.</div>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("security_settings_form"):
        c1, c2 = st.columns(2)
        with c1:
            timeout = st.number_input("Session Timeout (Minutes)", min_value=5, max_value=1440, value=s["session_timeout_mins"])
        with c2:
            max_mb = st.number_input("Max Upload Size (MB)", min_value=1, max_value=1024, value=s["max_upload_mb"])
        
        if st.form_submit_button("Save Security Settings", type="primary"):
            st.session_state["app_settings"]["session_timeout_mins"] = timeout
            st.session_state["app_settings"]["max_upload_mb"] = max_mb
            st.success("Security settings updated successfully.")

    st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)

    # Email Notifications
    st.markdown("""
    <div class="settings-card">
        <div class="settings-card-title">📧 Email Notifications</div>
        <div class="settings-hint">Configure SMTP server for system alerts (new incidents, status changes).</div>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("email_settings_form"):
        enable_emails = st.checkbox("Enable Email Notifications", value=s["enable_email_notifs"])
        
        c1, c2 = st.columns(2)
        with c1:
            smtp_server = st.text_input("SMTP Server", value=s["smtp_server"])
            smtp_user = st.text_input("SMTP Username (Email)", value=s["smtp_user"])
        with c2:
            smtp_port = st.number_input("SMTP Port", min_value=1, max_value=65535, value=s["smtp_port"])
            smtp_pass = st.text_input("SMTP Password / App Password", type="password", value=s["smtp_pass"])
            
        if st.form_submit_button("Save Email Configuration"):
            st.session_state["app_settings"]["enable_email_notifs"] = enable_emails
            st.session_state["app_settings"]["smtp_server"] = smtp_server
            st.session_state["app_settings"]["smtp_port"] = smtp_port
            st.session_state["app_settings"]["smtp_user"] = smtp_user
            if smtp_pass:
                st.session_state["app_settings"]["smtp_pass"] = smtp_pass
            st.success("Email configuration saved.")
            
    st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
    
    # System info
    st.markdown("""
    <div class="settings-card">
        <div class="settings-card-title">ℹ️ System Information</div>
        <div style="color:#7FB3D3;font-size:13px;line-height:1.6;">
            <strong>FAFO Version:</strong> 1.0.0-rc1<br>
            <strong>Database Path:</strong> {}<br>
            <strong>Python Version:</strong> 3.14<br>
            <strong>Environment:</strong> Production
        </div>
    </div>
    """.format(DATABASE_PATH), unsafe_allow_html=True)
