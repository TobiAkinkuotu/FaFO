import streamlit as st
import datetime
import importlib
import os
import sqlite3
import urllib.parse
import requests
from modules.auth import authenticate_user, check_session_timeout, authenticate_google_user, create_session, validate_session, logout_user
from modules.notifications import render_notification_bell
from modules.rbac import abort_if_unauthorized, get_pages_for_role, normalize_role
from app_config.roles import ROLE_DESCRIPTIONS
from app_config.settings import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, DATABASE_PATH
from database.connection import get_db_connection
from database import init_db as db_init
from database.seed_admin import seed_admin

st.set_page_config(page_title="FAFO Incident Preservation System", layout="wide")


def ensure_database_initialized():
    """Initialize the SQLite schema and seed the default admin user when missing."""
    try:
        db_init.init_db()
        seed_admin()
    except Exception as exc:
        st.error(f"Database initialization failed: {exc}")
        raise


ensure_database_initialized()

# ─── Global CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* ── Base ── */
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

  html, body, [class*="css"] {
    font-family: 'Inter', system-ui, sans-serif !important;
  }
  .stApp {
    background-color: #0D1B2A !important;
    color: #EAF1F8 !important;
  }
  h1, h2, h3, h4 { color: #1E6DB5 !important; }

  /* ── Sidebar ── */
  section[data-testid="stSidebar"] {
    background-color: rgba(17, 34, 54, 0.4) !important;
    border-right: 1px solid #1A3A5C !important;
  }
  section[data-testid="stSidebar"] * { color: #EAF1F8 !important; }

  /* ── Buttons (global fallback) ── */
  button[kind="primaryFormSubmit"],
  .stButton > button {
    background-color: #1A73E8 !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    height: 44px !important;
    transition: all 0.2s ease !important;
  }
  button[kind="primaryFormSubmit"]:hover,
  .stButton > button:hover {
    background-color: #1558A0 !important;
  }

  .block-container {
    padding-top: 2.5rem !important;
    padding-bottom: 2.5rem !important;
  }
  section[data-testid="stSidebar"] {
    min-width: 260px !important;
  }

  /* ── Dark input fields ── */
  input[type="text"], input[type="password"], textarea, .stTextInput input {
    background-color: #0D1B2A !important;
    border: 1px solid #1A3A5C !important;
    border-radius: 8px !important;
    color: #EAF1F8 !important;
    padding: 0 16px !important;
    height: 44px !important;
  }
  input[type="text"]:focus, input[type="password"]:focus, .stTextInput input:focus {
    border-color: #1E6DB5 !important;
    box-shadow: 0 0 8px #1E6DB5 !important;
    outline: none !important;
  }

  /* ── Remove Streamlit chrome on login ── */
  #MainMenu, footer, header { visibility: hidden; }

  /* ── Login page centering ── */
  .login-outer {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 85vh;
    flex-direction: column;
  }
  .login-card {
    background: #112236;
    border-radius: 16px;
    padding: 24px;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.2);
    position: relative;
  }
  .login-shield {
    font-size: 48px;
    text-align: center;
    margin-bottom: 6px;
    display: block;
  }
  .login-brand {
    font-size: 32px;
    font-weight: 700;
    color: #1E6DB5;
    text-align: center;
    letter-spacing: 2px;
    display: block;
    line-height: 1.1;
  }
  .login-subtitle {
    font-size: 12px;
    color: #8BA3BE;
    text-align: center;
    margin-bottom: 28px;
    display: block;
    letter-spacing: 0.5px;
  }
  .google-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    background: #1E6DB5;
    color: #ffffff;
    font-size: 14px;
    font-weight: 600;
    border-radius: 8px;
    height: 44px;
    text-decoration: none !important;
    border: none;
    cursor: pointer;
    margin-bottom: 20px;
    transition: all 0.2s ease;
    box-sizing: border-box;
  }
  .google-btn:hover { background: #1558A0; color: #fff; }
  .google-icon {
    font-size: 16px;
    background: white;
    color: #1E6DB5;
    border-radius: 50%;
    width: 22px;
    height: 22px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-weight: 900;
    font-style: italic;
    line-height: 1;
    font-family: Georgia, serif;
  }
  .or-divider {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 18px 0;
  }
  .or-line {
    flex: 1;
    height: 1px;
    background: #1A3A5C;
  }
  .or-text {
    color: #8BA3BE;
    font-size: 12px;
    font-weight: 500;
    white-space: nowrap;
  }
  .field-label {
    font-size: 12px;
    font-weight: 600;
    color: #8BA3BE;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 6px;
    display: block;
  }
  .login-input {
    width: 100%;
    background: #0D1B2A;
    border: 1px solid #1A3A5C;
    border-radius: 8px;
    color: #EAF1F8;
    font-size: 14px;
    height: 44px;
    padding: 0 16px;
    box-sizing: border-box;
    margin-bottom: 14px;
    outline: none;
    transition: all 0.2s ease;
    font-family: inherit;
  }
  .login-input:focus {
    border-color: #1E6DB5;
    box-shadow: 0 0 8px #1E6DB5;
  }
  .login-submit {
    width: 100%;
    background: #1E6DB5;
    color: #ffffff;
    font-size: 14px;
    font-weight: 700;
    border-radius: 8px;
    height: 44px;
    border: none;
    cursor: pointer;
    margin-top: 8px;
    transition: all 0.2s ease;
    letter-spacing: 0.5px;
    font-family: inherit;
  }
  .login-submit:hover { background: #1558A0; }
  .login-watermark {
    position: absolute;
    bottom: 14px;
    right: 18px;
    font-size: 18px;
    opacity: 0.12;
    pointer-events: none;
    user-select: none;
  }
</style>
""", unsafe_allow_html=True)


def get_google_login_url():
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI):
        return None

    auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    return f"{auth_endpoint}?{urllib.parse.urlencode(params)}"


def _render_sidebar():
    role = st.session_state.get("role", "submitter")
    pages = get_pages_for_role(role)

    if "active_page" not in st.session_state or st.session_state["active_page"] not in pages:
        st.session_state["active_page"] = pages[0] if pages else "Settings"

    with st.sidebar:
        st.markdown(f"""
        <div style="padding: 16px 0 20px 0; border-bottom: 1px solid #1A3A5C; margin-bottom: 16px;">
          <div style="font-size:20px; font-weight:700; color:#1A73E8; letter-spacing:2px;">🛡️ FAFO</div>
          <div style="font-size:11px; color:#8BA3BE; margin-top:2px;">Incident Preservation System</div>
        </div>
        <div style="font-size:13px; color:#8BA3BE; margin-bottom:4px;">Signed in as</div>
        <div style="font-size:14px; font-weight:600; color:#EAF1F8; margin-bottom:16px;">
          {st.session_state.get('username', 'Unknown')}
          <span style="background:#1A3A5C;color:#1A73E8;font-size:11px;padding:2px 8px;border-radius:4px;margin-left:6px;">
            {st.session_state.get('role', 'USER').upper()}
          </span>
        </div>
        """ , unsafe_allow_html=True)

        for page_name in pages:
            is_active = st.session_state["active_page"] == page_name
            btn_type = "primary" if is_active else "secondary"
            if st.button(page_name, key=f"nav_{page_name}", use_container_width=True, type=btn_type):
                st.session_state["active_page"] = page_name
                st.rerun()

        st.divider()
        if st.button("⎋ Logout", use_container_width=True):
            logout_user(st.session_state)
            st.rerun()

    return pages


def _safe_render_page(page: str):
    page_mapping = {
        "Dashboard": ("modules.dashboard", "render_dashboard"),
        "Submit Incident": ("modules.incident_manager", "render_submission_form"),
        "Search & Export": ("modules.search_analytics", "render_search_analytics"),
        "Upload Evidence": ("modules.evidence_ui", "render_evidence_upload"),
        "Lawyer Portal": ("modules.lawyer_portal", "render_lawyer_portal"),
        "Admin Panel": ("modules.admin_panel", "render_admin_panel"),
        "My Incidents": ("modules.my_incidents", "render_my_incidents"),
        "Evidence Repository": ("modules.evidence_repository", "render_evidence_repository"),
        "Settings": ("modules.settings_panel", "render_settings_panel"),
    }

    if page not in page_mapping:
        st.error(f"Page '{page}' is not configured.")
        return

    module_name, func_name = page_mapping[page]
    try:
        module = importlib.import_module(module_name)
        if page == "Upload Evidence":
            incident_id = st.session_state.get("upload_incident_id")
            if not incident_id:
                st.error("No incident selected for evidence upload. Choose an incident from My Incidents first.")
                return
            getattr(module, func_name)(incident_id)
        else:
            getattr(module, func_name)()
    except Exception as exc:
        st.error(f"Unable to load {page}: {exc}")


def login_form():
    """Render login page using native Streamlit widgets styled with CSS."""

    google_url = get_google_login_url()
    google_configured = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI)
    google_misconfigured = bool(GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET or GOOGLE_REDIRECT_URI) and not google_configured

    # ── Centre column layout ──────────────────────────────────────────────────
    _, centre, _ = st.columns([1, 1.4, 1])
    with centre:
        # Logo / branding
        st.markdown(
            "<div style='text-align:center;font-size:52px;margin-bottom:4px;'>🛡️</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<div style='text-align:center;font-size:30px;font-weight:700;"
            "color:#1E6DB5;letter-spacing:3px;margin-bottom:2px;'>FAFO</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<div style='text-align:center;font-size:12px;color:#8BA3BE;"
            "margin-bottom:24px;letter-spacing:0.5px;'>Incident Preservation System</div>",
            unsafe_allow_html=True,
        )

        # Google login button — rendered as a native Streamlit link button
        if google_url:
            st.link_button(
                "🔵  Sign in with Google",
                url=google_url,
                use_container_width=True,
            )
        else:
            st.button("🔵  Sign in with Google", disabled=True, use_container_width=True)
            if google_misconfigured:
                st.info(
                    "Google OAuth is partially configured but missing required settings. "
                    "Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI in Streamlit Cloud."
                )
            elif not GOOGLE_CLIENT_ID:
                st.info("Google login is disabled because GOOGLE_CLIENT_ID is not configured.")
            elif not GOOGLE_CLIENT_SECRET:
                st.info("Google login is disabled because GOOGLE_CLIENT_SECRET is not configured.")
            elif not GOOGLE_REDIRECT_URI:
                st.info("Google login is disabled because GOOGLE_REDIRECT_URI is not configured.")

        st.markdown(
            "<div style='display:flex;align-items:center;gap:12px;margin:16px 0;'>"
            "<div style='flex:1;height:1px;background:#1A3A5C;'></div>"
            "<span style='color:#8BA3BE;font-size:12px;'>or</span>"
            "<div style='flex:1;height:1px;background:#1A3A5C;'></div>"
            "</div>",
            unsafe_allow_html=True,
        )

        # Native Streamlit form
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", placeholder="Enter your password", type="password")
            submit = st.form_submit_button("Login", use_container_width=True)

            if submit:
                user_dict, err_msg = authenticate_user(username, password)
                if user_dict:
                    create_session(st.session_state, user_dict["username"], user_dict["role"], user_dict["id"])
                    st.rerun()
                else:
                    st.error(err_msg or "Invalid credentials.")

        # Developer convenience: auto-login as admin when enabled via env
        # Set FAFO_DEV_AUTO_LOGIN=1 in your environment to enable this button.
        try:
          dev_auto = os.getenv("FAFO_DEV_AUTO_LOGIN", "0") == "1"
        except Exception:
          dev_auto = False

        if dev_auto:
          if st.button("Auto-login as admin (dev only)", use_container_width=True):
            try:
              conn = get_db_connection()
              cursor = conn.cursor()
              cursor.execute("SELECT id, username, role FROM users WHERE username = 'admin' LIMIT 1")
              row = cursor.fetchone()
              conn.close()
              if row:
                user_id, uname, role = row
                create_session(st.session_state, uname, role, user_id)
                st.success("Auto-logged in as admin")
                st.rerun()
              else:
                st.error("No admin user found in the database.")
            except Exception as exc:
              st.error(f"Auto-login failed: {exc}")

    # Bottom watermark rendered separately
    st.markdown("""
    <style>
      /* Style the login form block to look like it's inside the card */
      div[data-testid="stForm"] {
        background: #112236 !important;
        border: none !important;
        padding: 0 24px 24px 24px !important;
        border-radius: 0 0 16px 16px !important;
        margin-top: -8px !important;
        position: relative;
        box-shadow: 0 8px 32px rgba(0,0,0,0.2) !important;
        max-width: 380px !important;
        margin-left: auto !important;
        margin-right: auto !important;
      }
      div[data-testid="stForm"]::after {
        content: "🔒";
        position: absolute;
        bottom: 14px;
        right: 18px;
        font-size: 18px;
        opacity: 0.12;
        pointer-events: none;
      }
      /* Style submit button inside form */
      div[data-testid="stForm"] .stButton > button,
      div[data-testid="stForm"] [data-testid="stFormSubmitButton"] button {
        width: 100% !important;
        background: #1E6DB5 !important;
        color: #fff !important;
        font-weight: 700 !important;
        font-size: 14px !important;
        border-radius: 8px !important;
        height: 44px !important;
        letter-spacing: 0.5px !important;
        border: none !important;
      }
      div[data-testid="stForm"] .stButton > button:hover,
      div[data-testid="stForm"] [data-testid="stFormSubmitButton"] button:hover {
        background: #1558A0 !important;
      }
      /* Input fields in form */
      div[data-testid="stForm"] input {
        background: #0D1B2A !important;
        border: 1px solid #1A3A5C !important;
        border-radius: 8px !important;
        color: #EAF1F8 !important;
        font-size: 14px !important;
        height: 44px !important;
        padding: 0 16px !important;
      }
      div[data-testid="stForm"] input:focus {
        border-color: #1E6DB5 !important;
        box-shadow: 0 0 8px #1E6DB5 !important;
      }
      /* Label overrides */
      div[data-testid="stForm"] label { color: #8BA3BE !important; font-size: 12px !important; }
    </style>
    """, unsafe_allow_html=True)


# ─── Handle Google OAuth callback ─────────────────────────────────────────────
if "code" in st.query_params and not st.session_state.get("authenticated", False):
    code = st.query_params["code"]
    if isinstance(code, list):
        code = code[0]

    try:
        token_endpoint = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        resp = requests.post(token_endpoint, data=data)
        resp.raise_for_status()
        tokens = resp.json()

        userinfo_endpoint = "https://www.googleapis.com/oauth2/v1/userinfo"
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        user_resp = requests.get(userinfo_endpoint, headers=headers)
        user_resp.raise_for_status()
        user_info = user_resp.json()

        email = user_info.get("email")
        if email:
            user_dict, err_msg = authenticate_google_user(email)
            if user_dict:
                create_session(st.session_state, user_dict["username"], user_dict["role"], user_dict["id"])
                st.query_params.clear()
                st.rerun()
            else:
                st.error(err_msg or "Failed to authenticate with Google.")
        else:
            st.error("Could not retrieve email from Google.")
    except Exception as e:
        st.error(f"Google login failed: {e}")

# ─── Main Routing ──────────────────────────────────────────────────────────────
def _get_role_welcome(role: str) -> str:
    return ROLE_DESCRIPTIONS.get(normalize_role(role), "Use the left menu to navigate to your permitted pages.")


if not st.session_state.get("authenticated", False):
    login_form()
else:
    # Enforce session timeout
    if not validate_session(st.session_state) or not check_session_timeout(st.session_state):
        st.warning("Session timed out. Please log in again.")
        logout_user(st.session_state)
        st.rerun()
    else:
        pages = _render_sidebar()
        page = st.session_state.get("active_page", pages[0] if pages else "Settings")
        abort_if_unauthorized(page, st.session_state.get("role"))

        st.markdown(
            f"""
            <div style='padding: 18px 0 14px 0;'>
              <h2 style='margin:0;color:#EAF1F8;'>Welcome back, {st.session_state.get('username', 'User')}!</h2>
              <p style='margin:8px 0 0 0;color:#A8BECF;font-size:14px;'>
                { _get_role_welcome(st.session_state.get('role')) }
              </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        _safe_render_page(page)
