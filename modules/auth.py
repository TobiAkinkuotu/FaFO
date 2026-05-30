"""
auth.py — Full Authentication Engine for FAFO
Handles: login, logout, session validation, account lockout, JWT tokens, session timeout
"""

import jwt
import datetime
import sqlite3
import secrets
import logging
import streamlit as st
import bcrypt
from database.connection import get_db_connection
from config.settings import (
    SECRET_KEY, DATABASE_PATH, SESSION_TIMEOUT_MINUTES,
    MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES
)
from modules.utils import generate_uuid, get_utc_now

logger = logging.getLogger(__name__)


# Helper: robust ISO datetime parsing to UTC
def _parse_iso_to_utc(iso_str: str) -> datetime.datetime | None:
    if not iso_str:
        return None
    try:
        # Accept both trailing Z and +00:00
        if iso_str.endswith("Z"):
            iso_str = iso_str.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def _minutes_text(minutes: int) -> str:
    return f"{minutes} minute" + ("s" if minutes != 1 else "")


def _format_lock_message(minutes: int) -> str:
    return f"Account locked for { _minutes_text(minutes) }."


# ---------------------------------------------------------------------------
# Password Utilities
# ---------------------------------------------------------------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except (ValueError, Exception):
        return False


def get_password_hash(password: str) -> str:
    """Hash a password with bcrypt (12 rounds)."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


# ---------------------------------------------------------------------------
# JWT Utilities
# ---------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: datetime.timedelta = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + (
        expires_delta if expires_delta
        else datetime.timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.datetime.now(datetime.timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> dict | None:
    """Decode and validate a JWT token. Returns payload or None."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ---------------------------------------------------------------------------
# Account Lockout Helpers
# ---------------------------------------------------------------------------

def is_account_locked(conn: sqlite3.Connection, username: str) -> tuple[bool, str]:
    """
    Check if an account is currently locked due to too many failed attempts.
    Returns (is_locked: bool, message: str).
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT failed_logins, locked_until, is_active FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    if not row:
        return False, ""

    # Defensive reads
    failed_logins = int(row[0] or 0)
    locked_until = row[1]
    is_active = bool(row[2])

    if not is_active:
        return True, "This account has been deactivated by an administrator."

    if locked_until:
        lock_time = _parse_iso_to_utc(locked_until)
        now = datetime.datetime.now(datetime.timezone.utc)
        if lock_time and now < lock_time:
            remaining = int((lock_time - now).total_seconds() / 60)
            if remaining < 1:
                remaining = 1
            return True, f"Account temporarily locked. Try again in {_minutes_text(remaining)}."
        else:
            # Lock has expired — clear it
            cursor.execute(
                "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username = ?",
                (username,)
            )
            conn.commit()

    return False, ""


def record_failed_login(conn: sqlite3.Connection, username: str):
    """Increment failed login counter and lock account if threshold is reached."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, failed_logins FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    if not row:
        return

    user_id = row[0]
    failed_logins = int(row[1] or 0)
    new_count = failed_logins + 1

    if new_count >= MAX_LOGIN_ATTEMPTS:
        lock_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=LOCKOUT_MINUTES)
        locked_until = lock_time.isoformat().replace("+00:00", "Z")
        cursor.execute(
            "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
            (new_count, locked_until, user_id)
        )
        # Log lockout in audit_logs
        _insert_audit_log(conn, user_id, username, "ACCOUNT_LOCKED")
    else:
        cursor.execute(
            "UPDATE users SET failed_logins = ? WHERE id = ?",
            (new_count, user_id)
        )

    # Log failed attempt
    _insert_audit_log(conn, user_id, username, "LOGIN_FAILED")
    conn.commit()


def reset_failed_logins(conn: sqlite3.Connection, user_id: int):
    """Reset failed login counter and lockout after successful login."""
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
        (user_id,)
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Core Login / Authenticate
# ---------------------------------------------------------------------------

def authenticate_user(username: str, password: str) -> tuple[dict | None, str | None]:
    """
    Full login pipeline.
    1. Look up user
    2. Check lockout
    3. Verify password
    4. Reset failed counter on success / increment on failure
    5. Return user dict on success, None on failure

    Returns dict with keys: id, username, role, email
    or None on any failure.
    Also returns an error string as second element of tuple.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        is_locked, lock_msg = is_account_locked(conn, username)
        if is_locked:
            return None, lock_msg

        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, password_hash, role, email, is_active FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

        if not row:
            # Don't reveal whether username exists
            return None, "Invalid username or password."

        user_id, password_hash, role, email, is_active = row

        if not is_active:
            return None, "This account has been deactivated."

        if not verify_password(password, password_hash):
            record_failed_login(conn, username)
            cursor.execute(
                "SELECT failed_logins FROM users WHERE id = ?", (user_id,)
            )
            f_row = cursor.fetchone()
            fails = int(f_row[0] if f_row and f_row[0] is not None else 0)
            remaining = MAX_LOGIN_ATTEMPTS - fails
            if remaining > 0:
                return None, f"Invalid username or password. {remaining} attempt(s) remaining."
            else:
                # Deterministic lockout message
                return None, _format_lock_message(LOCKOUT_MINUTES)

        # Success — reset counter and log
        reset_failed_logins(conn, user_id)
        _insert_audit_log(conn, user_id, username, "LOGIN")

        return {
            "id": user_id,
            "username": username,
            "role": role,
            "email": email or ""
        }, None

    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Session Helpers
# ---------------------------------------------------------------------------

def create_session(session_state, username: str, role: str, user_id: int) -> str:
    """Create a DB-backed session token and store it in Streamlit session state."""
    session_token = secrets.token_urlsafe(32)
    expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=SESSION_TIMEOUT_MINUTES))
    expires_at_str = expires_at.isoformat().replace("+00:00", "Z")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        cursor.execute(
            "INSERT INTO sessions (user_id, session_token, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (user_id, session_token, expires_at_str, datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")),
        )
        conn.commit()
    finally:
        conn.close()

    session_state.update({
        "authenticated": True,
        "username": username,
        "role": role,
        "user_id": user_id,
        "session_token": session_token,
        "last_activity": datetime.datetime.now(datetime.timezone.utc),
        "login_timestamp": datetime.datetime.now(datetime.timezone.utc),
    })
    return session_token


def validate_session(session_state) -> bool:
    """Validate the current session against the sessions table."""
    session_token = session_state.get("session_token")
    if not session_token:
        return False

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.user_id, s.expires_at, u.username, u.role, u.is_active
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ?
            """,
            (session_token,),
        )
        row = cursor.fetchone()
        if not row:
            logout_user(session_state)
            return False

        user_id, expires_at, username, role, is_active = row
        if not bool(is_active):
            logout_user(session_state)
            return False

        expires_at_dt = _parse_iso_to_utc(expires_at)
        now = datetime.datetime.now(datetime.timezone.utc)
        if not expires_at_dt or now > expires_at_dt:
            logout_user(session_state)
            return False

        session_state["user_id"] = user_id
        session_state["username"] = username
        session_state["role"] = role
        session_state["last_activity"] = now
        return True
    finally:
        conn.close()


def check_session_timeout(session_state) -> bool:
    """
    Check if the current session has exceeded the timeout window.
    Returns True if session is VALID, False if expired.
    """
    last_activity = session_state.get("last_activity") or session_state.get("login_timestamp")
    if last_activity is None:
        return False

    # Accept either datetime or ISO string
    if isinstance(last_activity, str):
        last_dt = _parse_iso_to_utc(last_activity)
        if not last_dt:
            return False
    elif isinstance(last_activity, datetime.datetime):
        last_dt = last_activity if last_activity.tzinfo else last_activity.replace(tzinfo=datetime.timezone.utc)
    else:
        return False

    elapsed = (datetime.datetime.now(datetime.timezone.utc) - last_dt).total_seconds() / 60
    if elapsed >= SESSION_TIMEOUT_MINUTES:
        logout_user(session_state)
        return False

    session_state["last_activity"] = datetime.datetime.now(datetime.timezone.utc)
    return True


def logout_user(session_state):
    """Invalidate the current DB session and clear Streamlit state."""
    session_token = session_state.get("session_token")
    if session_token:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
            conn.commit()
            conn.close()
        except Exception:
            pass

    for key in list(session_state.keys()):
        del session_state[key]


def refresh_session_timestamp(session_state):
    """Update the login timestamp to extend the session on activity."""
    session_state["login_timestamp"] = datetime.datetime.now(datetime.timezone.utc)


# ---------------------------------------------------------------------------
# User Management (Admin Operations)
# ---------------------------------------------------------------------------

def create_user(username: str, password: str, role: str, email: str = "") -> tuple[bool, str]:
    """Create a new user account. Returns (success, message)."""
    if role not in ("submitter", "reviewer", "lawyer", "admin"):
        return False, f"Invalid role: {role}"

    password_hash = get_password_hash(password)
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO users (username, password_hash, role, email)
               VALUES (?, ?, ?, ?)""",
            (username, password_hash, role, email)
        )
        conn.commit()
        user_id = cursor.lastrowid
        _insert_audit_log(conn, user_id, username, "USER_CREATED")
        return True, f"User '{username}' created successfully."
    except sqlite3.IntegrityError:
        return False, f"Username '{username}' already exists."
    except Exception as e:
        return False, f"Database error: {e}"
    finally:
        conn.close()


def update_user_role(target_user_id: int, new_role: str, acting_user_id: int, acting_username: str) -> tuple[bool, str]:
    """Change the role of an existing user."""
    if new_role not in ("submitter", "reviewer", "lawyer", "admin"):
        return False, f"Invalid role: {new_role}"
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (new_role, target_user_id)
        )
        conn.commit()
        _insert_audit_log(conn, acting_user_id, acting_username, "USER_ROLE_CHANGED", "user", str(target_user_id))
        return True, "Role updated."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def set_user_active(target_user_id: int, is_active: bool, acting_user_id: int, acting_username: str) -> tuple[bool, str]:
    """Activate or deactivate a user account."""
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (1 if is_active else 0, target_user_id)
        )
        conn.commit()
        action = "USER_ACTIVATED" if is_active else "USER_DEACTIVATED"
        _insert_audit_log(conn, acting_user_id, acting_username, action, "user", str(target_user_id))
        return True, "Account status updated."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def reset_user_password(target_user_id: int, new_password: str, acting_user_id: int, acting_username: str) -> tuple[bool, str]:
    """Reset a user's password (admin operation)."""
    new_hash = get_password_hash(new_password)
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL WHERE id = ?",
            (new_hash, target_user_id)
        )
        conn.commit()
        _insert_audit_log(conn, acting_user_id, acting_username, "PASSWORD_RESET", "user", str(target_user_id))
        return True, "Password reset successfully."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def get_all_users() -> list[dict]:
    """Fetch all users for admin management."""
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, role, email, is_active, failed_logins, locked_until, created_at FROM users ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()
        return [
            {
                "id": r[0], "username": r[1], "role": r[2], "email": r[3],
                "is_active": bool(r[4]), "failed_logins": r[5],
                "locked_until": r[6], "created_at": r[7]
            }
            for r in rows
        ]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Internal Helper
# ---------------------------------------------------------------------------

def _insert_audit_log(conn: sqlite3.Connection, user_id: int, username: str,
                       action: str, target_type: str = None, target_id: str = None):
    """Internal helper — insert audit log within an existing connection."""
    log_id = generate_uuid()
    timestamp = get_utc_now()
    try:
        conn.execute(
            """INSERT INTO audit_logs (log_id, user_id, username, action, target_type, target_id, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (log_id, user_id, username, action, target_type, target_id, timestamp)
        )
    except Exception:
        pass  # Never let logging crash the auth flow

# ---------------------------------------------------------------------------
# Google OAuth Helpers
# ---------------------------------------------------------------------------

def authenticate_google_user(email: str) -> tuple[dict | None, str | None]:
    """
    Authenticate a user via Google OAuth.
    If the user exists by email, log them in.
    If not, auto-register them as 'submitter'.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, role, is_active FROM users WHERE email = ?",
            (email,)
        )
        row = cursor.fetchone()

        if row:
            # User exists
            user_id, username, role, is_active = row
            if not is_active:
                return None, "This account has been deactivated."
            
            # Reset counter and log login
            reset_failed_logins(conn, user_id)
            _insert_audit_log(conn, user_id, username, "GOOGLE_LOGIN")
            
            return {
                "id": user_id,
                "username": username,
                "role": role,
                "email": email
            }, None
        else:
            # User does not exist, auto-register
            # We'll use the email prefix as a default username (e.g. jdoe@org -> jdoe)
            base_username = email.split('@')[0]
            username = base_username
            # ensure uniqueness just in case
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            suffix = 1
            while cursor.fetchone():
                username = f"{base_username}{suffix}"
                suffix += 1
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            
            # Insert new user with a dummy hashed password since they use Google
            dummy_hash = get_password_hash("GOOGLE_OAUTH_NO_LOCAL_PASSWORD")
            cursor.execute(
                """INSERT INTO users (username, password_hash, role, email)
                   VALUES (?, ?, ?, ?)""",
                (username, dummy_hash, "submitter", email)
            )
            conn.commit()
            new_user_id = cursor.lastrowid
            
            _insert_audit_log(conn, new_user_id, username, "USER_CREATED_VIA_GOOGLE")
            _insert_audit_log(conn, new_user_id, username, "GOOGLE_LOGIN")
            
            return {
                "id": new_user_id,
                "username": username,
                "role": "submitter",
                "email": email
            }, None

    finally:
        conn.close()
