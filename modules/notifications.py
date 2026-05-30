import json
import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Dict, List, Optional

from config.settings import NOTIFICATION_EMAILS, SMTP_HOST, SMTP_PASS, SMTP_PORT, SMTP_USER
from database.connection import get_db_connection

logger = logging.getLogger(__name__)


class NotificationType(Enum):
    INCIDENT_CREATED = "INCIDENT_CREATED"
    EVIDENCE_UPLOADED = "EVIDENCE_UPLOADED"
    STATUS_CHANGED = "STATUS_CHANGED"
    AI_ANALYSIS_READY = "AI_ANALYSIS_READY"
    ASSIGNED_TO_YOU = "ASSIGNED_TO_YOU"
    EXPORT_READY = "EXPORT_READY"
    SECURITY_ALERT = "SECURITY_ALERT"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"


class NotificationChannel(Enum):
    IN_APP = "IN_APP"
    EMAIL = "EMAIL"
    BOTH = "BOTH"


def send_email_notification(subject: str, body: str, recipients: Optional[List[str]] = None) -> bool:
    """Send a plain text email notification, or log it in mock mode when SMTP is not configured."""
    recipients = recipients or NOTIFICATION_EMAILS
    if not recipients:
        recipients = [SMTP_USER] if SMTP_USER else []

    if not SMTP_USER or not SMTP_PASS:
        logger.info("[MOCK EMAIL] To=%s | Subject=%s | Body=%s", recipients, subject, body)
        return False

    msg = MIMEText(body)
    msg["Subject"] = f"[FAFO] {subject}"
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(recipients)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as exc:
        logger.error("Failed to send email notification: %s", exc)
        return False


def create_notification(
    user_id: int,
    notification_type: NotificationType,
    title: str,
    message: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    channel: NotificationChannel = NotificationChannel.IN_APP,
) -> Optional[str]:
    """Create an in-app notification and optionally send email."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        notification_id = f"NTF_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{os.urandom(3).hex()}"

        cursor.execute(
            """
            INSERT INTO notifications (
                notification_id, user_id, type, title, message,
                target_type, target_id, channel, is_read, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                notification_id,
                user_id,
                notification_type.value,
                title,
                message,
                target_type,
                target_id,
                channel.value,
                0,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        conn.close()

        if channel in (NotificationChannel.EMAIL, NotificationChannel.BOTH):
            send_email_notification(title, message)
        return notification_id
    except Exception as exc:
        logger.error("Failed to create notification: %s", exc)
        return None


def get_user_notifications(user_id: int, unread_only: bool = False, limit: int = 50) -> List[Dict[str, Any]]:
    """Read notifications for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    query = """
        SELECT notification_id, type, title, message, target_type, target_id, channel, is_read, created_at
        FROM notifications
        WHERE user_id = ?
    """
    params = [user_id]
    if unread_only:
        query += " AND is_read = 0"
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "notification_id": row[0],
            "type": row[1],
            "title": row[2],
            "message": row[3],
            "target_type": row[4],
            "target_id": row[5],
            "channel": row[6],
            "is_read": bool(row[7]),
            "created_at": row[8],
        }
        for row in rows
    ]


def mark_notification_read(notification_id: str) -> bool:
    """Mark one notification as read."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE notification_id = ?", (notification_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as exc:
        logger.error("Failed to mark notification read: %s", exc)
        return False


def mark_all_read(user_id: int) -> bool:
    """Mark all notifications for a user as read."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0", (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as exc:
        logger.error("Failed to mark all notifications read: %s", exc)
        return False


def get_unread_count(user_id: int) -> int:
    """Get the unread notification count for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (user_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count


def notify_new_incident(incident_id: str, category: str, severity: str):
    """Send a notification for a newly created incident."""
    # Best-effort: notify admins/reviewers if the user exists.
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE role IN ('admin', 'reviewer') AND is_active = 1")
        reviewers = [row[0] for row in cursor.fetchall()]
        conn.close()
        for reviewer_id in reviewers:
            create_notification(
                reviewer_id,
                NotificationType.INCIDENT_CREATED,
                "New Incident Submitted",
                f"Incident {incident_id} was submitted with category {category} and severity {severity}.",
                target_type="incident",
                target_id=incident_id,
                channel=NotificationChannel.IN_APP,
            )
    except Exception as exc:
        logger.error("Failed to notify reviewers: %s", exc)


def notify_evidence_uploaded(incident_id: str, evidence_id: str, uploader_id: int):
    """Notify reviewers and owners when evidence is uploaded."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT created_by FROM incidents WHERE incident_id = ?", (incident_id,))
        owner = cursor.fetchone()
        cursor.execute("SELECT id FROM users WHERE role IN ('admin', 'reviewer') AND is_active = 1")
        reviewers = [row[0] for row in cursor.fetchall()]
        conn.close()
        notify_ids = set(reviewers)
        if owner and owner[0]:
            notify_ids.add(owner[0])
        notify_ids.discard(uploader_id)
        for uid in notify_ids:
            create_notification(uid, NotificationType.EVIDENCE_UPLOADED, "New Evidence Uploaded", f"Evidence {evidence_id} was uploaded to incident {incident_id}.", target_type="evidence", target_id=evidence_id, channel=NotificationChannel.IN_APP)
    except Exception as exc:
        logger.error("Failed to notify evidence upload: %s", exc)


def notify_ai_analysis_ready(incident_id: str, category: str, severity: str):
    """Notify owner that AI analysis completed."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT created_by FROM incidents WHERE incident_id = ?", (incident_id,))
        owner = cursor.fetchone()
        conn.close()
        if owner and owner[0]:
            owner_conn = get_db_connection()
            owner_cursor = owner_conn.cursor()
            owner_cursor.execute("SELECT id FROM users WHERE username = ?", (owner[0],))
            row = owner_cursor.fetchone()
            owner_conn.close()
            if row:
                create_notification(row[0], NotificationType.AI_ANALYSIS_READY, "AI Analysis Complete", f"AI classified incident {incident_id} as {severity} severity ({category}).", target_type="incident", target_id=incident_id, channel=NotificationChannel.IN_APP)
    except Exception as exc:
        logger.error("Failed to notify AI analysis ready: %s", exc)


def notify_security_alert(username: str, alert_type: str, details: str):
    """Notify admins about a security alert or lockout."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE role = 'admin' AND is_active = 1")
        admins = [row[0] for row in cursor.fetchall()]
        conn.close()
        for admin_id in admins:
            create_notification(admin_id, NotificationType.SECURITY_ALERT, f"Security Alert: {alert_type}", f"User {username}: {details}", channel=NotificationChannel.BOTH)
    except Exception as exc:
        logger.error("Failed to notify security alert: %s", exc)


def render_notification_bell(user_id: int):
    """Render a notification bell in Streamlit sidebar."""
    import streamlit as st
    count = get_unread_count(user_id)
    bell = "🔔" if count == 0 else f"🔔 {count}"
    with st.sidebar:
        st.caption(f"{bell} Notifications")
        if count:
            if st.button("Mark all read", key=f"mark_all_read_{user_id}"):
                mark_all_read(user_id)
                st.rerun()
        notifs = get_user_notifications(user_id, unread_only=True, limit=5)
        if not notifs:
            st.caption("No new notifications")
        else:
            for notif in notifs:
                st.markdown(f"**{notif['title']}**")
                st.caption(notif['message'])
                if st.button("✓", key=f"read_{notif['notification_id']}"):
                    mark_notification_read(notif['notification_id'])
                    st.rerun()


def render_notification_center(user_id: int):
    """Render the full notification center page."""
    import streamlit as st
    st.title("📬 Notification Center")
    st.write("Unread notifications")
    for notif in get_user_notifications(user_id, unread_only=True, limit=100):
        st.markdown(f"- **{notif['title']}** — {notif['message']}")
