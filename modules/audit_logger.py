import json
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from database.connection import get_db_connection
from modules.utils import generate_uuid, get_utc_now

logger = logging.getLogger(__name__)


class AuditAction(Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_UPDATED = "INCIDENT_UPDATED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    EVIDENCE_UPLOADED = "EVIDENCE_UPLOADED"
    EVIDENCE_DELETED = "EVIDENCE_DELETED"
    AI_CLASSIFICATION_RUN = "AI_CLASSIFICATION_RUN"
    EXPORT_PDF = "EXPORT_PDF"
    EXPORT_ZIP = "EXPORT_ZIP"
    EXPORT_CSV = "EXPORT_CSV"
    EXPORT_JSON = "EXPORT_JSON"
    USER_CREATED = "USER_CREATED"
    LAWYER_PORTAL_VIEWED = "LAWYER_PORTAL_VIEWED"
    LAWYER_CASE_OPENED = "LAWYER_CASE_OPENED"
    USER_UPDATED = "USER_UPDATED"
    USER_DEACTIVATED = "USER_DEACTIVATED"
    ROLE_CHANGED = "ROLE_CHANGED"


def log_event(
    action: AuditAction,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Record a standardized audit event and return the generated log_id."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        log_id = f"AUD_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{os.urandom(3).hex()}"

        cursor.execute(
            """
            INSERT INTO audit_logs (
                log_id, action, user_id, username, target_type,
                target_id, details, ip_address, metadata_json, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_id,
                action.value if isinstance(action, AuditAction) else str(action),
                user_id,
                username,
                target_type,
                target_id,
                details,
                ip_address,
                json.dumps(metadata) if metadata else None,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        conn.close()
        logger.info("AUDIT: %s | user=%s (%s) | target=%s:%s | %s", action, username, user_id, target_type, target_id, details)
        return log_id
    except Exception as exc:
        logger.error("Failed to write audit log: %s", exc)
        return None


def log_action(user_id: int, username: str, action: str, target_type: str = None,
               target_id: str = None, ip_address: str = None, user_agent: str = None,
               details: str = None):
    """Backwards-compatible wrapper around the new audit logger."""
    return log_event(
        action=action,
        user_id=user_id,
        username=username,
        target_type=target_type,
        target_id=target_id,
        details=details,
        ip_address=ip_address,
        metadata={"user_agent": user_agent} if user_agent else None,
    )


def get_audit_trail(target_type: Optional[str] = None, target_id: Optional[str] = None,
                    user_id: Optional[int] = None, action: Optional[str] = None,
                    start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                    limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Query audit logs with optional filters."""
    conn = get_db_connection()
    cursor = conn.cursor()
    conditions = ["1=1"]
    params: List[Any] = []

    if target_type:
        conditions.append("target_type = ?")
        params.append(target_type)
    if target_id:
        conditions.append("target_id = ?")
        params.append(target_id)
    if user_id is not None:
        conditions.append("user_id = ?")
        params.append(user_id)
    if action:
        conditions.append("action = ?")
        params.append(action)
    if start_date:
        conditions.append("timestamp >= ?")
        params.append(start_date.isoformat())
    if end_date:
        conditions.append("timestamp <= ?")
        params.append(end_date.isoformat())

    cursor.execute(
        f"""
        SELECT log_id, action, user_id, username, target_type, target_id,
               details, ip_address, metadata_json, timestamp
        FROM audit_logs
        WHERE {' AND '.join(conditions)}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """,
        (*params, limit, offset),
    )
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "log_id": row[0],
            "action": row[1],
            "user_id": row[2],
            "username": row[3],
            "target_type": row[4],
            "target_id": row[5],
            "details": row[6],
            "ip_address": row[7],
            "metadata": json.loads(row[8]) if row[8] else None,
            "timestamp": row[9],
        }
        for row in rows
    ]


def get_incident_history(incident_id: str) -> List[Dict[str, Any]]:
    """Return the audit history for a specific incident."""
    return get_audit_trail(target_type="incident", target_id=incident_id, limit=500)


def get_user_activity(user_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    """Return recent activity for a specific user."""
    return get_audit_trail(user_id=user_id, limit=limit)


def get_audit_stats(days: int = 30) -> Dict[str, Any]:
    """Return summary statistics for the audit trail."""
    conn = get_db_connection()
    cursor = conn.cursor()
    stats = {
        "total_events_30d": 0,
        "events_by_action": {},
        "events_by_user": {},
        "login_failures_24h": 0,
        "active_incidents_touched": 0,
    }

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE timestamp >= date('now', '-' || ?)" , (f"{days} days",))
    stats['total_events_30d'] = cursor.fetchone()[0]

    cursor.execute("SELECT action, COUNT(*) FROM audit_logs WHERE timestamp >= date('now', '-' || ?) GROUP BY action", (f"{days} days",))
    stats['events_by_action'] = dict(cursor.fetchall())

    cursor.execute("SELECT username, COUNT(*) FROM audit_logs WHERE timestamp >= date('now', '-' || ?) AND username IS NOT NULL GROUP BY username ORDER BY COUNT(*) DESC LIMIT 10", (f"{days} days",))
    stats['events_by_user'] = dict(cursor.fetchall())

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'LOGIN_FAILURE' AND timestamp >= date('now', '-1 days')")
    stats['login_failures_24h'] = cursor.fetchone()[0]
    conn.close()
    return stats
