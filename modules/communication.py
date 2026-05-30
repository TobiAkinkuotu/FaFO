import sqlite3
import uuid
from datetime import datetime
from app_config.settings import DATABASE_PATH
import logging

logger = logging.getLogger(__name__)

def add_communication(incident_id: str, user_id: int, sender_name: str, message: str, is_alert: bool = False) -> bool:
    """Add a new communication message to an incident."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        message_id = str(uuid.uuid4())
        
        cursor.execute("""
            INSERT INTO communications (message_id, incident_id, user_id, sender_name, message, is_alert)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (message_id, incident_id, user_id, sender_name, message, is_alert))
        
        conn.commit()
        conn.close()
        
        # If it's an alert, we could trigger an email or webhook here
        if is_alert:
            logger.info(f"ALERT TRIGGERED for Incident {incident_id}: {message}")
            # e.g., send_slack_notification(message)
            
        return True
    except Exception as e:
        logger.error(f"Failed to add communication: {e}")
        return False

def get_communications(incident_id: str) -> list:
    """Get all communications for a given incident."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM communications 
            WHERE incident_id = ? 
            ORDER BY timestamp ASC
        """, (incident_id,))
        
        messages = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return messages
    except Exception as e:
        logger.error(f"Failed to fetch communications: {e}")
        return []
