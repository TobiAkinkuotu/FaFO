import uuid
from datetime import datetime, timezone
import re

def generate_incident_id() -> str:
    """Generate a unique incident ID in format INC-YYYYMMDD-UUID4"""
    date_str = datetime.utcnow().strftime("%Y%m%d")
    short_uuid = str(uuid.uuid4()).split('-')[0].upper()
    return f"INC-{date_str}-{short_uuid}"

def generate_uuid() -> str:
    """Generate a standard UUID string."""
    return str(uuid.uuid4())

def get_utc_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()

def sanitize_filename(filename: str) -> str:
    """Remove unsafe characters from filenames."""
    # Keep alphanumeric, dash, underscore, dot
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)
