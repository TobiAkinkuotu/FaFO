import os
try:
    import magic
except ImportError:
    magic = None
import mimetypes
from pathlib import Path
from typing import Optional, Tuple
import logging

from config.settings import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_MB

logger = logging.getLogger(__name__)

def is_safe_path(base_dir: Path, requested_path: Path) -> bool:
    """Ensure the requested path is within the base directory to prevent path traversal."""
    try:
        # Resolve resolves symlinks and normalizes path
        resolved_requested = requested_path.resolve()
        resolved_base = base_dir.resolve()
        # Check if the base directory is a parent of the requested path
        return resolved_base in resolved_requested.parents
    except Exception:
        return False

def validate_file_upload(file_bytes: bytes, filename: str) -> tuple[bool, str]:
    """Validate file size, extension, and mime type."""
    if len(file_bytes) > MAX_FILE_SIZE_MB * 1024 * 1024:
        return False, f"File exceeds maximum size of {MAX_FILE_SIZE_MB}MB."

    ext = Path(filename).suffix.lower()
    allowed_exts = [e for exts in ALLOWED_EXTENSIONS.values() for e in exts]
    if ext not in allowed_exts:
        return False, f"File extension {ext} is not allowed."

    if magic:
        mime_type = magic.from_buffer(file_bytes[:2048], mime=True)
    else:
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = "application/octet-stream"

    return True, mime_type


def sanitize_filename(filename: str) -> Optional[str]:
    """Sanitize a filename to prevent path traversal and unsafe characters."""
    if not filename:
        return None

    basename = os.path.basename(filename)
    safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')
    sanitized = ''.join(c for c in basename if c in safe_chars)

    if not sanitized or sanitized.strip('.') == '':
        return None

    if sanitized.count('.') > 1:
        parts = sanitized.split('.')
        sanitized = f"{parts[0]}.{parts[-1]}"

    return sanitized


def get_secure_storage_path(incident_id: str, filename: str, category: str) -> Path:
    """Generate a secure storage path for evidence files."""
    from config.settings import EVIDENCE_REPO_PATH

    if not incident_id or '/' in incident_id or '\\' in incident_id or '..' in incident_id:
        raise ValueError("Invalid incident ID")

    folder_map = {
        'image': 'screenshots',
        'images': 'screenshots',
        'video': 'videos',
        'videos': 'videos',
        'audio': 'audio',
        'document': 'documents',
        'documents': 'documents',
        'archive': 'archives',
        'archives': 'archives',
    }

    folder = folder_map.get(category, 'other')
    base_path = Path(EVIDENCE_REPO_PATH) / f"incident_{incident_id}" / folder
    base_path.mkdir(parents=True, exist_ok=True)

    stem = Path(filename).stem
    suffix = Path(filename).suffix
    unique_name = f"{stem}_{os.urandom(4).hex()}{suffix}"

    return base_path / unique_name


def validate_file_upload_complete(file_obj) -> Tuple[bool, str, Optional[str]]:
    """Complete validation for Streamlit file objects."""
    if file_obj is None:
        return False, "No file provided", None

    file_bytes = file_obj.getvalue()
    filename = file_obj.name

    is_valid, mime_or_msg = validate_file_upload(file_bytes, filename)
    if not is_valid:
        return False, mime_or_msg, None

    ext = Path(filename).suffix.lower()
    category = None
    for cat, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            category = cat
            break

    safe_name = sanitize_filename(filename)
    if not safe_name:
        return False, "Invalid filename", None

    logger.info(f"File validated: {safe_name} ({category}, {len(file_bytes)} bytes)")
    return True, "", category
