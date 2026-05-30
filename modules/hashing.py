import hashlib
from pathlib import Path
from typing import Dict
import logging

logger = logging.getLogger(__name__)

def generate_file_hash(file_path: Path) -> str:
    """Generate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_bytes_hash(file_bytes: bytes) -> str:
    """Generate SHA-256 hash from raw bytes (useful before writing to disk)."""
    return hashlib.sha256(file_bytes).hexdigest()

def verify_file_integrity(file_path: Path, expected_hash: str) -> bool:
    """Verify that a file's current hash matches its expected hash."""
    if not file_path.exists():
        return False
    current_hash = generate_file_hash(file_path)
    return current_hash == expected_hash


def generate_file_hashes(file_path: str) -> Dict[str, str]:
    """Generate SHA-256, MD5, and file size for forensic evidence handling."""
    hashes = {'sha256': '', 'md5': '', 'file_size': 0}

    try:
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)

        hashes['sha256'] = sha256_hash.hexdigest()
        hashes['md5'] = md5_hash.hexdigest()
        hashes['file_size'] = Path(file_path).stat().st_size

        logger.info(f"Hashes generated for {file_path}: SHA256={hashes['sha256'][:16]}...")
    except Exception as e:
        logger.error(f"Hash generation failed for {file_path}: {e}")
        raise

    return hashes
