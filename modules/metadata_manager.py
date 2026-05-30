import os
from pathlib import Path
from PIL import Image, ExifTags
from datetime import datetime
import mimetypes
from typing import Any, Dict

def extract_file_metadata(file_path: Path) -> dict:
    """Extract basic file metadata."""
    if not file_path.exists():
        return {}
        
    stat = file_path.stat()
    mime_type, _ = mimetypes.guess_type(str(file_path))
    mime_type = mime_type or "application/octet-stream"
    
    metadata = {
        "file_size": stat.st_size,
        "created_at": datetime.utcfromtimestamp(stat.st_ctime).isoformat() + "Z",
        "modified_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
        "mime_type": mime_type,
        "extension": file_path.suffix.lower()
    }
    
    # Extract EXIF if image
    if mime_type.startswith('image/'):
        metadata["exif"] = extract_image_exif(file_path)
        
    return metadata

def extract_metadata(file_path: str, category: str) -> Dict[str, Any]:
    """Compatibility wrapper that returns the same metadata shape used by the hardened evidence pipeline."""
    metadata = extract_file_metadata(Path(file_path))
    metadata.setdefault("category", category)
    return metadata


def extract_image_exif(image_path: Path) -> dict:
    """Extract EXIF data from JPEG/TIFF images."""
    exif_data = {}
    try:
        img = Image.open(image_path)
        if hasattr(img, '_getexif') and img._getexif():
            exif = img._getexif()
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                # Filter out raw byte blobs that can't be serialized to JSON easily
                if isinstance(value, (str, int, float)):
                    exif_data[tag] = value
                elif isinstance(value, tuple):
                    # Convert tuples (like rational numbers for GPS) to strings
                    exif_data[tag] = str(value)
    except Exception:
        pass # Not all images have EXIF or are compatible
    return exif_data
