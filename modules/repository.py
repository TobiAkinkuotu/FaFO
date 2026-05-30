import json
from pathlib import Path
from config.settings import EVIDENCE_REPO_PATH

def init_incident_repo(incident_id: str) -> Path:
    """Create the folder structure for a new incident."""
    incident_dir = EVIDENCE_REPO_PATH / incident_id
    
    # Subdirectories
    (incident_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    (incident_dir / "videos").mkdir(parents=True, exist_ok=True)
    (incident_dir / "audio").mkdir(parents=True, exist_ok=True)
    (incident_dir / "documents").mkdir(parents=True, exist_ok=True)
    
    # Initialize empty JSON sidecar files
    for filename in ["metadata.json", "hashes.json", "ocr_results.json", "ai_analysis.json"]:
        file_path = incident_dir / filename
        if not file_path.exists():
            with open(file_path, "w") as f:
                json.dump({}, f)
                
    return incident_dir

def get_incident_repo(incident_id: str) -> Path:
    """Get the path to an existing incident repository."""
    return EVIDENCE_REPO_PATH / incident_id

def route_file_to_subfolder(mime_type: str) -> str:
    """Determine the correct subfolder based on mime type."""
    if mime_type.startswith("image/"):
        return "screenshots"
    elif mime_type.startswith("video/"):
        return "videos"
    elif mime_type.startswith("audio/"):
        return "audio"
    else:
        return "documents"
