import os
import warnings
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_REPO_PATH = Path(os.getenv("EVIDENCE_REPO_PATH", str(BASE_DIR / "evidence_repository")))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "database" / "fafo.db")))
UPLOADS_DIR = BASE_DIR / "uploads"
EXPORTS_DIR = BASE_DIR / "exports"
LOGS_DIR = BASE_DIR / "logs"
TEMP_DIR = BASE_DIR / "temp_processing"

# Ensure directories exist
for d in [EVIDENCE_REPO_PATH, UPLOADS_DIR, EXPORTS_DIR, LOGS_DIR, TEMP_DIR]:
    d.mkdir(parents=True, exist_ok=True)
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

# Application Config
DEFAULT_SECRET_KEY = "fallback_dev_key_do_not_use_in_prod"
SECRET_KEY = os.getenv("SECRET_KEY", DEFAULT_SECRET_KEY)
if SECRET_KEY == DEFAULT_SECRET_KEY:
    warnings.warn("Using the fallback development secret key; set SECRET_KEY in your environment for production.", RuntimeWarning)
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "30"))

# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8501")

# Upload Config
ALLOWED_EXTENSIONS = {
    "image": [".png", ".jpg", ".jpeg"],
    "video": [".mp4", ".mov", ".avi", ".mkv", ".webm"],
    "audio": [".mp3", ".wav"],
    "document": [".pdf", ".docx", ".txt", ".zip"]
}
ALLOWED_EXTENSIONS_FLAT = {ext for exts in ALLOWED_EXTENSIONS.values() for ext in exts}
MAX_FILE_SIZE_MB = 100
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# Email Config
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
NOTIFICATION_EMAILS = [e.strip() for e in os.getenv("NOTIFICATION_EMAILS", "").split(",") if e.strip()]
