# FAFO Incident Preservation System

FAFO (Facts, Accountability, Forensics, and Observation) is a private, secure, enterprise-grade cybersecurity evidence preservation and incident documentation platform.

## Setup Instructions

1. Ensure Python 3.11+, `tesseract-ocr`, and `ffmpeg` are installed on your system.
2. Clone the repository and navigate to `fafo_project`.
3. Create a virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Copy `.env.example` to `.env` and fill in the values.
6. Initialize the database:
   ```bash
   python database/init_db.py
   ```
7. Run the Streamlit application:
   ```bash
   streamlit run app.py
   ```

## Streamlit Cloud Deployment

This repository is already Streamlit-ready because the main app is in `app.py` and the required dependencies are listed in `requirements.txt`.

1. Push your repository to GitHub.
2. Open https://share.streamlit.io and connect your GitHub account.
3. Select this repository and choose `app.py` as the main file.
4. In the Streamlit app settings, add environment variables for production, such as:
   - `SECRET_KEY`
   - `DATABASE_PATH` (usually `./database/fafo.db`)
   - `EVIDENCE_REPO_PATH` (usually `./evidence_repository`)
   - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`
   - `NOTIFICATION_EMAILS`
   - `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` (if using Google OAuth)
5. Deploy and open the live app URL.

> Note: The app requires `tesseract-ocr` and `ffmpeg` at build/runtime. Streamlit Cloud does not install system packages automatically, so if you need those tools in production, use a Docker deployment or a custom VM.

## Docker / Vercel Deployment

This project can be containerized and deployed to Vercel using the included `Dockerfile` and `vercel.json`.

1. Build locally with Docker:
   ```bash
   docker build -t fafo_incident_system .
   ```

2. Run locally with Docker:
   ```bash
   docker run --rm -p 8501:8501 fafo_incident_system
   ```

3. Deploy to Vercel:
   - Add the project to Vercel.
   - Configure environment variables in Vercel for `SECRET_KEY`, `SMTP_USER`, `SMTP_PASS`, any OAuth values, and any app-specific settings.
   - Ensure `DATABASE_PATH` is set to `./database/fafo.db` if needed.
   - Vercel will use the `Dockerfile` and `vercel.json` to build the container.
