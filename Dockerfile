FROM python:3.11-slim

# Prevent Python from writing pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (Tesseract, FFmpeg, Poppler, etc.)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    ffmpeg \
    poppler-utils \
    libgl1-mesa-glx \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app/

# Expose default application port; allow Vercel or container runtimes to override it
ENV PORT=8501
EXPOSE 8501

# Run the database initializer, seed admin, then start the Streamlit app with a dynamic port
CMD ["sh", "-c", "python database/init_db.py && python database/seed_admin.py && streamlit run app.py --server.address=0.0.0.0 --server.port=${PORT:-8501}"]
