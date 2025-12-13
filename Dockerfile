FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (including FFmpeg for transcoding)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY looter_app.py .

# Copy templates (required)
COPY templates/ templates/

# Create directories
RUN mkdir -p /config /storage static

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

# Use gevent for async if available, fallback to default
CMD ["python", "looter_app.py"]
