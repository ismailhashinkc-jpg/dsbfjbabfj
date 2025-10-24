# Dockerfile for Hashi Zone Flask app
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (needed for bcrypt, pillow, qrcode, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first (caching optimization)
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . /app

# Create writable directory for database
RUN mkdir -p /data
VOLUME ["/data"]

# Environment variables
ENV HASHI_DB="sqlite:////data/hashi_zone.db"
ENV FLASK_ENV=production

# Expose port
EXPOSE 5000

# Start the app with Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "--workers", "3", "--threads", "2"]
