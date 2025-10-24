# Dockerfile for Hashi Zone Flask app
FROM python:3.11-slim

# Set workdir
WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . /app

# Create venv and add to PATH
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip
RUN pip install --upgrade pip

# Install requirements with compatibility fixes
RUN pip install -r requirements.txt
RUN pip install "Werkzeug<3" "Flask-WTF>=1.1.1"

# Create writable directory for database
RUN mkdir -p /data
VOLUME ["/data"]

# Environment variables
ENV HASHI_DB="sqlite:////data/hashi_zone.db"
ENV FLASK_ENV=production

# Expose port 5000
EXPOSE 5000

# Start Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "--workers", "3", "--threads", "2"]
