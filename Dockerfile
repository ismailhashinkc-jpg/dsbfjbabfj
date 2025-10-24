# Dockerfile for Hashi Zone Flask app
FROM python:3.11-slim

# Set workdir
WORKDIR /app

# System deps (for pillow/qrcode/sqlalchemy/bcrypt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . /app

# Create virtual environment and add to PATH
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Create writable directory for database
RUN mkdir -p /data
VOLUME ["/data"]

# Environment variables
ENV HASHI_DB="sqlite:////data/hashi_zone.db"
ENV FLASK_ENV=production

# Expose port
EXPOSE 5000

# Start app with gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "--workers", "3", "--threads", "2"]
