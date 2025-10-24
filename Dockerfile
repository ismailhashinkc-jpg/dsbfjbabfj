# Use official slim Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Create writable directory for SQLite database
RUN mkdir -p /data
VOLUME ["/data"]

# Environment variables
ENV HASHI_DB="sqlite:////data/hashi_zone.db"
ENV FLASK_ENV=production

# Expose the port that Render uses
ENV PORT=10000
EXPOSE $PORT

# Run the app with Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:$PORT", "app:app", "--workers", "3", "--threads", "2"]
