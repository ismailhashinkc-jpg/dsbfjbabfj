# Dockerfile for Hashi Zone Flask app
FROM python:3.11-slim

# set workdir
WORKDIR /app

# system deps (for pillow/qrcode/sqlalchemy/bcrypt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# copy project
COPY . /app

# create venv and install
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# create writable directory for database
RUN mkdir -p /data
VOLUME ["/data"]

ENV HASHI_DB="sqlite:////data/hashi_zone.db"
ENV FLASK_ENV=production

EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "--workers", "3", "--threads", "2"]
