# Hashi Zone

Hashi Zone is a small Flask-based admin portal with **real authentication**, optional TOTP 2FA, and a green & black themed dashboard. This repository includes a safe **proxy list manager** (text-only; it does not route or proxy traffic).

## Features

- Secure authentication with bcrypt-hashed passwords
- Optional TOTP 2-factor authentication (setup via QR code)
- CSRF-protected forms and rate-limited login
- Proxy list manager (add/view/remove proxy entries as text)
- Dockerfile and docker-compose for easy deployment
- GitHub Actions CI workflow for linting & tests (basic)
- Clean green & black UI with responsive layout

> ⚠️ **Important security note:** Do NOT use this app to facilitate or distribute proxies for illegal activity or bypass network protections. The proxy manager stores text entries only.

---

## Quick start (local)

1. Clone the repo.
2. Create a Python venv and install dependencies:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Set admin password and secret (development):
```bash
export HASHI_ADMIN_PASS='YourDevPass123'
export HASHI_ADMIN_USER='hashi'
export HASHI_SECRET_KEY='change_this_secret'
```

4. Run:
```bash
python app.py
```
Visit `http://127.0.0.1:5000`.

## Using Docker

Build and run with Docker:

```bash
docker build -t hashi-zone .
docker run -p 5000:5000 -e HASHI_ADMIN_PASS='YourDevPass123' -e HASHI_ADMIN_USER='hashi' -e HASHI_SECRET_KEY='change_this' -v hashi_data:/data hashi-zone
```

Or with docker-compose:

```bash
docker compose up --build
```

## GitHub Actions (CI)

A basic GitHub Actions workflow is included at `.github/workflows/ci.yml`. It runs flake8 linting and some lightweight checks.

## Files of interest

- `app.py` — main Flask app
- `templates/`, `static/css/style.css` — UI templates & styles
- `Dockerfile`, `docker-compose.yml` — docker configs
- `.github/workflows/ci.yml` — CI workflow
- `requirements.txt`

## Next steps

- Add user management, roles, or audit logging.
- Enable HTTPS (via reverse proxy) for production.
- Replace raw password env usage with hashed password and secure secret management.

If you want, I can:
- Add automated backups for the SQLite DB.
- Add unit tests for the authentication flows.
- Deploy the app to a cloud provider (I can provide the steps).

