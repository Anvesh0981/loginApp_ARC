# Credential Vault — Deployment Guide

Multi-user login credential manager with admin-issued access keys, static security questions, completion status tracking, and PostgreSQL backend.

---

## Tech Stack

| Layer      | Choice                          | Why                                          |
|------------|----------------------------------|----------------------------------------------|
| Server     | **Railway.app**                 | Git-push deploy, free tier, auto-SSL         |
| Database   | **PostgreSQL** (Railway addon)  | Multi-user safe, concurrent access, reliable |
| App        | **Flask + Gunicorn**            | Lightweight, fast to deploy                  |

---

## Architecture

```
Users (access key) ─┐
                     ├─► Flask App (Railway) ──► PostgreSQL
Admin (password) ───┘         │
                               ├── access_keys table
                               ├── logins table
                               └── audit_log table
```

---

## Deploy to Railway in 5 Steps

### Step 1 — Create Railway account
Go to https://railway.app and sign up (free).

### Step 2 — New project from GitHub
1. Push this folder to a GitHub repo
2. In Railway: **New Project → Deploy from GitHub repo**
3. Select your repo

### Step 3 — Add PostgreSQL
In your Railway project: **+ New → Database → Add PostgreSQL**
Railway automatically sets `DATABASE_URL` in your app environment.

### Step 4 — Set environment variables
In Railway → your service → **Variables**, add:

```
SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_hex(32))">
ADMIN_PASSWORD=<your strong admin password>
TARGET_URL=https://your-actual-app.com/login
```

`DATABASE_URL` is set automatically by the PostgreSQL addon.

### Step 5 — Deploy
Railway auto-deploys on every git push. The first deploy also runs `init_db()` automatically which creates all tables.

**Your app is live at:** `https://your-project.up.railway.app`

---

## Using the App

### Admin workflow
1. Go to `/admin/login` → enter admin password
2. Click **"Generate Access Key"**
3. Fill in the user's name and optional email / expiry
4. Copy the generated key (shown only once!) and share it with the user
5. From the admin panel you can:
   - View all access keys (active / disabled / expired)
   - Enable/disable any key
   - See all logins saved under each key
   - Read the full audit log

### User workflow
1. Go to `/` or `/login`
2. Enter the access key provided by admin
3. Save login profiles with:
   - Username + password
   - 4 static security question answers
   - Status: Pending / In Progress / Completed / Failed
   - Optional target date and notes
4. Update status to **Completed** — the completion timestamp is recorded automatically

---

## Database Schema

```sql
access_keys
  id, key_hash, key_preview, owner_name, owner_email,
  is_active, created_at, expires_at, notes

logins
  id, key_id (FK), label, username, password,
  ans_q1..ans_q4, target_date, status, notes,
  created_at, updated_at, completed_at

audit_log
  id, key_id (FK), action, detail, ip_addr, created_at
```

---

## Security Notes

- Passwords are stored **as-is** — for production add encryption using the `cryptography` library
- Access keys are stored as **SHA-256 hashes** — the raw key is never saved
- Admin password is checked via direct string comparison — fine for low-traffic internal tools
- Use Railway's built-in HTTPS — never run without SSL in production
- Set `SESSION_COOKIE_SECURE=True` and `SESSION_COOKIE_HTTPONLY=True` in production

---

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set up local PostgreSQL
createdb credential_vault

# Set env vars
export DATABASE_URL=postgresql://localhost/credential_vault
export SECRET_KEY=dev_secret_key
export ADMIN_PASSWORD=admin123
export TARGET_URL=https://example.com/login

# Run
python app.py
# → http://127.0.0.1:5000
```

---

## Alternative Deployment Platforms

| Platform      | Notes                                           |
|---------------|-------------------------------------------------|
| **Render**    | Similar to Railway, free tier available         |
| **Fly.io**    | Docker-based, generous free tier                |
| **Heroku**    | Paid only, but very mature                      |
| **DigitalOcean App Platform** | $5/month, straightforward         |
| **VPS (Ubuntu)** | Full control, use nginx + gunicorn + systemd |

For a VPS setup, add `nginx.conf` proxying to gunicorn on port 5000 and a `systemd` service file.
