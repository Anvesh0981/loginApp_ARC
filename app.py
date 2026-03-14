"""
Login Credential Vault
Multi-user Flask app with PostgreSQL, admin-issued access keys,
static security questions, per-login completion status.
"""
import os, secrets, hashlib, threading, time, json
from datetime import datetime, date
from functools import wraps
from flask import (Flask, render_template, request, jsonify,
                   session, redirect, url_for, abort, stream_with_context, Response)
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# WebSocket support for VNC proxy
try:
    from flask_sock import Sock
    sock = Sock(app)
    _has_sock = True
except ImportError:
    _has_sock = False

# ── Config ────────────────────────────────────────────────────────────────────
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin1234")
TARGET_URL     = os.environ.get("TARGET_URL", "https://abc-app.example.com/login")

# Full list of selectable security questions (matches the target app dropdowns)
SECURITY_QUESTION_OPTIONS = [
    "What is your mother's maiden name?",
    "What was the name of your first/current/favorite pet?",
    "What was your first car?",
    "What elementary school did you attend?",
    "What is the name of the town/city where you were born?",
    "What is the name of the road/street you grew up on?",
    "What is your least favorite food?",
    "What was the first company that you worked for?",
    "What is your favorite food?",
    "What high school did you attend?",
    "Where did you meet your spouse?",
    "What is your sibling's middle name?",
    "Who was your childhood hero?",
    "In what city or town was your first job?",
    "What is the name of a college you applied to but didn't attend?",
]

LOGIN_STATUSES = ["pending", "in_progress", "completed", "failed"]

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_db():
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError("DATABASE_URL is not set in environment variables.")
    # Railway gives postgres:// but psycopg2 needs postgresql://
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    conn = psycopg2.connect(url, cursor_factory=RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS access_keys (
            id          SERIAL PRIMARY KEY,
            key_hash    TEXT UNIQUE NOT NULL,
            key_preview TEXT NOT NULL,
            custom_key  TEXT UNIQUE,
            owner_name  TEXT NOT NULL,
            owner_email TEXT NOT NULL DEFAULT '',
            is_active   BOOLEAN DEFAULT TRUE,
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            expires_at  TIMESTAMPTZ,
            notes       TEXT DEFAULT ''
        )
    """)
    c.execute("ALTER TABLE access_keys ADD COLUMN IF NOT EXISTS custom_key TEXT UNIQUE")
    c.execute("""
        CREATE TABLE IF NOT EXISTS logins (
            id           SERIAL PRIMARY KEY,
            key_id       INTEGER NOT NULL REFERENCES access_keys(id) ON DELETE CASCADE,
            label        TEXT NOT NULL,
            username     TEXT NOT NULL,
            password     TEXT NOT NULL,
            sel_q1       TEXT DEFAULT '',
            ans_q1       TEXT DEFAULT '',
            sel_q2       TEXT DEFAULT '',
            ans_q2       TEXT DEFAULT '',
            sel_q3       TEXT DEFAULT '',
            ans_q3       TEXT DEFAULT '',
            target_date  TEXT DEFAULT '',
            status       TEXT DEFAULT 'pending',
            notes        TEXT DEFAULT '',
            created_at   TIMESTAMPTZ DEFAULT NOW(),
            updated_at   TIMESTAMPTZ DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )
    """)
    # For existing deployments: add columns if missing
    for col in ["sel_q1","sel_q2","sel_q3"]:
        c.execute(f"ALTER TABLE logins ADD COLUMN IF NOT EXISTS {col} TEXT DEFAULT ''")
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         SERIAL PRIMARY KEY,
            key_id     INTEGER REFERENCES access_keys(id) ON DELETE SET NULL,
            action     TEXT NOT NULL,
            detail     TEXT DEFAULT '',
            ip_addr    TEXT DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    conn.commit()
    conn.close()

def log_action(key_id, action, detail=""):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO audit_log (key_id, action, detail, ip_addr) VALUES (%s,%s,%s,%s)",
            (key_id, action, detail, request.remote_addr)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def hash_key(raw_key):
    return hashlib.sha256(raw_key.encode()).hexdigest()

# ── Ensure tables exist on first request (works under gunicorn, no shell needed)
_db_initialized    = False  # set True after first init_db() call
_browser_sessions  = {}    # key_id -> threading.Event
captcha_store      = {}    # lid -> {"value": str, "event": threading.Event}

@app.before_request
def ensure_tables():
    global _db_initialized
    if not _db_initialized:
        try:
            init_db()
            _db_initialized = True
        except Exception as e:
            print(f"DB init warning: {e}")

# ── Auth decorators ───────────────────────────────────────────────────────────
def require_user(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("key_id"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH + SETUP
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/novnc")
@app.route("/novnc/<path:filename>")
def novnc_static(filename="vnc.html"):
    """Serve noVNC static files — no auth needed for JS/CSS assets."""
    novnc_path = "/usr/share/novnc"
    import os
    filepath = os.path.join(novnc_path, filename)
    if os.path.isfile(filepath):
        from flask import send_file
        return send_file(filepath)
    # Also check core subdir
    filepath2 = os.path.join(novnc_path, "core", filename.replace("core/",""))
    if os.path.isfile(filepath2):
        from flask import send_file
        return send_file(filepath2)
    return "Not found", 404

# WebSocket proxy: browser <-> Flask <-> local VNC :5900
# Registered after app init so sock is available
def _register_websockify():
    import socket, threading

    @sock.route("/websockify")
    def websockify(ws):
        """Proxy noVNC WebSocket to local VNC server on port 5900."""
        try:
            vnc = socket.create_connection(("localhost", 5900), timeout=5)
        except Exception as e:
            print(f"VNC connection failed: {e}", flush=True)
            return

        def ws_to_vnc():
            try:
                while True:
                    data = ws.receive()
                    if data is None: break
                    if isinstance(data, str): data = data.encode()
                    vnc.sendall(data)
            except Exception: pass
            finally:
                try: vnc.close()
                except: pass

        def vnc_to_ws():
            try:
                while True:
                    data = vnc.recv(65536)
                    if not data: break
                    ws.send(data)
            except Exception: pass
            finally:
                try: ws.close()
                except: pass

        t = threading.Thread(target=vnc_to_ws, daemon=True)
        t.start()
        ws_to_vnc()
        t.join()

if _has_sock:
    _register_websockify()

@app.route("/vnc")
@require_user
def vnc_viewer():
    """Full-screen noVNC — connects WebSocket through same Railway port."""
    return """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Vault — Live Browser</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0c0e15;font-family:system-ui,sans-serif;height:100vh;display:flex;flex-direction:column}
  .bar{background:#13161f;border-bottom:1px solid #1e2535;padding:0 20px;height:44px;
       display:flex;align-items:center;gap:12px;flex-shrink:0}
  .logo{color:#c8f04a;font-weight:800;font-size:0.88rem}
  .steps{display:flex;gap:6px;margin-left:8px}
  .step{font-size:0.7rem;padding:3px 10px;border-radius:99px;border:1px solid #1e2535;color:#5a6480}
  .step.done{border-color:rgba(61,255,160,0.3);color:#3dffa0;background:rgba(61,255,160,0.06)}
  .back{margin-left:auto;color:#5b9cf6;font-size:0.78rem;text-decoration:none;
        padding:4px 12px;border:1px solid rgba(91,156,246,0.3);border-radius:6px}
  #screen{flex:1;width:100%;border:none}
  .loading{flex:1;display:flex;align-items:center;justify-content:center;
           flex-direction:column;gap:14px;color:#5a6480;font-size:0.85rem}
  .spin{width:28px;height:28px;border:3px solid #1e2535;border-top-color:#c8f04a;
        border-radius:50%;animation:s 0.8s linear infinite}
  @keyframes s{to{transform:rotate(360deg)}}
</style>
</head>
<body>
  <div class="bar">
    <span class="logo">🔐 Vault Live Browser</span>
    <div class="steps">
      <span class="step">1 Solve captcha</span>
      <span class="step">2 Click Sign In</span>
      <span class="step">3 Answers auto-filled</span>
      <span class="step">4 Click Continue</span>
    </div>
    <a href="/dashboard" class="back">← Dashboard</a>
  </div>
  <div class="loading" id="loading">
    <div class="spin"></div>
    <div>Connecting to browser on server...</div>
    <div style="font-size:0.72rem;margin-top:4px">Takes a few seconds to start</div>
  </div>
  <canvas id="screen" style="display:none"></canvas>

  <!-- Load noVNC core directly -->
  <script type="module">
    import RFB from '/novnc/core/rfb.js';

    const loading = document.getElementById('loading');
    const canvas  = document.getElementById('screen');

    // WebSocket URL — same host/port as Flask, path /websockify
    const wsUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://') +
                  location.host + '/websockify';

    function connect() {
      loading.style.display = 'flex';
      canvas.style.display  = 'none';

      const rfb = new RFB(canvas, wsUrl, { wsProtocols: ['binary'] });

      rfb.addEventListener('connect', () => {
        loading.style.display = 'none';
        canvas.style.display  = 'block';
        rfb.scaleViewport = true;
        rfb.resizeSession = false;
      });

      rfb.addEventListener('disconnect', e => {
        if (!e.detail.clean) {
          loading.innerHTML =
            '<div class="spin"></div>' +
            '<div>Reconnecting...</div>';
          setTimeout(connect, 3000);
        }
      });

      rfb.addEventListener('credentialsrequired', () => rfb.sendCredentials({ password: '' }));
    }

    connect();
  </script>
</body>
</html>"""

@app.route("/setup-db")
def setup_db():
    secret = request.args.get("key", "")
    setup_secret = os.environ.get("SETUP_SECRET", "")
    if not setup_secret or secret != setup_secret:
        return "forbidden", 403
    try:
        init_db()
        return "Tables created successfully!", 200
    except Exception as e:
        return f"Error: {e}", 500

# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC — Access key login
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def root():
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))
    if session.get("key_id"):
        return redirect(url_for("user_dashboard"))
    return redirect(url_for("login_page"))

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def do_login():
    raw_key = request.json.get("access_key", "").strip()
    if not raw_key:
        return jsonify({"ok": False, "error": "Access key required"})

    conn = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT * FROM access_keys
           WHERE key_hash=%s AND is_active=TRUE
           AND (expires_at IS NULL OR expires_at > NOW())""",
        (hash_key(raw_key),)
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": "Invalid or expired access key"})

    session["key_id"]    = row["id"]
    session["key_owner"] = row["owner_name"]
    log_action(row["id"], "LOGIN", f"User {row['owner_name']} logged in")
    return jsonify({"ok": True})

@app.route("/logout")
def logout():
    kid = session.get("key_id")
    if kid:
        log_action(kid, "LOGOUT", "")
    session.clear()
    return redirect(url_for("login_page"))

# ══════════════════════════════════════════════════════════════════════════════
#  USER DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/dashboard")
@require_user
def user_dashboard():
    return render_template("dashboard.html",
                           owner=session["key_owner"],
                           question_options=SECURITY_QUESTION_OPTIONS,
                           target_url=TARGET_URL,
                           statuses=LOGIN_STATUSES)

# ── User API ──────────────────────────────────────────────────────────────────
@app.route("/api/logins", methods=["GET"])
@require_user
def api_list():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT * FROM logins WHERE key_id=%s ORDER BY created_at DESC",
        (session["key_id"],)
    )
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/logins", methods=["POST"])
@require_user
def api_create():
    d = request.json
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """INSERT INTO logins
           (key_id,label,username,password,
            sel_q1,ans_q1,sel_q2,ans_q2,sel_q3,ans_q3,
            target_date,status,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (session["key_id"], d.get("label",""), d.get("username",""),
         d.get("password",""),
         d.get("sel_q1",""), d.get("ans_q1",""),
         d.get("sel_q2",""), d.get("ans_q2",""),
         d.get("sel_q3",""), d.get("ans_q3",""),
         d.get("target_date",""), d.get("status","pending"), d.get("notes",""))
    )
    new_id = c.fetchone()["id"]
    conn.commit()
    conn.close()
    log_action(session["key_id"], "CREATE_LOGIN", f"Label: {d.get('label','')}")
    return jsonify({"ok": True, "id": new_id})

@app.route("/api/logins/<int:lid>", methods=["PUT"])
@require_user
def api_update(lid):
    d = request.json
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM logins WHERE id=%s AND key_id=%s", (lid, session["key_id"]))
    if not c.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "Not found"}), 404

    params = [d.get("label",""), d.get("username",""), d.get("password",""),
              d.get("sel_q1",""), d.get("ans_q1",""),
              d.get("sel_q2",""), d.get("ans_q2",""),
              d.get("sel_q3",""), d.get("ans_q3",""),
              d.get("target_date",""), d.get("status","pending"), d.get("notes",""),
              lid, session["key_id"]]

    if d.get("status") == "completed":
        c.execute(
            """UPDATE logins SET label=%s,username=%s,password=%s,
               sel_q1=%s,ans_q1=%s,sel_q2=%s,ans_q2=%s,sel_q3=%s,ans_q3=%s,
               target_date=%s,status=%s,notes=%s,
               updated_at=NOW(),completed_at=NOW()
               WHERE id=%s AND key_id=%s""", params
        )
    else:
        c.execute(
            """UPDATE logins SET label=%s,username=%s,password=%s,
               sel_q1=%s,ans_q1=%s,sel_q2=%s,ans_q2=%s,sel_q3=%s,ans_q3=%s,
               target_date=%s,status=%s,notes=%s,
               updated_at=NOW(),completed_at=NULL
               WHERE id=%s AND key_id=%s""", params
        )
    conn.commit()
    conn.close()
    log_action(session["key_id"], "UPDATE_LOGIN", f"ID:{lid} status:{d.get('status')}")
    return jsonify({"ok": True})

@app.route("/api/logins/<int:lid>", methods=["DELETE"])
@require_user
def api_delete(lid):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM logins WHERE id=%s AND key_id=%s", (lid, session["key_id"]))
    conn.commit()
    conn.close()
    log_action(session["key_id"], "DELETE_LOGIN", f"ID:{lid}")
    return jsonify({"ok": True})

@app.route("/api/stats", methods=["GET"])
@require_user
def api_stats():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT status, COUNT(*) as n FROM logins WHERE key_id=%s GROUP BY status",
              (session["key_id"],))
    rows = c.fetchall()
    conn.close()
    counts = {r["status"]: r["n"] for r in rows}
    total = sum(counts.values())
    return jsonify({
        "total":       total,
        "pending":     counts.get("pending", 0),
        "in_progress": counts.get("in_progress", 0),
        "completed":   counts.get("completed", 0),
        "failed":      counts.get("failed", 0),
    })

# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/login", methods=["GET"])
def admin_login_page():
    return render_template("admin_login.html")

@app.route("/admin/login", methods=["POST"])
def admin_do_login():
    pw = request.json.get("password", "")
    if pw != ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "Wrong password"})
    session["is_admin"] = True
    return jsonify({"ok": True})

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login_page"))

@app.route("/admin")
@require_admin
def admin_dashboard():
    return render_template("admin.html")

# ── Admin API ─────────────────────────────────────────────────────────────────
@app.route("/api/admin/keys", methods=["GET"])
@require_admin
def admin_list_keys():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT ak.*, COUNT(l.id) as login_count
        FROM access_keys ak
        LEFT JOIN logins l ON l.key_id = ak.id
        GROUP BY ak.id ORDER BY ak.created_at DESC
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/keys", methods=["POST"])
@require_admin
def admin_create_key():
    d = request.json
    custom = (d.get("custom_key") or "").strip()
    if custom:
        if len(custom) < 3 or " " in custom:
            return jsonify({"ok": False, "error": "Key must be at least 3 characters with no spaces"})
        raw_key = custom
    else:
        raw_key = "VLT-" + secrets.token_urlsafe(20)

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM access_keys WHERE custom_key=%s", (raw_key,))
    if c.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": f"Key \"{raw_key}\" is already in use. Choose a different one."})

    expires = d.get("expires_at") or None
    c.execute(
        """INSERT INTO access_keys
           (key_hash,key_preview,custom_key,owner_name,owner_email,expires_at,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (hash_key(raw_key), raw_key if len(raw_key) <= 14 else raw_key[:12]+"...",
         raw_key if custom else None,
         d.get("owner_name",""), d.get("owner_email",""),
         expires, d.get("notes",""))
    )
    new_id = c.fetchone()["id"]
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": new_id, "raw_key": raw_key, "is_custom": bool(custom)})

@app.route("/api/admin/keys/<int:kid>", methods=["PUT"])
@require_admin
def admin_update_key(kid):
    d = request.json
    new_key = (d.get("custom_key") or "").strip()

    conn = get_db()
    c = conn.cursor()

    if new_key:
        if len(new_key) < 3 or " " in new_key:
            conn.close()
            return jsonify({"ok": False, "error": "Key must be at least 3 characters with no spaces"})
        c.execute("SELECT id FROM access_keys WHERE custom_key=%s AND id!=%s", (new_key, kid))
        if c.fetchone():
            conn.close()
            return jsonify({"ok": False, "error": f"Key \"{new_key}\" is already in use."})
        c.execute(
            """UPDATE access_keys SET owner_name=%s,owner_email=%s,is_active=%s,
               expires_at=%s,notes=%s,key_hash=%s,key_preview=%s,custom_key=%s
               WHERE id=%s""",
            (d.get("owner_name",""), d.get("owner_email",""),
             d.get("is_active", True), d.get("expires_at") or None, d.get("notes",""),
             hash_key(new_key),
             new_key if len(new_key) <= 14 else new_key[:12]+"...",
             new_key, kid)
        )
    else:
        c.execute(
            """UPDATE access_keys SET owner_name=%s,owner_email=%s,
               is_active=%s,expires_at=%s,notes=%s WHERE id=%s""",
            (d.get("owner_name",""), d.get("owner_email",""),
             d.get("is_active", True), d.get("expires_at") or None,
             d.get("notes",""), kid)
        )

    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/admin/keys/<int:kid>", methods=["DELETE"])
@require_admin
def admin_delete_key(kid):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM access_keys WHERE id=%s", (kid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/admin/keys/<int:kid>/logins", methods=["GET"])
@require_admin
def admin_key_logins(kid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM logins WHERE key_id=%s ORDER BY created_at DESC", (kid,))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as n FROM access_keys")
    total_keys = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) as n FROM access_keys WHERE is_active=TRUE")
    active_keys = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) as n FROM logins")
    total_logins = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) as n FROM logins WHERE status='completed'")
    completed = c.fetchone()["n"]
    conn.close()
    return jsonify({"total_keys": total_keys, "active_keys": active_keys,
                    "total_logins": total_logins, "completed": completed})

@app.route("/api/admin/logs", methods=["GET"])
@require_admin
def admin_logs():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT al.*, ak.owner_name
        FROM audit_log al
        LEFT JOIN access_keys ak ON ak.id = al.key_id
        ORDER BY al.created_at DESC LIMIT 200
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ══════════════════════════════════════════════════════════════════════════════
#  PLAYWRIGHT RUN

@app.route("/api/run/captcha/<int:lid>", methods=["POST"])
@require_user
def submit_captcha(lid):
    """Receives captcha text from dashboard and unblocks the Playwright thread."""
    text = (request.json or {}).get("captcha", "").strip()
    if lid in captcha_store:
        captcha_store[lid]["value"] = text
        captcha_store[lid]["event"].set()
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "No active session for this login"})
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/run/<int:lid>", methods=["GET", "POST"])
@require_user
def run_login(lid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM logins WHERE id=%s AND key_id=%s", (lid, session["key_id"]))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "Login not found"}), 404

    login = dict(row)

    def automate():
        try:
            from playwright.sync_api import sync_playwright
            import shutil

            chromium_path = (
                os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH") or
                shutil.which("chromium") or "/usr/bin/chromium"
            )

            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=False,
                    executable_path=chromium_path,
                    args=["--no-sandbox", "--disable-setuid-sandbox",
                          "--disable-dev-shm-usage", "--start-maximized",
                          "--disable-blink-features=AutomationControlled"]
                )
                context = browser.new_context(
                    viewport={"width": 1280, "height": 900},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36"
                )
                page = context.new_page()

                # ── Open login page ───────────────────────────────────────
                print(f"[Vault] Opening {TARGET_URL}", flush=True)
                page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(2000)

                # ── Fill username ─────────────────────────────────────────
                def js_fill(selector, value):
                    page.evaluate("""([sel, val]) => {
                        const el = document.querySelector(sel);
                        if (!el) return;
                        const s = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')?.set;
                        if (s) s.call(el, val); else el.value = val;
                        ['focus','keydown','keypress','input','keyup','change','blur'].forEach(e =>
                            el.dispatchEvent(new Event(e, {bubbles:true, cancelable:true}))
                        );
                    }""", [selector, value])

                def js_fill_handle(handle, value):
                    page.evaluate("""([el, val]) => {
                        const s = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')?.set;
                        if (s) s.call(el, val); else el.value = val;
                        ['focus','keydown','keypress','input','keyup','change','blur'].forEach(e =>
                            el.dispatchEvent(new Event(e, {bubbles:true, cancelable:true}))
                        );
                    }""", [handle, value])

                # Username = first non-password/hidden input before the password field
                all_inputs = page.query_selector_all("input")
                pass_el = page.query_selector('input[type="password"]')
                pass_idx = next((i for i,el in enumerate(all_inputs) if el==pass_el), 999)

                user_el = next((
                    el for i,el in enumerate(all_inputs)
                    if i < pass_idx and
                    (el.get_attribute("type") or "text").lower() not in
                    ["hidden","submit","button","checkbox","radio","file","image"]
                ), None)

                if user_el:
                    js_fill_handle(user_el, login["username"])
                    print(f"[Vault] Username filled", flush=True)

                # ── Fill password ─────────────────────────────────────────
                page.wait_for_timeout(400)
                if pass_el:
                    js_fill_handle(pass_el, login["password"])
                    print(f"[Vault] Password filled", flush=True)

                # ── Wait for security questions page ──────────────────────
                # (user solves captcha and clicks Sign In in the VNC viewer)
                print("[Vault] Waiting for security questions page...", flush=True)
                try:
                    page.wait_for_function(
                        "() => document.body.innerText.toLowerCase().includes('security question')",
                        timeout=180000  # 3 minutes
                    )
                    print("[Vault] Security questions page detected!", flush=True)
                except Exception:
                    print("[Vault] Timed out waiting for security questions", flush=True)
                    page.wait_for_timeout(1800000)
                    browser.close()
                    return

                page.wait_for_timeout(1200)

                # ── Fill security answers ─────────────────────────────────
                answers = [
                    login.get("ans_q1") or "",
                    login.get("ans_q2") or "",
                    login.get("ans_q3") or "",
                ]
                answers = [a for a in answers if a.strip()]

                if answers:
                    all_inputs_now = page.query_selector_all("input")
                    answer_boxes = []
                    for el in all_inputs_now:
                        t = (el.get_attribute("type") or "text").lower()
                        # Exclude truly non-fillable types only
                        if t in ["hidden","submit","button","checkbox","radio","file","image","reset"]:
                            continue
                        # Skip username field
                        try:
                            val = el.input_value() or ""
                            if val.strip() == login["username"].strip():
                                continue
                        except Exception:
                            pass
                        answer_boxes.append(el)

                    print(f"[Vault] Found {len(answer_boxes)} answer box(es)", flush=True)

                    filled = 0
                    for i, box in enumerate(answer_boxes[:len(answers)]):
                        try:
                            js_fill_handle(box, answers[i])
                            filled += 1
                            print(f"[Vault] Answer {i+1} filled", flush=True)
                        except Exception as e:
                            print(f"[Vault] Answer {i+1} failed: {e}", flush=True)

                    print(f"[Vault] {filled} answer(s) filled. User can now click Continue.", flush=True)

                # ── Keep browser open for user to take over ───────────────
                page.wait_for_timeout(1800000)  # 30 minutes
                browser.close()

        except Exception as e:
            print(f"[Vault] Error: {e}", flush=True)

    # Kill any existing browser session for this user
    existing = _browser_sessions.pop(session["key_id"], None)
    if existing:
        try: existing.set()
        except: pass

    stop_event = threading.Event()
    _browser_sessions[session["key_id"]] = stop_event

    t = threading.Thread(target=automate, daemon=True)
    t.start()

    time.sleep(2)
    return redirect("/vnc")



# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    print("🔐 Credential Vault → http://127.0.0.1:5000")
    app.run(debug=True, port=5000)