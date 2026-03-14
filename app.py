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

try:
    from flask_sock import Sock
    sock = Sock(app)
    _has_sock = True
except ImportError:
    _has_sock = False

# ── Config ────────────────────────────────────────────────────────────────────
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin1234")
TARGET_URL     = os.environ.get("TARGET_URL", "https://abc-app.example.com/login")

STATIC_QUESTIONS = [
    "What is your mother's maiden name?",
    "What was the name of your first pet?",
    "What city were you born in?",
    "What was the name of your first school?",
]

LOGIN_STATUSES = ["pending", "in_progress", "completed", "failed"]

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_db():
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. "
            "In Railway: open your PostgreSQL service → Connect tab → "
            "copy DATABASE_URL → paste into your Flask service Variables."
        )
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
    # For existing deployments: add column if missing
    c.execute("ALTER TABLE access_keys ADD COLUMN IF NOT EXISTS custom_key TEXT UNIQUE")

    c.execute("""
        CREATE TABLE IF NOT EXISTS logins (
            id           SERIAL PRIMARY KEY,
            key_id       INTEGER NOT NULL REFERENCES access_keys(id) ON DELETE CASCADE,
            label        TEXT NOT NULL,
            username     TEXT NOT NULL,
            password     TEXT NOT NULL,
            ans_q1       TEXT DEFAULT '',
            ans_q2       TEXT DEFAULT '',
            ans_q3       TEXT DEFAULT '',
            ans_q4       TEXT DEFAULT '',
            target_date  TEXT DEFAULT '',
            status       TEXT DEFAULT 'pending',
            notes        TEXT DEFAULT '',
            created_at   TIMESTAMPTZ DEFAULT NOW(),
            updated_at   TIMESTAMPTZ DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )
    """)

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

# ── First-request DB init (works under gunicorn with no shell access) ─────────
_db_ready = False

@app.before_request
def ensure_db():
    global _db_ready
    if not _db_ready:
        try:
            init_db()
            _db_ready = True
        except Exception:
            pass  # error surfaces naturally on the actual DB call

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

# ── Ensure tables exist on every first request ───────────────────────────────
_db_initialized    = False
_browser_sessions  = {}
captcha_store      = {}

@app.before_request
def ensure_tables():
    global _db_initialized
    if not _db_initialized:
        try:
            init_db()
            _db_initialized = True
        except Exception as e:
            print(f"DB init warning: {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH + SETUP
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/healthz")
def healthz():
    return "ok", 200

@app.route("/setup-db")
def setup_db():
    """One-time manual trigger to create tables. Protected by SETUP_SECRET env var."""
    secret = request.args.get("key", "")
    setup_secret = os.environ.get("SETUP_SECRET", "")
    if not setup_secret or secret != setup_secret:
        return "forbidden", 403
    try:
        init_db()
        return "✅ Tables created successfully! You can remove SETUP_SECRET now.", 200
    except Exception as e:
        return f"❌ Error: {e}", 500

# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC — Access key login
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def root():
    if not os.environ.get("DATABASE_URL"):
        return (
            "<h2 style='font-family:sans-serif'>Setup required</h2>"
            "<p style='font-family:sans-serif'><b>DATABASE_URL</b> is not set.<br><br>"
            "In Railway: open your <b>PostgreSQL</b> service → <b>Connect</b> tab → "
            "copy <b>DATABASE_URL</b> → paste it into your Flask service "
            "<b>Variables</b> tab, then redeploy.</p>"
        ), 500
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
                           questions=STATIC_QUESTIONS,
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
           (key_id,label,username,password,ans_q1,ans_q2,ans_q3,ans_q4,
            target_date,status,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (session["key_id"], d.get("label",""), d.get("username",""),
         d.get("password",""), d.get("ans_q1",""), d.get("ans_q2",""),
         d.get("ans_q3",""), d.get("ans_q4",""), d.get("target_date",""),
         d.get("status","pending"), d.get("notes",""))
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
              d.get("ans_q1",""), d.get("ans_q2",""), d.get("ans_q3",""), d.get("ans_q4",""),
              d.get("target_date",""), d.get("status","pending"), d.get("notes",""),
              lid, session["key_id"]]

    if d.get("status") == "completed":
        c.execute(
            """UPDATE logins SET label=%s,username=%s,password=%s,
               ans_q1=%s,ans_q2=%s,ans_q3=%s,ans_q4=%s,
               target_date=%s,status=%s,notes=%s,
               updated_at=NOW(),completed_at=NOW()
               WHERE id=%s AND key_id=%s""", params
        )
    else:
        c.execute(
            """UPDATE logins SET label=%s,username=%s,password=%s,
               ans_q1=%s,ans_q2=%s,ans_q3=%s,ans_q4=%s,
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
    init_db()
    d = request.json
    custom = (d.get("custom_key") or "").strip()
    if custom:
        # Validate: no spaces, min 3 chars
        if len(custom) < 3 or " " in custom:
            return jsonify({"ok": False, "error": "Key must be at least 3 characters with no spaces"})
        raw_key = custom
    else:
        raw_key = "VLT-" + secrets.token_urlsafe(20)

    conn = get_db()
    c = conn.cursor()
    # Check uniqueness of custom key
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
        # Check uniqueness (excluding this record)
        c.execute("SELECT id FROM access_keys WHERE custom_key=%s AND id!=%s", (new_key, kid))
        if c.fetchone():
            conn.close()
            return jsonify({"ok": False, "error": f"Key \"{new_key}\" is already in use."})
        c.execute(
            """UPDATE access_keys SET owner_name=%s,owner_email=%s,is_active=%s,
               expires_at=%s,notes=%s,
               key_hash=%s,key_preview=%s,custom_key=%s
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
#  DEBUG + VNC + RUN
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/debug/screenshots")
def debug_screenshots():
    """List all debug screenshots taken during automation runs."""
    import glob
    screenshot_dir = "/tmp/vault_screenshots"
    if not os.path.isdir(screenshot_dir):
        return jsonify({"screenshots": [], "msg": "No screenshots directory yet"})
    files = sorted(glob.glob(f"{screenshot_dir}/*.png"), reverse=True)
    return jsonify({
        "screenshots": [os.path.basename(f) for f in files[:20]],
        "count": len(files)
    })

@app.route("/debug/screenshots/<filename>")
def debug_screenshot_file(filename):
    """Serve a specific debug screenshot."""
    from flask import send_file
    path = f"/tmp/vault_screenshots/{filename}"
    if not os.path.isfile(path):
        return "Not found", 404
    return send_file(path, mimetype="image/png")

@app.route("/debug/playwright")
def debug_playwright():
    """Test Playwright launch directly — shows result in browser."""
    import shutil, traceback
    result = {}
    try:
        os.environ["DISPLAY"] = ":99"
        chromium_path = (
            os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH") or
            shutil.which("chromium") or "/usr/bin/chromium"
        )
        result["chromium_path"] = chromium_path
        result["chromium_exists"] = os.path.isfile(chromium_path or "")

        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=False,
                executable_path=chromium_path,
                args=["--no-sandbox","--disable-setuid-sandbox",
                      "--disable-dev-shm-usage"]
            )
            page = browser.new_page()
            page.goto("about:blank")
            result["status"] = "SUCCESS - Playwright launched!"
            result["title"] = page.title()
            browser.close()
    except Exception as e:
        result["status"] = "FAILED"
        result["error"] = str(e)
        result["traceback"] = traceback.format_exc()
    return jsonify(result)

@app.route("/debug/vnc")
def debug_vnc():
    """Debug — check VNC and noVNC status. Remove after confirming it works."""
    import os, socket
    info = {}
    # Check noVNC files
    novnc_paths = ["/usr/share/novnc", "/usr/share/novnc/utils/novnc_proxy"]
    for p in novnc_paths:
        info[p] = os.path.exists(p)
    # List novnc dir
    novnc_dir = "/usr/share/novnc"
    if os.path.isdir(novnc_dir):
        info["novnc_files"] = os.listdir(novnc_dir)[:20]
        core_dir = os.path.join(novnc_dir, "core")
        if os.path.isdir(core_dir):
            info["novnc_core"] = os.listdir(core_dir)[:10]
    # Check VNC port
    try:
        s = socket.create_connection(("localhost", 5900), timeout=1)
        s.close()
        info["vnc_5900"] = "OPEN"
    except Exception as e:
        info["vnc_5900"] = f"CLOSED: {e}"
    # Check env
    info["DISPLAY"] = os.environ.get("DISPLAY", "not set")
    info["PLAYWRIGHT_CHROMIUM"] = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH", "not set")
    return jsonify(info)



# WebSocket proxy handled by flask-sock
if _has_sock:
    def _make_vnc_handler(name):
        def handler(ws):
            import socket
            try:
                vnc = socket.create_connection(("localhost", 5900), timeout=3)
                print(f"[VNC] {name}: connected to VNC :5900", flush=True)
            except Exception as e:
                print(f"[VNC] {name}: failed to connect: {e}", flush=True)
                return
            stop = threading.Event()
            def vnc_to_ws():
                try:
                    while not stop.is_set():
                        d = vnc.recv(65536)
                        if not d: break
                        ws.send(d)
                except Exception: pass
                finally: stop.set()
            t = threading.Thread(target=vnc_to_ws, daemon=True)
            t.start()
            try:
                while not stop.is_set():
                    d = ws.receive()
                    if d is None: break
                    if isinstance(d, str): d = d.encode()
                    vnc.sendall(d)
            except Exception: pass
            finally:
                stop.set()
                try: vnc.close()
                except: pass
                t.join(timeout=2)
        handler.__name__ = name
        return handler

    sock.route("/websockify")(_make_vnc_handler("ws1"))
    sock.route("/vnc-proxy/websockify")(_make_vnc_handler("ws2"))
    sock.route("/novnc-static/websockify")(_make_vnc_handler("ws3"))


@app.route("/vnc")
@require_user
def vnc_viewer():
    """VNC viewer - loads noVNC and connects WebSocket through Flask."""
    return """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Vault Live Browser</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0c0e15;font-family:system-ui,sans-serif;height:100vh;display:flex;flex-direction:column}
.bar{background:#13161f;border-bottom:1px solid #1e2535;padding:0 20px;height:44px;
     display:flex;align-items:center;gap:10px;flex-shrink:0}
.logo{color:#c8f04a;font-weight:800;font-size:0.9rem}
.step{font-size:0.7rem;padding:3px 10px;border-radius:99px;border:1px solid #1e2535;color:#5a6480}
.back{margin-left:auto;color:#5b9cf6;font-size:0.78rem;text-decoration:none;
      padding:4px 12px;border:1px solid rgba(91,156,246,0.3);border-radius:6px}
#screen{flex:1;width:100%}
</style>
</head>
<body>
<div class="bar">
  <span class="logo">&#128272; Vault Browser</span>
  <span class="step">1 Solve captcha</span>
  <span class="step">2 Sign In</span>
  <span class="step">3 Answers filled</span>
  <span class="step">4 Continue</span>
  <a href="/dashboard" class="back">&#8592; Dashboard</a>
</div>
<canvas id="screen"></canvas>
<script src="/novnc-static/core/rfb.js" type="module" id="rfb-script"></script>
<script type="module">
// Wait for rfb.js to be available
async function startVNC() {
  const wsUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://')
                + location.host + '/websockify';
  try {
    const { default: RFB } = await import('/novnc-static/core/rfb.js');
    const rfb = new RFB(document.getElementById('screen'), wsUrl);
    rfb.scaleViewport = true;
    rfb.addEventListener('connect', () => console.log('VNC connected'));
    rfb.addEventListener('disconnect', (e) => {
      if (!e.detail.clean) setTimeout(startVNC, 2000);
    });
  } catch(e) {
    console.error('VNC error:', e);
    document.getElementById('screen').outerHTML =
      '<div style="color:#c8f04a;padding:20px;font-family:monospace">VNC Error: ' + e + '</div>';
  }
}
startVNC();
</script>
</body>
</html>"""

@app.route("/novnc-static/<path:filename>")
def novnc_static(filename):
    """Serve noVNC static files."""
    import os
    for base in ["/usr/share/novnc", "/usr/share/novnc/core"]:
        fp = os.path.join(base, filename)
        if os.path.isfile(fp):
            from flask import send_file
            return send_file(fp)
        # try without subdir
        fp2 = os.path.join("/usr/share/novnc", filename)
        if os.path.isfile(fp2):
            from flask import send_file
            return send_file(fp2)
    return f"Not found: {filename}", 404



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

            # Set DISPLAY before launching so Chromium renders on Xvfb :99
            os.environ["DISPLAY"] = ":99"
            os.putenv("DISPLAY", ":99")

            # ── Screenshot dir for debugging ──────────────────────────
            SCREENSHOT_DIR = "/tmp/vault_screenshots"
            os.makedirs(SCREENSHOT_DIR, exist_ok=True)

            def take_screenshot(page, step_name):
                """Save a debug screenshot with timestamp."""
                try:
                    ts = int(time.time())
                    path = f"{SCREENSHOT_DIR}/{ts}_{step_name}.png"
                    page.screenshot(path=path, full_page=True)
                    print(f"[Vault] Screenshot saved: {path}", flush=True)
                except Exception as e:
                    print(f"[Vault] Screenshot failed ({step_name}): {e}", flush=True)

            # ── Retry wrapper for page.goto ───────────────────────────
            def safe_goto(page, url, retries=3):
                """Retry page navigation up to N times on failure."""
                for attempt in range(retries):
                    try:
                        print(f"[Vault] Navigation attempt {attempt + 1}/{retries}: {url}", flush=True)
                        page.goto(url, wait_until="domcontentloaded", timeout=60000)
                        # Verify the page actually loaded something
                        page.wait_for_load_state("domcontentloaded", timeout=15000)
                        print(f"[Vault] Page loaded successfully", flush=True)
                        return True
                    except Exception as e:
                        print(f"[Vault] Navigation attempt {attempt + 1} failed: {e}", flush=True)
                        take_screenshot(page, f"nav_retry_{attempt + 1}")
                        if attempt < retries - 1:
                            time.sleep(3)
                print(f"[Vault] All {retries} navigation attempts failed", flush=True)
                return False

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

                # ── FIX 1: Retry navigation to target URL ─────────────
                if not safe_goto(page, TARGET_URL):
                    take_screenshot(page, "final_nav_failure")
                    print("[Vault] FATAL: Could not open target URL after retries", flush=True)
                    page.wait_for_timeout(1800000)
                    browser.close()
                    return

                take_screenshot(page, "01_page_loaded")

                # ── JS fill helper (native setter for React/Angular) ──
                def js_fill_handle(handle, value):
                    page.evaluate("""([el, val]) => {
                        const s = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')?.set;
                        if (s) s.call(el, val); else el.value = val;
                        ['focus','keydown','keypress','input','keyup','change','blur'].forEach(e =>
                            el.dispatchEvent(new Event(e, {bubbles:true, cancelable:true}))
                        );
                    }""", [handle, value])

                # ── FIX 2: wait_for_selector before interacting ───────
                # Wait for at least one input and the password field to exist
                try:
                    page.wait_for_selector('input', state="attached", timeout=30000)
                    print("[Vault] Input elements found on page", flush=True)
                except Exception as e:
                    print(f"[Vault] No input elements found: {e}", flush=True)
                    take_screenshot(page, "no_inputs_found")
                    page.wait_for_timeout(1800000)
                    browser.close()
                    return

                # Wait specifically for password field (confirms login form is ready)
                try:
                    page.wait_for_selector('input[type="password"]', state="attached", timeout=30000)
                    print("[Vault] Password field found — login form is ready", flush=True)
                except Exception as e:
                    print(f"[Vault] Password field not found: {e}", flush=True)
                    take_screenshot(page, "no_password_field")
                    # Continue anyway — some sites load password field dynamically

                # Small pause for any late-loading JS
                page.wait_for_timeout(1500)

                # ── FIX 3: Use locator() API with auto-wait ──────────
                # Username = first non-password/hidden text input before the password field
                all_inputs = page.locator("input").all()
                pass_loc = page.locator('input[type="password"]')
                pass_el = pass_loc.first.element_handle() if pass_loc.count() > 0 else None

                # Find password index in DOM order
                pass_idx = 999
                input_handles = []
                for i, loc in enumerate(all_inputs):
                    handle = loc.element_handle()
                    input_handles.append(handle)
                    if pass_el and handle == pass_el:
                        pass_idx = i

                user_el = None
                for i, handle in enumerate(input_handles):
                    if i >= pass_idx:
                        break
                    try:
                        t = (handle.get_attribute("type") or "text").lower()
                    except Exception:
                        t = "text"
                    if t in ["hidden", "submit", "button", "checkbox", "radio", "file", "image"]:
                        continue
                    user_el = handle
                    break

                if user_el:
                    js_fill_handle(user_el, login["username"])
                    print("[Vault] Username filled", flush=True)
                else:
                    print("[Vault] WARNING: Could not find username input", flush=True)
                    take_screenshot(page, "no_username_field")

                # ── Fill password ─────────────────────────────────────
                page.wait_for_timeout(400)
                if pass_el:
                    js_fill_handle(pass_el, login["password"])
                    print("[Vault] Password filled", flush=True)
                else:
                    print("[Vault] WARNING: Could not find password input", flush=True)

                take_screenshot(page, "02_credentials_filled")

                # ── Wait for security questions page ──────────────────
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
                    take_screenshot(page, "sq_timeout")
                    page.wait_for_timeout(1800000)
                    browser.close()
                    return

                page.wait_for_timeout(1200)
                take_screenshot(page, "03_security_questions_page")

                # ── Fill security answers ─────────────────────────────
                answers = [
                    login.get("ans_q1") or "",
                    login.get("ans_q2") or "",
                    login.get("ans_q3") or "",
                ]
                answers = [a for a in answers if a.strip()]

                if answers:
                    # Re-query inputs on the new page using locator() API
                    page.wait_for_selector('input', state="attached", timeout=15000)
                    page.wait_for_timeout(800)

                    all_inputs_now = page.locator("input").all()
                    answer_boxes = []
                    for loc in all_inputs_now:
                        try:
                            el = loc.element_handle()
                            t = (el.get_attribute("type") or "text").lower()
                            # Exclude truly non-fillable types only
                            if t in ["hidden", "submit", "button", "checkbox", "radio", "file", "image", "reset"]:
                                continue
                            # Skip username field (may still be on page)
                            try:
                                val = loc.input_value(timeout=2000) or ""
                                if val.strip() == login["username"].strip():
                                    continue
                            except Exception:
                                pass
                            answer_boxes.append(el)
                        except Exception:
                            continue

                    print(f"[Vault] Found {len(answer_boxes)} answer box(es)", flush=True)

                    filled = 0
                    for i, box in enumerate(answer_boxes[:len(answers)]):
                        try:
                            js_fill_handle(box, answers[i])
                            filled += 1
                            print(f"[Vault] Answer {i+1} filled", flush=True)
                        except Exception as e:
                            print(f"[Vault] Answer {i+1} failed: {e}", flush=True)
                            take_screenshot(page, f"answer_{i+1}_failed")

                    take_screenshot(page, "04_answers_filled")
                    print(f"[Vault] {filled} answer(s) filled. User can now click Continue.", flush=True)

                # ── FIX 4: Detect login success/failure ───────────────
                # Check if we ended up somewhere meaningful
                current_url = page.url
                print(f"[Vault] Current URL: {current_url}", flush=True)
                # Check for common error indicators
                try:
                    error_visible = page.locator("text=incorrect").or_(
                        page.locator("text=invalid")).or_(
                        page.locator("text=error")).or_(
                        page.locator("text=failed"))
                    if error_visible.count() > 0 and error_visible.first.is_visible():
                        print("[Vault] WARNING: Possible error detected on page", flush=True)
                        take_screenshot(page, "possible_error_detected")
                except Exception:
                    pass

                # ── Keep browser open for user to take over ───────────
                page.wait_for_timeout(1800000)  # 30 minutes
                browser.close()

        except Exception as e:
            import traceback
            print(f"[Vault] Error: {e}", flush=True)
            print(traceback.format_exc(), flush=True)
            # Try to capture final error screenshot
            try:
                take_screenshot(page, "fatal_error")
            except Exception:
                pass

    # Kill any existing browser session for this user
    existing = _browser_sessions.pop(session["key_id"], None)
    if existing:
        try: existing.set()
        except: pass

    stop_event = threading.Event()
    _browser_sessions[session["key_id"]] = stop_event

    print(f"[Vault] Starting automation for login {lid}", flush=True)
    t = threading.Thread(target=automate, daemon=True)
    t.start()
    print(f"[Vault] Thread alive: {t.is_alive()}", flush=True)
    # Return success — dashboard will open /vnc separately
    return jsonify({"ok": True, "msg": "Browser launching"})




# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    print("🔐 Credential Vault → http://127.0.0.1:5000")
    app.run(debug=True, port=5000)