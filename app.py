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
_db_initialized = False

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
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/run/<int:lid>", methods=["POST"])
@require_user
def run_login(lid):
    """
    Launches a headless Playwright browser, fills username+password on page 1,
    then fills security question answers on page 2.
    Streams status updates as Server-Sent Events so the dashboard shows live progress.
    """
    # Fetch the login record
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM logins WHERE id=%s AND key_id=%s", (lid, session["key_id"]))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "Login not found"}), 404

    login = dict(row)

    def generate():
        def send(event, data):
            return "event: " + event + "\ndata: " + json.dumps(data) + "\n\n"

        yield send("status", {"msg": "🚀 Starting browser…", "step": 1})

        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        except ImportError:
            yield send("error", {"msg": "Playwright not installed. Run: playwright install chromium"})
            return

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox",
                          "--disable-dev-shm-usage", "--disable-gpu"]
                )
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0.0.0 Safari/537.36"
                )
                page = context.new_page()

                # ── Page 1: Login ──────────────────────────────────────────
                yield send("status", {"msg": "🌐 Opening login page…", "step": 2})
                page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(1500)

                yield send("status", {"msg": "✏️ Filling username & password…", "step": 3})

                # Fill username — find first text/email input
                username_filled = False
                for selector in [
                    'input[type="email"]',
                    'input[autocomplete="username"]',
                    'input[name="username"]',
                    'input[name="email"]',
                    'input[name="userId"]',
                    'input[id*="user" i]',
                    'input[id*="email" i]',
                    'input[placeholder*="user" i]',
                    'input[placeholder*="email" i]',
                ]:
                    try:
                        el = page.locator(selector).first
                        if el.is_visible(timeout=500):
                            el.fill(login["username"])
                            username_filled = True
                            break
                    except Exception:
                        continue

                # Fallback: first visible text input before password
                if not username_filled:
                    try:
                        inputs = page.locator(
                            'input:not([type="password"]):not([type="hidden"])'
                            ':not([type="submit"]):not([type="button"])'
                            ':not([type="checkbox"]):not([type="radio"])'
                        ).all()
                        for inp in inputs:
                            try:
                                if inp.is_visible(timeout=300):
                                    inp.fill(login["username"])
                                    username_filled = True
                                    break
                            except Exception:
                                continue
                    except Exception:
                        pass

                # Fill password
                password_filled = False
                try:
                    pwd_el = page.locator('input[type="password"]').first
                    if pwd_el.is_visible(timeout=2000):
                        pwd_el.fill(login["password"])
                        password_filled = True
                except Exception:
                    pass

                u_status = "✓ Username" if username_filled else "✗ Username"
                p_status = "✓ Password" if password_filled else "✗ Password"
                yield send("status", {
                    "msg": f"{u_status}  {p_status} filled — waiting for you to solve captcha & sign in…",
                    "step": 4,
                    "waiting_captcha": True
                })

                # ── Wait for navigation to security questions page ─────────
                # Poll until URL changes or "security question" appears — up to 3 min
                yield send("status", {"msg": "⏳ Waiting for security questions page…", "step": 5})

                security_page_found = False
                for _ in range(180):  # 180 x 1s = 3 minutes
                    try:
                        body_text = page.inner_text("body").lower()
                        if "security question" in body_text or "secret question" in body_text:
                            security_page_found = True
                            break
                    except Exception:
                        pass
                    time.sleep(1)

                if not security_page_found:
                    yield send("error", {"msg": "Security questions page not detected within 3 minutes."})
                    browser.close()
                    return

                yield send("status", {"msg": "🛡 Security questions page detected! Filling answers…", "step": 6})
                page.wait_for_timeout(800)

                # ── Page 2: Security questions ─────────────────────────────
                answers = [
                    {"q": (login.get("sel_q1") or "").lower(), "a": login.get("ans_q1") or ""},
                    {"q": (login.get("sel_q2") or "").lower(), "a": login.get("ans_q2") or ""},
                    {"q": (login.get("sel_q3") or "").lower(), "a": login.get("ans_q3") or ""},
                ]
                answers = [x for x in answers if x["a"].strip()]

                # Get all visible text inputs excluding username
                all_inputs = page.locator(
                    'input:not([type="password"]):not([type="hidden"])'
                    ':not([type="submit"]):not([type="button"])'
                    ':not([type="checkbox"]):not([type="radio"])'
                ).all()

                answer_boxes = []
                for inp in all_inputs:
                    try:
                        if inp.is_visible(timeout=300):
                            val = inp.input_value()
                            if val.strip() != login["username"].strip():
                                answer_boxes.append(inp)
                    except Exception:
                        continue

                filled = 0

                # Match by question text near each input
                used_answers = set()
                for i, box in enumerate(answer_boxes):
                    best_ans = None
                    best_score = 0
                    # Get bounding box and find nearby text
                    try:
                        # Use evaluate to get surrounding text
                        nearby = page.evaluate("""(el) => {
                            let text = '';
                            let node = el.parentElement;
                            for (let i = 0; i < 4 && node; i++) {
                                text += ' ' + (node.innerText || '');
                                node = node.parentElement;
                            }
                            return text.toLowerCase();
                        }""", box.element_handle())
                    except Exception:
                        nearby = ""

                    for j, ans in enumerate(answers):
                        if j in used_answers or not ans["q"]:
                            continue
                        q_words = [w for w in ans["q"].split() if len(w) > 3]
                        if not q_words:
                            continue
                        score = sum(1 for w in q_words if w in nearby) / len(q_words)
                        if score > best_score and score >= 0.25:
                            best_score = score
                            best_ans = (j, ans)

                    if best_ans:
                        try:
                            box.fill(best_ans[1]["a"])
                            used_answers.add(best_ans[0])
                            filled += 1
                        except Exception:
                            pass

                # Positional fallback
                if filled == 0:
                    for i, box in enumerate(answer_boxes[:len(answers)]):
                        ans = next((a for j,a in enumerate(answers) if j not in used_answers), None)
                        if ans:
                            try:
                                box.fill(ans["a"])
                                used_answers.add(i)
                                filled += 1
                            except Exception:
                                pass

                yield send("status", {
                    "msg": f"✓ {filled} answer{'s' if filled>1 else ''} filled — click Continue when ready",
                    "step": 7,
                    "done": True
                })

                # Keep browser open for 5 minutes so user can click Continue
                time.sleep(300)
                browser.close()

        except Exception as e:
            yield send("error", {"msg": f"Error: {str(e)}"})

    return app.response_class(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )

# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    print("🔐 Credential Vault → http://127.0.0.1:5000")
    app.run(debug=True, port=5000)