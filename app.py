# AraxisLauncher — Backend API
# Flask + SQLite

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, bcrypt, jwt, uuid, datetime, secrets, os, random, string

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "araxis.db")

PLANS = {"weekly": 7, "monthly": 30, "lifetime": 36500}

# ── DATABASE ─────────────────────────────────────────────────────────────────────
def get_db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with get_db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         TEXT PRIMARY KEY,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT DEFAULT 'user',
            banned     INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            plan       TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            active     INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS promo_codes (
            id       TEXT PRIMARY KEY,
            code     TEXT UNIQUE NOT NULL,
            plan     TEXT NOT NULL,
            uses     INTEGER DEFAULT 0,
            max_uses INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS activation_keys (
            id         TEXT PRIMARY KEY,
            key        TEXT UNIQUE NOT NULL,
            plan       TEXT NOT NULL,
            email      TEXT,
            redeemed   INTEGER DEFAULT 0,
            user_id    TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            redeemed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS logs (
            id      TEXT PRIMARY KEY,
            user_id TEXT,
            action  TEXT,
            details TEXT,
            ip      TEXT,
            ts      TEXT DEFAULT (datetime('now'))
        );
        """)
        # Admin par défaut
        try:
            uid = str(uuid.uuid4())
            pw  = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
            con.execute("INSERT INTO users (id,email,password,role) VALUES (?,?,?,?)",
                        (uid, "admin@araxis.local", pw, "admin"))
            con.commit()
        except Exception:
            pass

init_db()

# ── HELPERS ──────────────────────────────────────────────────────────────────────
def make_token(uid):
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    return jwt.encode({"user_id": uid, "exp": exp}, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["user_id"]
    except Exception:
        return None

def get_user(uid):
    with get_db() as con:
        r = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return dict(r) if r else None

def active_sub(uid):
    with get_db() as con:
        r = con.execute("""
            SELECT * FROM subscriptions
            WHERE user_id=? AND active=1 AND expires_at > datetime('now')
            ORDER BY expires_at DESC LIMIT 1
        """, (uid,)).fetchone()
    return dict(r) if r else None

def sub_info(sub):
    if not sub:
        return None
    exp   = datetime.datetime.fromisoformat(sub["expires_at"])
    delta = exp - datetime.datetime.utcnow()
    secs  = int(delta.total_seconds())
    return {
        "plan":       sub["plan"],
        "expires_at": sub["expires_at"],
        "days":       max(secs // 86400, 0),
        "hours":      max((secs % 86400) // 3600, 0),
        "mins":       max((secs % 3600) // 60, 0),
        "active":     secs > 0,
    }

def log_it(uid, action, details="", ip=""):
    with get_db() as con:
        con.execute("INSERT INTO logs (id,user_id,action,details,ip) VALUES (?,?,?,?,?)",
                    (str(uuid.uuid4()), uid, action, details, ip))
        con.commit()

def gen_activation_key(plan):
    """Génère une clé du type ARX-MO-XXXXX-XXXXX-XXXXX"""
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    seg = lambda: ''.join(random.choices(chars, k=5))
    pfx = {"weekly": "WK", "monthly": "MO", "lifetime": "LT"}.get(plan, "XX")
    return f"ARX-{pfx}-{seg()}-{seg()}-{seg()}"

def auth_required(f):
    from functools import wraps
    @wraps(f)
    def w(*a, **kw):
        token = request.headers.get("Authorization","").replace("Bearer ","")
        uid   = decode_token(token)
        if not uid: return jsonify({"error":"Token invalide"}), 401
        user  = get_user(uid)
        if not user: return jsonify({"error":"Introuvable"}), 401
        if user["banned"]: return jsonify({"error":"Compte banni"}), 403
        return f(user, *a, **kw)
    return w

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def w(*a, **kw):
        token = request.headers.get("Authorization","").replace("Bearer ","")
        uid   = decode_token(token)
        if not uid: return jsonify({"error":"Non autorisé"}), 401
        user  = get_user(uid)
        if not user or user["role"] != "admin":
            return jsonify({"error":"Accès refusé"}), 403
        return f(user, *a, **kw)
    return w

# ── AUTH ─────────────────────────────────────────────────────────────────────────
@app.post("/api/register")
def register():
    d  = request.json or {}
    em = d.get("email","").strip().lower()
    pw = d.get("password","")
    if not em or len(pw) < 6:
        return jsonify({"error":"Email requis + mot de passe min. 6 caractères"}), 400
    h   = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    uid = str(uuid.uuid4())
    try:
        with get_db() as con:
            con.execute("INSERT INTO users (id,email,password) VALUES (?,?,?)", (uid,em,h))
            con.commit()
        log_it(uid, "REGISTER", em, request.remote_addr)
        return jsonify({"token": make_token(uid), "message": "Compte créé"})
    except sqlite3.IntegrityError:
        return jsonify({"error":"Email déjà utilisé"}), 409

@app.post("/api/login")
def login():
    d  = request.json or {}
    em = d.get("email","").strip().lower()
    pw = d.get("password","")
    with get_db() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (em,)).fetchone()
    if not row:
        return jsonify({"error":"Email ou mot de passe incorrect"}), 401
    user = dict(row)
    if user["banned"]:
        return jsonify({"error":"Compte banni"}), 403
    if not bcrypt.checkpw(pw.encode(), user["password"].encode()):
        log_it(user["id"], "LOGIN_FAIL", "", request.remote_addr)
        return jsonify({"error":"Email ou mot de passe incorrect"}), 401
    log_it(user["id"], "LOGIN", "", request.remote_addr)
    sub = active_sub(user["id"])
    return jsonify({
        "token": make_token(user["id"]),
        "user":  {"id":user["id"], "email":user["email"], "role":user["role"]},
        "subscription": sub_info(sub),
    })

@app.get("/api/me")
@auth_required
def me(u):
    sub = active_sub(u["id"])
    return jsonify({
        "user": {"id":u["id"], "email":u["email"], "role":u["role"]},
        "subscription": sub_info(sub),
    })

# ── SUBSCRIPTION ─────────────────────────────────────────────────────────────────
@app.post("/api/subscription/verify")
@auth_required
def verify(u):
    sub = active_sub(u["id"])
    log_it(u["id"], "LAUNCH_VERIFY", "", request.remote_addr)
    if sub:
        return jsonify({"authorized":True, "subscription":sub_info(sub)})
    return jsonify({"authorized":False, "message":"Abonnement inactif ou expiré"}), 403

@app.post("/api/promo/apply")
@auth_required
def apply_promo(u):
    code = (request.json or {}).get("code","").strip().upper()
    with get_db() as con:
        promo = con.execute(
            "SELECT * FROM promo_codes WHERE code=? AND uses < max_uses", (code,)
        ).fetchone()
        if not promo:
            return jsonify({"error":"Code invalide ou épuisé"}), 400
        promo = dict(promo)
        days  = PLANS.get(promo["plan"], 30)
        exp   = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).isoformat()
        con.execute("INSERT INTO subscriptions (id,user_id,plan,expires_at) VALUES (?,?,?,?)",
                    (str(uuid.uuid4()), u["id"], promo["plan"], exp))
        con.execute("UPDATE promo_codes SET uses=uses+1 WHERE id=?", (promo["id"],))
        con.commit()
    log_it(u["id"], "PROMO_APPLIED", code, request.remote_addr)
    return jsonify({"message":"Code appliqué !", "expires_at":exp})

# ── ACTIVATION KEYS (ACHAT SITE WEB) ─────────────────────────────────────────────

@app.post("/api/keys/generate")
def generate_key():
    """
    Appelé par le site web après un paiement réussi.
    Nécessite un secret partagé (WEBHOOK_SECRET) pour sécuriser l'appel.
    En mode démo : accepte sans vérification.
    """
    d      = request.json or {}
    plan   = d.get("plan", "monthly")
    email  = d.get("email", "").strip().lower()
    secret = d.get("secret", "")

    # Sécurité : vérifie le secret partagé
    expected = os.environ.get("WEBHOOK_SECRET", "araxis_demo_secret")
    if secret != expected:
        return jsonify({"error": "Non autorisé"}), 401

    if plan not in PLANS:
        return jsonify({"error": "Plan invalide"}), 400

    key = gen_activation_key(plan)
    kid = str(uuid.uuid4())
    with get_db() as con:
        con.execute(
            "INSERT INTO activation_keys (id,key,plan,email) VALUES (?,?,?,?)",
            (kid, key, plan, email)
        )
        con.commit()

    log_it(None, "KEY_GENERATED", f"{key} plan={plan} email={email}", request.remote_addr)
    return jsonify({"key": key, "plan": plan})


@app.post("/api/keys/redeem")
@auth_required
def redeem_key(u):
    """
    Le client entre sa clé dans le launcher → active son abonnement.
    """
    key_str = (request.json or {}).get("key", "").strip().upper()
    with get_db() as con:
        row = con.execute(
            "SELECT * FROM activation_keys WHERE key=? AND redeemed=0", (key_str,)
        ).fetchone()
        if not row:
            return jsonify({"error": "Clé invalide ou déjà utilisée"}), 400
        row = dict(row)
        days = PLANS.get(row["plan"], 30)
        exp  = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).isoformat()
        con.execute(
            "INSERT INTO subscriptions (id,user_id,plan,expires_at) VALUES (?,?,?,?)",
            (str(uuid.uuid4()), u["id"], row["plan"], exp)
        )
        con.execute(
            "UPDATE activation_keys SET redeemed=1, user_id=?, redeemed_at=datetime('now') WHERE id=?",
            (u["id"], row["id"])
        )
        con.commit()
    log_it(u["id"], "KEY_REDEEMED", key_str, request.remote_addr)
    return jsonify({"message": "Clé activée !", "plan": row["plan"], "expires_at": exp})


# ── ADMIN ─────────────────────────────────────────────────────────────────────────
@app.get("/api/admin/users")
@admin_required
def admin_users(u):
    with get_db() as con:
        rows = con.execute("SELECT id,email,role,banned,created_at FROM users").fetchall()
    result = []
    for r in rows:
        ud = dict(r)
        ud["subscription"] = sub_info(active_sub(ud["id"]))
        result.append(ud)
    return jsonify(result)

@app.post("/api/admin/ban")
@admin_required
def admin_ban(u):
    d = request.json or {}
    with get_db() as con:
        con.execute("UPDATE users SET banned=? WHERE id=?", (int(d.get("banned",1)), d.get("user_id")))
        con.commit()
    log_it(u["id"], "BAN" if d.get("banned") else "UNBAN", d.get("user_id",""))
    return jsonify({"message":"Mis à jour"})

@app.post("/api/admin/set-role")
@admin_required
def admin_role(u):
    d    = request.json or {}
    uid  = d.get("user_id")
    role = d.get("role","user")
    if role not in ("user","admin"):
        return jsonify({"error":"Rôle invalide"}), 400
    with get_db() as con:
        con.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
        con.commit()
    log_it(u["id"], "SET_ROLE", f"{uid}->{role}")
    return jsonify({"message":"Rôle mis à jour"})

@app.post("/api/admin/grant-sub")
@admin_required
def admin_grant(u):
    d    = request.json or {}
    uid  = d.get("user_id")
    plan = d.get("plan","monthly")
    days = PLANS.get(plan, 30)
    exp  = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).isoformat()
    with get_db() as con:
        con.execute("INSERT INTO subscriptions (id,user_id,plan,expires_at) VALUES (?,?,?,?)",
                    (str(uuid.uuid4()), uid, plan, exp))
        con.commit()
    log_it(u["id"], "ADMIN_GRANT", f"{uid} plan={plan}")
    return jsonify({"message":"Abonnement accordé", "expires_at":exp})

@app.post("/api/admin/promo/create")
@admin_required
def admin_create_promo(u):
    d    = request.json or {}
    code = d.get("code","").strip().upper()
    plan = d.get("plan","monthly")
    mu   = int(d.get("max_uses", 1))
    if not code:
        return jsonify({"error":"Code requis"}), 400
    try:
        with get_db() as con:
            con.execute("INSERT INTO promo_codes (id,code,plan,max_uses) VALUES (?,?,?,?)",
                        (str(uuid.uuid4()), code, plan, mu))
            con.commit()
        log_it(u["id"], "PROMO_CREATED", f"{code} plan={plan}")
        return jsonify({"message":"Code créé"})
    except sqlite3.IntegrityError:
        return jsonify({"error":"Code déjà existant"}), 409

@app.get("/api/admin/logs")
@admin_required
def admin_logs(u):
    with get_db() as con:
        rows = con.execute("SELECT * FROM logs ORDER BY ts DESC LIMIT 300").fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/admin/promos")
@admin_required
def admin_promos(u):
    with get_db() as con:
        rows = con.execute("SELECT * FROM promo_codes").fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/admin/keys")
@admin_required
def admin_keys(u):
    with get_db() as con:
        rows = con.execute(
            "SELECT * FROM activation_keys ORDER BY created_at DESC LIMIT 300"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"AraxisLauncher API → http://localhost:{port}")
    print("Admin : admin@araxis.local / admin123")
    app.run(host="0.0.0.0", port=port, debug=False)
