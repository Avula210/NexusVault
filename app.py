"""
NexusVault - Passkey Authentication Backend
Flask + py_webauthn + SQLite
"""

import json
import os
import sqlite3
import time
import uuid
from base64 import b64encode, b64decode
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS

import webauthn
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

app = Flask(__name__, template_folder="templates", static_folder="static")

# Secret key for session signing
app.secret_key = os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)

# ─── Environment Detection ────────────────────────────────────────────────────
DEPLOYED_URL = os.getenv("DEPLOYED_URL", "localhost:5000")
DEPLOYED_ORIGIN = os.getenv("DEPLOYED_ORIGIN", "https://localhost:5000")

# ─── WebAuthn Configuration ───────────────────────────────────────────────────
if "vercel.app" in DEPLOYED_URL:
    RP_ID = DEPLOYED_URL
    ORIGIN = DEPLOYED_ORIGIN
else:
    RP_ID = "localhost"
    ORIGIN = "https://localhost:5000"

RP_NAME = "NexusVault"
CHALLENGE_TIMEOUT = 300

# ─── CORS (AFTER ORIGIN is defined) ────────────────────────────────────────────
CORS(app, supports_credentials=True, origins=[ORIGIN])

# ─── Database Setup ───────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "nexusvault.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,           -- UUID
            username TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT DEFAULT 'member',    -- 'member' or 'admin'
            created_at INTEGER NOT NULL,
            last_login INTEGER
        )
    """)

    # Credentials table (one user can have multiple passkeys/devices)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,               -- credential_id (base64url)
            user_id TEXT NOT NULL,
            public_key BLOB NOT NULL,          -- COSE-encoded public key bytes
            sign_count INTEGER DEFAULT 0,      -- replay attack prevention
            transports TEXT,                   -- e.g. '["internal","hybrid"]'
            created_at INTEGER NOT NULL,
            last_used INTEGER,
            device_label TEXT,                 -- optional: "MacBook Touch ID"
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Active sessions table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Audit log
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            event TEXT NOT NULL,      -- 'register', 'login', 'logout', 'fail'
            detail TEXT,
            ip_address TEXT,
            timestamp INTEGER NOT NULL
        )
    """)

    conn.commit()
    conn.close()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def log_event(user_id, event, detail=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log(user_id,event,detail,ip_address,timestamp) VALUES(?,?,?,?,?)",
        (user_id, event, detail, request.remote_addr, int(time.time()))
    )
    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return user

def get_user_credentials(user_id):
    conn = get_db()
    creds = conn.execute("SELECT * FROM credentials WHERE user_id=?", (user_id,)).fetchall()
    conn.close()
    return creds

def rate_limit_check(username):
    """Check for too many failed attempts in the last 15 minutes."""
    conn = get_db()
    cutoff = int(time.time()) - 900  # 15 minutes
    fails = conn.execute(
        "SELECT COUNT(*) as c FROM audit_log WHERE detail=? AND event='fail' AND timestamp>?",
        (username, cutoff)
    ).fetchone()
    conn.close()
    return (fails["c"] or 0) >= 5  # block after 5 failures


# ─── Registration ─────────────────────────────────────────────────────────────

@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    data = request.get_json()
    username = (data.get("username") or "").strip().lower()
    display_name = (data.get("display_name") or "").strip()

    if not username or not display_name:
        return jsonify({"error": "Username and display name required"}), 400
    if len(username) < 3 or len(username) > 32:
        return jsonify({"error": "Username must be 3–32 characters"}), 400

    # Duplicate check
    existing = get_user_by_username(username)
    if existing:
        return jsonify({"error": "Username already registered"}), 409

    # Create a pending user ID (not committed until finish)
    user_id = str(uuid.uuid4())
    user_id_bytes = user_id.encode()

    # Get existing credentials for this user (empty for new user)
    exclude_credentials = []

    # Generate registration options
    # This creates a challenge the authenticator must sign
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id_bytes,
        user_name=username,
        user_display_name=display_name,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,   # ES256 (preferred)
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # RS256 fallback
        ],
        timeout=60000,  # 60s for user to respond
    )

    # Store challenge + pending user in session (expires with CHALLENGE_TIMEOUT)
    session["reg_challenge"] = bytes_to_base64url(options.challenge)
    session["reg_user_id"] = user_id
    session["reg_username"] = username
    session["reg_display_name"] = display_name
    session["reg_challenge_time"] = int(time.time())

    return jsonify(json.loads(options_to_json(options)))


@app.route("/api/register/finish", methods=["POST"])
def register_finish():
    # Retrieve challenge from session
    challenge_b64 = session.get("reg_challenge")
    challenge_time = session.get("reg_challenge_time", 0)
    user_id = session.get("reg_user_id")
    username = session.get("reg_username")
    display_name = session.get("reg_display_name")

    if not challenge_b64 or not user_id:
        return jsonify({"error": "No pending registration. Start again."}), 400

    # Challenge expiry check (anti-replay)
    if int(time.time()) - challenge_time > CHALLENGE_TIMEOUT:
        session.clear()
        return jsonify({"error": "Challenge expired. Please try again."}), 400

    credential_data = request.get_json()

    try:
        # py_webauthn verifies:
        #  1. challenge matches
        #  2. origin matches (anti-phishing)
        #  3. RP ID hash matches
        #  4. user verification flag set
        #  5. attestation is well-formed
        verification = verify_registration_response(
            credential=credential_data,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except Exception as e:
        log_event(user_id, "fail", username)
        return jsonify({"error": f"Registration verification failed: {str(e)}"}), 400

    # Store user + credential (public key) in DB
    now = int(time.time())
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users(id,username,display_name,role,created_at) VALUES(?,?,?,?,?)",
            (user_id, username, display_name, "member", now)
        )
        cred_id = bytes_to_base64url(verification.credential_id)
        conn.execute(
            """INSERT INTO credentials(id,user_id,public_key,sign_count,transports,created_at,device_label)
               VALUES(?,?,?,?,?,?,?)""",
            (
                cred_id,
                user_id,
                verification.credential_public_key,  # raw COSE bytes — public key only
                verification.sign_count,
                json.dumps(credential_data.get("response", {}).get("transports", [])),
                now,
                "Primary Device"
            )
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already taken"}), 409
    conn.close()

    # Clear registration session
    for k in ["reg_challenge","reg_user_id","reg_username","reg_display_name","reg_challenge_time"]:
        session.pop(k, None)

    log_event(user_id, "register", username)
    return jsonify({"status": "ok", "message": "Passkey registered successfully!"})


# ─── Authentication ───────────────────────────────────────────────────────────

@app.route("/api/login/begin", methods=["POST"])
def login_begin():
    data = request.get_json()
    username = (data.get("username") or "").strip().lower()

    if not username:
        return jsonify({"error": "Username required"}), 400

    # Rate limiting
    if rate_limit_check(username):
        return jsonify({"error": "Too many failed attempts. Try again in 15 minutes."}), 429

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get stored credentials (public keys) to tell authenticator which key to use
    creds = get_user_credentials(user["id"])
    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(c["id"]),
            transports=[AuthenticatorTransport(t) for t in json.loads(c["transports"] or "[]") if t],
        )
        for c in creds
    ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )

    session["auth_challenge"] = bytes_to_base64url(options.challenge)
    session["auth_username"] = username
    session["auth_user_id"] = user["id"]
    session["auth_challenge_time"] = int(time.time())

    return jsonify(json.loads(options_to_json(options)))


@app.route("/api/login/finish", methods=["POST"])
def login_finish():
    challenge_b64 = session.get("auth_challenge")
    challenge_time = session.get("auth_challenge_time", 0)
    username = session.get("auth_username")
    user_id = session.get("auth_user_id")

    if not challenge_b64 or not user_id:
        return jsonify({"error": "No pending login. Start again."}), 400

    if int(time.time()) - challenge_time > CHALLENGE_TIMEOUT:
        session.clear()
        return jsonify({"error": "Challenge expired."}), 400

    credential_data = request.get_json()
    credential_id = credential_data.get("id", "")

    # Look up the specific credential used
    conn = get_db()
    cred_row = conn.execute(
        "SELECT * FROM credentials WHERE id=? AND user_id=?",
        (credential_id, user_id)
    ).fetchone()

    if not cred_row:
        conn.close()
        log_event(user_id, "fail", username)
        return jsonify({"error": "Credential not found"}), 404

    try:
        # py_webauthn verifies:
        #  1. challenge signature (using stored public key)
        #  2. origin (anti-phishing)
        #  3. RP ID hash
        #  4. user verification flag
        #  5. sign_count > stored (anti-cloning/replay)
        verification = verify_authentication_response(
            credential=credential_data,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=cred_row["public_key"],
            credential_current_sign_count=cred_row["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        conn.close()
        log_event(user_id, "fail", username)
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 401

    # Update sign_count (monotonically increasing — prevents cloned authenticator replay)
    now = int(time.time())
    conn.execute(
        "UPDATE credentials SET sign_count=?, last_used=? WHERE id=?",
        (verification.new_sign_count, now, credential_id)
    )
    conn.execute("UPDATE users SET last_login=? WHERE id=?", (now, user_id))

    # Invalidate any existing sessions for this user (prevent multi-session)
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

    # Create new session record
    session_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO sessions(session_id,user_id,created_at,expires_at,ip_address,user_agent) VALUES(?,?,?,?,?,?)",
        (session_id, user_id, now, now + 3600, request.remote_addr, request.user_agent.string[:200])
    )
    conn.commit()
    conn.close()

    # Clear auth challenge from session
    for k in ["auth_challenge","auth_username","auth_user_id","auth_challenge_time"]:
        session.pop(k, None)

    # Set authenticated session
    session["user_id"] = user_id
    session["session_id"] = session_id
    session.permanent = True

    user = get_user_by_username(username)
    log_event(user_id, "login", username)
    return jsonify({
        "status": "ok",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
        }
    })


# ─── Protected Routes ─────────────────────────────────────────────────────────

@app.route("/api/me", methods=["GET"])
def me():
    user_id = session.get("user_id")
    session_id = session.get("session_id")
    if not user_id or not session_id:
        return jsonify({"error": "Not authenticated"}), 401

    # Validate session in DB (not just cookie)
    conn = get_db()
    db_session = conn.execute(
        "SELECT * FROM sessions WHERE session_id=? AND user_id=? AND expires_at>?",
        (session_id, user_id, int(time.time()))
    ).fetchone()
    if not db_session:
        conn.close()
        session.clear()
        return jsonify({"error": "Session expired or invalid"}), 401

    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    creds = conn.execute("SELECT id,created_at,last_used,device_label,sign_count FROM credentials WHERE user_id=?", (user_id,)).fetchall()
    logs = conn.execute(
        "SELECT event,detail,ip_address,timestamp FROM audit_log WHERE user_id=? ORDER BY timestamp DESC LIMIT 10",
        (user_id,)
    ).fetchall()
    conn.close()

    return jsonify({
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
            "created_at": user["created_at"],
            "last_login": user["last_login"],
        },
        "credentials": [dict(c) for c in creds],
        "recent_activity": [dict(l) for l in logs],
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    user_id = session.get("user_id")
    session_id = session.get("session_id")
    if user_id and session_id:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        conn.close()
        log_event(user_id, "logout", None)
    session.clear()
    return jsonify({"status": "ok"})


# ─── Admin Routes ─────────────────────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401
    conn = get_db()
    user = conn.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
    if not user or user["role"] != "admin":
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    users = conn.execute("SELECT id,username,display_name,role,created_at,last_login FROM users").fetchall()
    conn.close()
    return jsonify({"users": [dict(u) for u in users]})


# ─── Static Frontend ──────────────────────────────────────────────────────────

@app.route("/")
@app.route("/<path:path>")
def serve_frontend(path=""):
    return send_from_directory("templates", "index.html")


# Initialize database when app starts
init_db()

# For local development only
if __name__ == "__main__":
    print("\n🔐 NexusVault running at https://localhost:5000\n")
    app.run(debug=True, port=5000, ssl_context='adhoc')
