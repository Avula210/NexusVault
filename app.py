import json
import os
import time
import uuid
from datetime import timedelta

from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS

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

# Firebase DB functions
from db import (
    create_user,
    get_user_by_username,
    get_user,
    update_user_last_login,
    create_credential,
    get_user_credentials,
    get_credential,
    update_credential_sign_count,
    create_session,
    get_session,
    delete_session,
    delete_user_sessions,
    log_event,
    get_user_logs,
    rate_limit_check
)

# ─────────────────────────────────────────────────────────────
# Flask App
# ─────────────────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

app.secret_key = os.getenv("SECRET_KEY", os.urandom(32))

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)

# ─────────────────────────────────────────────────────────────
# Production / Local Config
# ─────────────────────────────────────────────────────────────

if os.getenv("VERCEL"):
    RP_ID = "nexus-vault-eta.vercel.app"
    ORIGIN = "https://nexus-vault-eta.vercel.app"
else:
    RP_ID = "localhost"
    ORIGIN = "https://localhost:5000"

RP_NAME = "NexusVault"
CHALLENGE_TIMEOUT = 300

# ─────────────────────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────────────────────

CORS(
    app,
    supports_credentials=True,
    origins=[ORIGIN]
)

# ─────────────────────────────────────────────────────────────
# Init DB
# ─────────────────────────────────────────────────────────────

def init_db():
    # Firebase auto creates collections
    pass

# ─────────────────────────────────────────────────────────────
# Registration Begin
# ─────────────────────────────────────────────────────────────

@app.route("/api/register/begin", methods=["POST"])
def register_begin():

    data = request.get_json()

    username = (data.get("username") or "").strip().lower()
    display_name = (data.get("display_name") or "").strip()

    if not username or not display_name:
        return jsonify({
            "error": "Username and display name required"
        }), 400

    if len(username) < 3 or len(username) > 32:
        return jsonify({
            "error": "Username must be 3-32 characters"
        }), 400

    existing = get_user_by_username(username)

    if existing:
        return jsonify({
            "error": "Username already registered"
        }), 409

    user_id = str(uuid.uuid4())

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id.encode(),
        user_name=username,
        user_display_name=display_name,
        exclude_credentials=[],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        timeout=60000,
    )

    session["reg_challenge"] = bytes_to_base64url(options.challenge)
    session["reg_user_id"] = user_id
    session["reg_username"] = username
    session["reg_display_name"] = display_name
    session["reg_challenge_time"] = int(time.time())

    return jsonify(json.loads(options_to_json(options)))

# ─────────────────────────────────────────────────────────────
# Registration Finish
# ─────────────────────────────────────────────────────────────

@app.route("/api/register/finish", methods=["POST"])
def register_finish():

    challenge_b64 = session.get("reg_challenge")
    challenge_time = session.get("reg_challenge_time", 0)

    user_id = session.get("reg_user_id")
    username = session.get("reg_username")
    display_name = session.get("reg_display_name")

    if not challenge_b64 or not user_id:
        return jsonify({
            "error": "No pending registration"
        }), 400

    if int(time.time()) - challenge_time > CHALLENGE_TIMEOUT:
        session.clear()

        return jsonify({
            "error": "Challenge expired"
        }), 400

    credential_data = request.get_json()

    try:

        verification = verify_registration_response(
            credential=credential_data,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )

    except Exception as e:

        log_event(user_id, "fail", username)

        return jsonify({
            "error": f"Registration verification failed: {str(e)}"
        }), 400

    try:

        cred_id = bytes_to_base64url(
            verification.credential_id
        )

        create_user(
            user_id,
            username,
            display_name
        )

        create_credential(
            cred_id,
            user_id,
            verification.credential_public_key,
            verification.sign_count,
            credential_data.get(
                "response",
                {}
            ).get(
                "transports",
                []
            )
        )

    except Exception as e:

        return jsonify({
            "error": f"Database error: {str(e)}"
        }), 500

    for k in [
        "reg_challenge",
        "reg_user_id",
        "reg_username",
        "reg_display_name",
        "reg_challenge_time"
    ]:
        session.pop(k, None)

    log_event(user_id, "register", username)

    return jsonify({
        "status": "ok",
        "message": "Passkey registered successfully"
    })

# ─────────────────────────────────────────────────────────────
# Login Begin
# ─────────────────────────────────────────────────────────────

@app.route("/api/login/begin", methods=["POST"])
def login_begin():

    data = request.get_json()

    username = (data.get("username") or "").strip().lower()

    if not username:
        return jsonify({
            "error": "Username required"
        }), 400

    if rate_limit_check(username):
        return jsonify({
            "error": "Too many failed attempts"
        }), 429

    user = get_user_by_username(username)

    if not user:
        return jsonify({
            "error": "User not found"
        }), 404

    creds = get_user_credentials(user["id"])

    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(c["id"]),
            transports=[]
        )
        for c in creds
    ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )

    session["auth_challenge"] = bytes_to_base64url(
        options.challenge
    )

    session["auth_username"] = username
    session["auth_user_id"] = user["id"]
    session["auth_challenge_time"] = int(time.time())

    return jsonify(json.loads(options_to_json(options)))

# ─────────────────────────────────────────────────────────────
# Login Finish
# ─────────────────────────────────────────────────────────────

@app.route("/api/login/finish", methods=["POST"])
def login_finish():

    challenge_b64 = session.get("auth_challenge")
    challenge_time = session.get("auth_challenge_time", 0)

    username = session.get("auth_username")
    user_id = session.get("auth_user_id")

    if not challenge_b64 or not user_id:
        return jsonify({
            "error": "No pending login"
        }), 400

    if int(time.time()) - challenge_time > CHALLENGE_TIMEOUT:

        session.clear()

        return jsonify({
            "error": "Challenge expired"
        }), 400

    credential_data = request.get_json()

    credential_id = credential_data.get("id", "")

    cred_row = get_credential(
        credential_id,
        user_id
    )

    if not cred_row:

        log_event(user_id, "fail", username)

        return jsonify({
            "error": "Credential not found"
        }), 404

    try:

        verification = verify_authentication_response(
            credential=credential_data,
            expected_challenge=base64url_to_bytes(
                challenge_b64
            ),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=cred_row["public_key"],
            credential_current_sign_count=cred_row["sign_count"],
            require_user_verification=True,
        )

    except Exception as e:

        log_event(user_id, "fail", username)

        return jsonify({
            "error": f"Authentication failed: {str(e)}"
        }), 401

    update_credential_sign_count(
        credential_id,
        verification.new_sign_count
    )

    update_user_last_login(user_id)

    delete_user_sessions(user_id)

    session_id = str(uuid.uuid4())

    create_session(
        session_id,
        user_id,
        request.remote_addr,
        request.user_agent.string[:200]
    )

    for k in [
        "auth_challenge",
        "auth_username",
        "auth_user_id",
        "auth_challenge_time"
    ]:
        session.pop(k, None)

    session["user_id"] = user_id
    session["session_id"] = session_id
    session.permanent = True

    user = get_user(user_id)

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

# ─────────────────────────────────────────────────────────────
# Current User
# ─────────────────────────────────────────────────────────────

@app.route("/api/me", methods=["GET"])
def me():

    user_id = session.get("user_id")
    session_id = session.get("session_id")

    if not user_id or not session_id:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    db_session = get_session(
        session_id,
        user_id
    )

    if not db_session:

        session.clear()

        return jsonify({
            "error": "Session expired"
        }), 401

    user = get_user(user_id)

    creds = get_user_credentials(user_id)

    logs = get_user_logs(user_id, limit=10)

    return jsonify({
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
            "created_at": user["created_at"],
            "last_login": user["last_login"],
        },
        "credentials": [
            {
                "id": c["id"],
                "created_at": c["created_at"],
                "last_used": c["last_used"],
                "device_label": c["device_label"],
                "sign_count": c["sign_count"],
            }
            for c in creds
        ],
        "recent_activity": logs,
    })

# ─────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────

@app.route("/api/logout", methods=["POST"])
def logout():

    user_id = session.get("user_id")
    session_id = session.get("session_id")

    if user_id and session_id:

        delete_session(session_id)

        log_event(
            user_id,
            "logout",
            None
        )

    session.clear()

    return jsonify({
        "status": "ok"
    })

# ─────────────────────────────────────────────────────────────
# Frontend
# ─────────────────────────────────────────────────────────────

@app.route("/")
@app.route("/<path:path>")
def serve_frontend(path=""):

    return send_from_directory(
        "templates",
        "index.html"
    )

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

init_db()

if __name__ == "__main__":

    print(
        "\n🔐 NexusVault running at https://localhost:5000\n"
    )

    app.run(
        debug=True,
        port=5000,
        ssl_context="adhoc"
    )
