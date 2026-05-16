# NexusVault — Passkey Authentication System
## Architecture & Interview Guide

---

## Project Overview
NexusVault is a passwordless digital identity platform built on **WebAuthn / FIDO2** standards.
Users register and authenticate using **passkeys** — cryptographic key pairs where the private key
never leaves the user's device.

---

## Tech Stack & Why Each Was Chosen

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | HTML + CSS + Vanilla JS | No build step; WebAuthn API is native to browsers |
| Backend | Python Flask | Lightweight, easy to understand; perfect for demonstrating auth flows |
| WebAuthn Library | `py_webauthn` 2.x | FIDO Alliance-compliant Python implementation |
| Database | SQLite | Zero setup, file-based; swap to PostgreSQL for production |
| Sessions | Flask server-side sessions | Session stored in DB, not just a cookie |

---

## How Passkeys Work — The Core Cryptography

### Registration (creating a passkey)

```
Browser                    Device Hardware               Server
  │                        (TPM / Secure Enclave)          │
  │── POST /register/begin ─────────────────────────────►  │
  │                                                         │
  │◄── challenge (random nonce) + RP info ──────────────── │
  │                                                         │
  │── navigator.credentials.create(options) ──────────────►│
  │                        │                               │
  │                   Generate ES256                        │
  │                   key pair (ECDSA)                      │
  │                   Private → stored in hardware          │
  │                   Public  → returned to browser         │
  │◄──────────────────────────────────────────────────────  │
  │                                                         │
  │── POST /register/finish (public key + credential ID) ──►│
  │                                                    Verify:
  │                                                    - challenge matches session
  │                                                    - origin = our domain (anti-phishing)
  │                                                    - RP ID hash correct
  │                                                    - user verification flag set
  │                                                    Store: public key + cred ID in DB
  │◄── 200 OK ──────────────────────────────────────────── │
```

### Authentication (logging in)

```
Browser                    Device Hardware               Server
  │                        (TPM / Secure Enclave)          │
  │── POST /login/begin ────────────────────────────────►  │
  │                                                         │
  │◄── new challenge + allowed credential IDs ──────────── │
  │                                                         │
  │── navigator.credentials.get(options) ─────────────────►│
  │                        │                               │
  │                   User provides biometric/PIN           │
  │                   Private key signs the challenge       │
  │                   Signature returned (NOT the key)      │
  │◄──────────────────────────────────────────────────────  │
  │                                                         │
  │── POST /login/finish (signature + authenticator data) ─►│
  │                                                    Verify:
  │                                                    - signature valid (using stored public key)
  │                                                    - challenge matches session
  │                                                    - origin correct
  │                                                    - sign_count > stored (anti-clone)
  │                                                    Create session in DB
  │◄── 200 OK + session cookie ─────────────────────────── │
```

---

## Database Schema

```sql
users (id, username, display_name, role, created_at, last_login)
credentials (id=cred_id, user_id, public_key BLOB, sign_count, transports, ...)
sessions (session_id, user_id, created_at, expires_at, ip_address, user_agent)
audit_log (id, user_id, event, detail, ip_address, timestamp)
```

**Key point for interviews:** The `credentials` table stores the COSE-encoded public key blob.
The private key is NEVER sent to or stored on the server.

---

## Security Properties (for interview questions)

### Why is this phishing-proof?
The credential is **origin-bound**. When the browser calls `navigator.credentials.get()`,
it embeds the current origin (e.g., `https://nexusvault.com`) in `clientDataJSON`.
The server verifies this matches `ORIGIN`. A phishing site at `https://nexus-vault-fake.com`
would produce a different origin — verification fails automatically.

### Why can't an attacker replay a captured authentication?
Each login generates a fresh **random challenge (nonce)**. The authenticator signs
`challenge + authenticatorData`. The server checks the challenge matches what it generated
(stored in the session). The challenge is single-use and expires in 5 minutes.

### What does sign_count protect against?
Authenticators increment a counter on every signing operation. The server stores the
last known count. If an attacker clones a hardware key and uses it, the legitimate device
will have a higher count. When the cloned key's count arrives lower than the DB value,
the server rejects the authentication.

### How is session security handled?
Sessions are validated in the database, not just by cookie value:
- Cookie contains `session_id`
- Every protected route queries `sessions` table: `WHERE session_id=? AND expires_at > now()`
- Logout deletes the row — cookie becomes immediately invalid
- Single active session: old sessions are deleted on new login

---

## Running the Project

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
python app.py
# → http://localhost:5000
```

**Note:** WebAuthn requires HTTPS in production, but `localhost` is exempt for development.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/register/begin | Generate registration challenge |
| POST | /api/register/finish | Verify & store public key |
| POST | /api/login/begin | Generate auth challenge |
| POST | /api/login/finish | Verify signature, create session |
| GET | /api/me | Get current user (session-protected) |
| POST | /api/logout | Destroy session |
| GET | /api/admin/users | List all users (admin only) |
