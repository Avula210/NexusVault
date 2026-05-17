import firebase_admin
from firebase_admin import credentials, firestore
import os
import json
import base64

# Initialize Firebase
db = None

try:

    if os.path.exists("firebase-key.json"):

        cred = credentials.Certificate(
            "firebase-key.json"
        )

    else:

        firebase_key_b64 = os.getenv(
            "FIREBASE_KEY_B64"
        )

        if not firebase_key_b64:
            raise Exception(
                "FIREBASE_KEY_B64 missing"
            )

        key_json = base64.b64decode(
            firebase_key_b64
        ).decode()

        key_dict = json.loads(key_json)

        cred = credentials.Certificate(
            key_dict
        )

    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)

    db = firestore.client()

    print("Firebase initialized successfully")

except Exception as e:

    print(f"Firebase init error: {e}")

# User functions
def create_user(user_id, username, display_name):
    db.collection('users').document(user_id).set({
        'username': username,
        'display_name': display_name,
        'role': 'member',
        'created_at': int(__import__('time').time()),
        'last_login': None
    })

def get_user_by_username(username):
    docs = db.collection('users').where('username', '==', username).stream()
    for doc in docs:
        return {**doc.to_dict(), 'id': doc.id}
    return None

def get_user(user_id):
    doc = db.collection('users').document(user_id).get()
    if doc.exists:
        return {**doc.to_dict(), 'id': doc.id}
    return None

def update_user_last_login(user_id):
    db.collection('users').document(user_id).update({
        'last_login': int(__import__('time').time())
    })

# Credential functions
def create_credential(cred_id, user_id, public_key, sign_count, transports):
    db.collection('credentials').document(cred_id).set({
        'user_id': user_id,
        'public_key': base64.b64encode(public_key).decode(),
        'sign_count': sign_count,
        'transports': transports,
        'created_at': int(__import__('time').time()),
        'last_used': None,
        'device_label': 'Primary Device'
    })

def get_user_credentials(user_id):
    docs = db.collection('credentials').where('user_id', '==', user_id).stream()
    creds = []
    for doc in docs:
        data = doc.to_dict()
        data['id'] = doc.id
        if isinstance(data.get('public_key'), str):
            data['public_key'] = base64.b64decode(data['public_key'])
        creds.append(data)
    return creds

def get_credential(cred_id, user_id):
    doc = db.collection('credentials').document(cred_id).get()
    if doc.exists:
        data = doc.to_dict()
        if data.get('user_id') == user_id:
            data['id'] = doc.id
            if isinstance(data.get('public_key'), str):
                data['public_key'] = base64.b64decode(data['public_key'])
            return data
    return None

def update_credential_sign_count(cred_id, sign_count):
    db.collection('credentials').document(cred_id).update({
        'sign_count': sign_count,
        'last_used': int(__import__('time').time())
    })

# Session functions
def create_session(session_id, user_id, ip_address, user_agent):
    import time
    now = int(time.time())
    db.collection('sessions').document(session_id).set({
        'user_id': user_id,
        'created_at': now,
        'expires_at': now + 3600,
        'ip_address': ip_address,
        'user_agent': user_agent
    })

def get_session(session_id, user_id):
    doc = db.collection('sessions').document(session_id).get()
    if doc.exists:
        data = doc.to_dict()
        if data.get('user_id') == user_id and data.get('expires_at') > int(__import__('time').time()):
            return {**data, 'id': doc.id}
    return None

def delete_session(session_id):
    db.collection('sessions').document(session_id).delete()

def delete_user_sessions(user_id):
    docs = db.collection('sessions').where('user_id', '==', user_id).stream()
    for doc in docs:
        doc.reference.delete()

# Audit log functions
def log_event(user_id, event, detail=None, ip_address=None):
    db.collection('audit_log').add({
        'user_id': user_id,
        'event': event,
        'detail': detail,
        'ip_address': ip_address,
        'timestamp': int(__import__('time').time())
    })

def get_user_logs(user_id, limit=10):
    docs = db.collection('audit_log').where('user_id', '==', user_id).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit).stream()
    return [{**doc.to_dict(), 'id': doc.id} for doc in docs]

def rate_limit_check(username):
    import time
    cutoff = int(time.time()) - 900
    docs = db.collection('audit_log').where('detail', '==', username).where('event', '==', 'fail').where('timestamp', '>', cutoff).stream()
    count = sum(1 for _ in docs)
    return count >= 5
