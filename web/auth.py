"""
AUTARCH Web Authentication
Session-based auth with bcrypt password hashing
"""

import os
import functools
import hashlib
from pathlib import Path
from flask import session, redirect, url_for, request

# Try bcrypt, fall back to hashlib
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


def hash_password(password):
    if BCRYPT_AVAILABLE:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    # Fallback: SHA-256 with salt
    salt = os.urandom(16).hex()
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"sha256${salt}${h}"


def check_password(password, password_hash):
    if BCRYPT_AVAILABLE and password_hash.startswith('$2'):
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    # Fallback check
    if password_hash.startswith('sha256$'):
        _, salt, h = password_hash.split('$', 2)
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    # Plain text comparison for default password
    return password == password_hash


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated


def get_credentials_path():
    from core.paths import get_data_dir
    return get_data_dir() / 'web_credentials.json'


def load_credentials():
    import json
    cred_path = get_credentials_path()
    if cred_path.exists():
        with open(cred_path) as f:
            return json.load(f)
    return {'username': 'admin', 'password': 'admin', 'force_change': True}


def save_credentials(username, password_hash, force_change=False):
    import json
    cred_path = get_credentials_path()
    cred_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cred_path, 'w') as f:
        json.dump({
            'username': username,
            'password': password_hash,
            'force_change': force_change
        }, f, indent=2)
