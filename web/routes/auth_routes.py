"""Auth routes - login, logout, password change"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from web.auth import check_password, hash_password, load_credentials, save_credentials

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        creds = load_credentials()

        if username == creds['username'] and check_password(password, creds['password']):
            session['user'] = username
            if creds.get('force_change'):
                flash('Please change the default password.', 'warning')
                return redirect(url_for('settings.index'))
            next_url = request.args.get('next', url_for('dashboard.index'))
            return redirect(next_url)
        else:
            flash('Invalid credentials.', 'error')

    return render_template('login.html')


@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    """JSON login endpoint for the companion app."""
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'ok': False, 'error': 'Missing username or password'}), 400

    creds = load_credentials()
    if username == creds['username'] and check_password(password, creds['password']):
        session['user'] = username
        return jsonify({'ok': True, 'user': username})
    else:
        return jsonify({'ok': False, 'error': 'Invalid credentials'}), 401


@auth_bp.route('/api/check', methods=['GET'])
def api_check():
    """Check if the current session is authenticated."""
    if 'user' in session:
        return jsonify({'ok': True, 'user': session['user']})
    return jsonify({'ok': False}), 401


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
