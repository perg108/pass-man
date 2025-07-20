from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
import sqlite3
import secrets
import hmac
import hashlib
import base64
import os
import json
from datetime import datetime, timedelta
from config import config
from forms import LoginForm, RegisterForm, AddPasswordForm, ViewPasswordForm, DeletePasswordForm
from security_utils import (
    track_login_attempt, is_ip_blocked, secure_headers, log_security_event,
    require_rate_limit, validate_password_strength
)

# Get configuration based on environment
config_name = os.environ.get('FLASK_ENV', 'development')
app_config = config.get(config_name, config['default'])

app = Flask(__name__)
app.config.from_object(app_config)

# Initialize security extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'

# Initialize Argon2 password hasher
ph = PasswordHasher()

# Database setup
DATABASE = app.config['DATABASE_PATH']

class User(UserMixin):
    def __init__(self, id, username, password_hash, master_key_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.master_key_hash = master_key_hash

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            master_key_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Passwords table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            username TEXT,
            encrypted_password TEXT NOT NULL,
            hmac_signature TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

@app.before_request
def before_request():
    """Security checks before each request"""
    # Force HTTPS in production
    if app.config.get('FORCE_HTTPS') and not request.is_secure:
        return redirect(request.url.replace('http://', 'https://'))
    
    # Set session timeout
    if current_user.is_authenticated:
        from flask import session
        if 'last_activity' in session:
            if datetime.now() - session['last_activity'] > timedelta(seconds=app.config['PERMANENT_SESSION_LIFETIME']):
                logout_user()
                flash('Your session has expired. Please log in again.', 'info')
                return redirect(url_for('login'))
        session['last_activity'] = datetime.now()

@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    headers = secure_headers()
    for header, value in headers.items():
        response.headers[header] = value
    return response

def generate_encryption_key(master_password, salt):
    """Generate encryption key from master password using PBKDF2"""
    key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_password(password, encryption_key):
    """Encrypt password using Fernet symmetric encryption"""
    fernet = Fernet(encryption_key)
    encrypted = fernet.encrypt(password.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

def decrypt_password(encrypted_password, encryption_key):
    """Decrypt password using Fernet symmetric encryption"""
    try:
        fernet = Fernet(encryption_key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_password.encode())
        decrypted = fernet.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception:
        return None

def generate_hmac(data, key):
    """Generate HMAC signature for data integrity verification"""
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(data, signature, key):
    """Verify HMAC signature"""
    expected_signature = generate_hmac(data, key)
    return hmac.compare_digest(signature, expected_signature)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        master_password = form.master_password.data
        
        # Additional server-side validation
        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            flash(f'Login password: {error_msg}', 'error')
            return render_template('register.html', form=form)
        
        is_valid, error_msg = validate_password_strength(master_password)
        if not is_valid:
            flash(f'Master password: {error_msg}', 'error')
            return render_template('register.html', form=form)
        
        # Hash the login password with Argon2id
        password_hash = ph.hash(password)
        
        # Hash the master password for verification
        master_key_hash = ph.hash(master_password)
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash, master_key_hash) VALUES (?, ?, ?)',
                         (username, password_hash, master_key_hash))
            conn.commit()
            conn.close()
            
            log_security_event('USER_REGISTERED', details={'username': username})
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@require_rate_limit
def login():
    form = LoginForm()
    ip_address = request.remote_addr
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            try:
                ph.verify(user_data[2], password)
                user = User(user_data[0], user_data[1], user_data[2], user_data[3])
                login_user(user, remember=False)
                
                # Track successful login
                track_login_attempt(ip_address, success=True)
                log_security_event('USER_LOGIN_SUCCESS', user_id=user.id)
                
                return redirect(url_for('dashboard'))
            except VerifyMismatchError:
                track_login_attempt(ip_address, success=False)
                log_security_event('USER_LOGIN_FAILED', details={'username': username, 'reason': 'invalid_password'})
                flash('Invalid credentials', 'error')
        else:
            track_login_attempt(ip_address, success=False)
            log_security_event('USER_LOGIN_FAILED', details={'username': username, 'reason': 'user_not_found'})
            flash('Invalid credentials', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_security_event('USER_LOGOUT', user_id=current_user.id)
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE user_id = ? ORDER BY service_name', (current_user.id,))
    passwords = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', passwords=passwords)

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute")
def add_password():
    form = AddPasswordForm()
    
    if form.validate_on_submit():
        service_name = form.service_name.data
        username = form.username.data
        password = form.password.data
        master_password = form.master_password.data
        
        # Verify master password
        try:
            ph.verify(current_user.master_key_hash, master_password)
        except VerifyMismatchError:
            flash('Invalid master password', 'error')
            return render_template('add_password.html', form=form)
        
        # Generate encryption key and encrypt password
        salt = secrets.token_bytes(32)
        encryption_key = generate_encryption_key(master_password, salt)
        encrypted_password = encrypt_password(password, encryption_key)
        
        # Generate HMAC for integrity verification
        hmac_data = f"{service_name}:{username}:{encrypted_password}"
        hmac_signature = generate_hmac(hmac_data, master_password)
        
        # Store salt with encrypted password
        stored_data = {
            'encrypted_password': encrypted_password,
            'salt': base64.urlsafe_b64encode(salt).decode()
        }
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (user_id, service_name, username, encrypted_password, hmac_signature)
                VALUES (?, ?, ?, ?, ?)
            ''', (current_user.id, service_name, username, json.dumps(stored_data), hmac_signature))
            conn.commit()
            conn.close()
            
            log_security_event('PASSWORD_ADDED', user_id=current_user.id, details={'service': service_name})
            flash('Password added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('Failed to add password. Please try again.', 'error')
            log_security_event('PASSWORD_ADD_ERROR', user_id=current_user.id, details={'error': str(e)})
    
    return render_template('add_password.html', form=form)

@app.route('/view_password/<int:password_id>', methods=['POST'])
@login_required
@limiter.limit("50 per minute")
def view_password(password_id):
    try:
        # Validate CSRF token
        csrf.validate()
        
        master_password = request.form.get('master_password')
        if not master_password:
            return jsonify({'error': 'Master password is required'}), 400
        
        # Verify master password
        try:
            ph.verify(current_user.master_key_hash, master_password)
        except VerifyMismatchError:
            log_security_event('INVALID_MASTER_PASSWORD', user_id=current_user.id, 
                             details={'password_id': password_id})
            return jsonify({'error': 'Invalid master password'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
        password_data = cursor.fetchone()
        conn.close()
        
        if not password_data:
            return jsonify({'error': 'Password not found'}), 404
        
        # Verify HMAC
        service_name, username, encrypted_data, hmac_signature = password_data[2], password_data[3], password_data[4], password_data[5]
        stored_data = json.loads(encrypted_data)
        
        hmac_data = f"{service_name}:{username}:{stored_data['encrypted_password']}"
        if not verify_hmac(hmac_data, hmac_signature, master_password):
            log_security_event('HMAC_VERIFICATION_FAILED', user_id=current_user.id, 
                             details={'password_id': password_id})
            return jsonify({'error': 'Data integrity check failed'}), 400
        
        # Decrypt password
        salt = base64.urlsafe_b64decode(stored_data['salt'])
        encryption_key = generate_encryption_key(master_password, salt)
        decrypted_password = decrypt_password(stored_data['encrypted_password'], encryption_key)
        
        if decrypted_password is None:
            return jsonify({'error': 'Failed to decrypt password'}), 400
        
        log_security_event('PASSWORD_VIEWED', user_id=current_user.id, 
                         details={'password_id': password_id, 'service': service_name})
        
        return jsonify({'password': decrypted_password})
        
    except Exception as e:
        log_security_event('PASSWORD_VIEW_ERROR', user_id=current_user.id, 
                         details={'password_id': password_id, 'error': str(e)})
        return jsonify({'error': 'An error occurred while viewing the password'}), 500

@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    try:
        # Get password info for logging before deletion
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT service_name FROM passwords WHERE id = ? AND user_id = ?', 
                      (password_id, current_user.id))
        password_data = cursor.fetchone()
        
        if not password_data:
            flash('Password not found', 'error')
            return redirect(url_for('dashboard'))
        
        service_name = password_data[0]
        
        cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
        
        if cursor.rowcount > 0:
            conn.commit()
            log_security_event('PASSWORD_DELETED', user_id=current_user.id, 
                             details={'password_id': password_id, 'service': service_name})
            flash('Password deleted successfully!', 'success')
        else:
            flash('Password not found', 'error')
        
        conn.close()
        
    except Exception as e:
        log_security_event('PASSWORD_DELETE_ERROR', user_id=current_user.id, 
                         details={'password_id': password_id, 'error': str(e)})
        flash('Failed to delete password. Please try again.', 'error')
    
    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', 
                         error_code=404, 
                         error_message="The requested page could not be found."), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', 
                         error_code=403, 
                         error_message="Access forbidden."), 403

@app.errorhandler(429)
def ratelimit_handler(error):
    return render_template('error.html', 
                         error_code=429, 
                         error_message="Too many requests. Please try again later."), 429

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', 
                         error_code=500, 
                         error_message="An internal server error occurred."), 500

if __name__ == '__main__':
    init_db()
    
    # Configuration based on environment
    debug_mode = app.config.get('DEBUG', False)
    host = app.config.get('HOST', '127.0.0.1')
    port = app.config.get('PORT', 5000)
    
    if debug_mode:
        print("⚠️  WARNING: Running in DEBUG mode. Never use this in production!")
        print(f"🔧 Development server starting on http://{host}:{port}")
    else:
        print(f"🚀 Production server starting on {host}:{port}")
    
    app.run(debug=debug_mode, host=host, port=port)