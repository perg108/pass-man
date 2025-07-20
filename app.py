from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
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
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Argon2 password hasher
ph = PasswordHasher()

# Database setup
DATABASE = 'password_manager.db'

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
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        master_password = request.form['master_password']
        
        if not username or not password or not master_password:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
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
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            try:
                ph.verify(user_data[2], password)
                user = User(user_data[0], user_data[1], user_data[2], user_data[3])
                login_user(user)
                return redirect(url_for('dashboard'))
            except VerifyMismatchError:
                flash('Invalid credentials', 'error')
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
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
def add_password():
    if request.method == 'POST':
        service_name = request.form['service_name']
        username = request.form['username']
        password = request.form['password']
        master_password = request.form['master_password']
        
        # Verify master password
        try:
            ph.verify(current_user.master_key_hash, master_password)
        except VerifyMismatchError:
            flash('Invalid master password', 'error')
            return render_template('add_password.html')
        
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
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (user_id, service_name, username, encrypted_password, hmac_signature)
            VALUES (?, ?, ?, ?, ?)
        ''', (current_user.id, service_name, username, json.dumps(stored_data), hmac_signature))
        conn.commit()
        conn.close()
        
        flash('Password added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_password.html')

@app.route('/view_password/<int:password_id>', methods=['POST'])
@login_required
def view_password(password_id):
    master_password = request.form['master_password']
    
    # Verify master password
    try:
        ph.verify(current_user.master_key_hash, master_password)
    except VerifyMismatchError:
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
        return jsonify({'error': 'Data integrity check failed'}), 400
    
    # Decrypt password
    salt = base64.urlsafe_b64decode(stored_data['salt'])
    encryption_key = generate_encryption_key(master_password, salt)
    decrypted_password = decrypt_password(stored_data['encrypted_password'], encryption_key)
    
    if decrypted_password is None:
        return jsonify({'error': 'Failed to decrypt password'}), 400
    
    return jsonify({'password': decrypted_password})

@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
    conn.commit()
    conn.close()
    
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)