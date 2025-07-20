# SecurePass - Password Manager

A secure password manager built with Flask, featuring Argon2id encryption, HMAC verification, and multi-user support.

## Features

- **Argon2id Encryption**: Industry-standard password hashing for maximum security
- **HMAC Verification**: Data integrity protection to ensure passwords haven't been tampered with
- **Multi-User Support**: Secure individual accounts for multiple users
- **Zero-Knowledge Architecture**: Your passwords are encrypted locally and never stored in plain text
- **Password Generator**: Built-in secure password generator with customizable options
- **Modern UI**: Clean, responsive web interface with Bootstrap 5
- **Local Storage**: SQLite database keeps your data on your device

## Security Architecture

### Encryption
- **Login passwords**: Hashed with Argon2id (memory-hard, resistant to GPU attacks)
- **Master passwords**: Separately hashed with Argon2id for verification
- **Stored passwords**: Encrypted with Fernet (AES 128 in CBC mode) using PBKDF2-derived keys
- **Key derivation**: PBKDF2 with 100,000 iterations and unique salts

### Integrity Protection
- **HMAC-SHA256**: Every stored password includes an HMAC signature
- **Data verification**: Passwords are verified for integrity before decryption
- **Tamper detection**: Any modification to stored data is detected

### Zero-Knowledge Design
- Master passwords are never stored in recoverable form
- Encryption keys are derived from master passwords on-demand
- No backdoors or recovery mechanisms (by design)

## Installation

### Quick Start (Windows)
1. **Download or clone** this repository
2. **Double-click** `install_and_run.bat` - this will:
   - Check if Python is installed
   - Guide you through Python installation if needed
   - Install all required dependencies
   - Start the application automatically

### Manual Installation
1. **Install Python 3.7+** from:
   - [Official Python website](https://www.python.org/downloads/)
   - Microsoft Store (search for "Python 3.11" or "Python 3.12")
   - [Anaconda Distribution](https://www.anaconda.com/products/distribution)

2. **Install dependencies**:
   ```bash
   # Windows
   python -m pip install Flask Flask-Login argon2-cffi cryptography
   
   # Or using requirements.txt
   python -m pip install -r requirements.txt
   ```

3. **Start the application**:
   ```bash
   python app.py
   ```

## Usage

1. **Start the application**:
   ```bash
   python app.py
   ```

2. **Open your browser** and navigate to `http://localhost:5000`

3. **Create an account**:
   - Choose a unique username
   - Set a login password (for accessing the application)
   - Set a master password (for encrypting your stored passwords)
   - **Important**: Your master password cannot be recovered if forgotten!

4. **Add passwords**:
   - Enter service name and username
   - Generate a secure password or enter your own
   - Confirm with your master password to encrypt and store

5. **View passwords**:
   - Enter your master password to decrypt and view stored passwords
   - Copy passwords to clipboard securely
   - Delete passwords you no longer need

## File Structure

```
pass-man/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── password_manager.db    # SQLite database (created automatically)
├── templates/
│   ├── base.html         # Base template with navigation
│   ├── index.html        # Landing page
│   ├── login.html        # User login
│   ├── register.html     # User registration
│   ├── dashboard.html    # Password vault
│   └── add_password.html # Add new password
└── README.md             # This file
```

## Security Considerations

### What This Protects Against
- **Data breaches**: Passwords are encrypted, not stored in plain text
- **Database theft**: Encrypted passwords are useless without master passwords
- **Insider threats**: Zero-knowledge design prevents unauthorized access
- **Data tampering**: HMAC verification detects any modifications

### What You Must Protect
- **Master password**: If forgotten, your data cannot be recovered
- **Device security**: Keep your computer secure and updated
- **Browser security**: Use a secure, updated browser
- **Network security**: Use HTTPS in production environments

### Production Deployment
For production use, consider:
- Using HTTPS (SSL/TLS) encryption
- Setting a strong Flask secret key
- Using a more robust database (PostgreSQL, MySQL)
- Implementing rate limiting
- Adding backup and recovery procedures
- Regular security audits

## Technical Details

### Dependencies
- **Flask**: Web framework
- **Flask-Login**: User session management
- **argon2-cffi**: Argon2id password hashing
- **cryptography**: Fernet encryption and cryptographic primitives
- **sqlite3**: Database (built into Python)

### Database Schema

**Users Table**:
- `id`: Primary key
- `username`: Unique username
- `password_hash`: Argon2id hash of login password
- `master_key_hash`: Argon2id hash of master password
- `created_at`: Account creation timestamp

**Passwords Table**:
- `id`: Primary key
- `user_id`: Foreign key to users table
- `service_name`: Name of the service/website
- `username`: Username for the service
- `encrypted_password`: JSON containing encrypted password and salt
- `hmac_signature`: HMAC-SHA256 signature for integrity
- `created_at`: Password creation timestamp
- `updated_at`: Last modification timestamp

## License

This project is provided as-is for educational and personal use. Use at your own risk.

## Disclaimer

While this password manager implements strong security practices, no software is 100% secure. Always:
- Keep backups of important passwords
- Use this software at your own risk
- Keep your system and browser updated
- Use strong, unique master passwords

The authors are not responsible for any data loss or security breaches.