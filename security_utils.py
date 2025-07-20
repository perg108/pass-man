"""
Security utilities for the password manager application
"""
import re
import html
from flask import request, abort
from functools import wraps
import time
import sqlite3
import hashlib

# Login attempt tracking (in-memory for simplicity, use Redis in production)
login_attempts = {}

def clean_login_attempts():
    """Clean old login attempts (call this periodically)"""
    current_time = time.time()
    window = 300  # 5 minutes
    global login_attempts
    login_attempts = {
        ip: attempts for ip, attempts in login_attempts.items()
        if current_time - attempts['first_attempt'] < window
    }

def track_login_attempt(ip_address, success=False):
    """Track login attempts from an IP address"""
    current_time = time.time()
    
    clean_login_attempts()
    
    if ip_address not in login_attempts:
        login_attempts[ip_address] = {
            'count': 0,
            'first_attempt': current_time,
            'last_attempt': current_time
        }
    
    if success:
        # Reset attempts on successful login
        if ip_address in login_attempts:
            del login_attempts[ip_address]
    else:
        login_attempts[ip_address]['count'] += 1
        login_attempts[ip_address]['last_attempt'] = current_time

def is_ip_blocked(ip_address, max_attempts=5):
    """Check if an IP address is blocked due to too many failed attempts"""
    clean_login_attempts()
    
    if ip_address in login_attempts:
        return login_attempts[ip_address]['count'] >= max_attempts
    return False

def validate_password_strength(password):
    """
    Validate password strength
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>?]', password):
        return False, "Password must contain at least one special character"
    
    return True, ""

def sanitize_input(text, max_length=255):
    """Sanitize user input to prevent XSS and other attacks"""
    if not text:
        return text
    
    # Limit length
    text = text[:max_length]
    
    # HTML escape
    text = html.escape(text)
    
    # Remove potentially dangerous characters
    text = re.sub(r'[<>"\']', '', text)
    
    return text.strip()

def validate_service_name(service_name):
    """Validate service name input"""
    if not service_name or len(service_name.strip()) == 0:
        return False, "Service name is required"
    
    service_name = service_name.strip()
    
    if len(service_name) > 100:
        return False, "Service name must be less than 100 characters"
    
    # Allow alphanumeric, spaces, dots, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9\s\.\-_]+$', service_name):
        return False, "Service name contains invalid characters"
    
    return True, sanitize_input(service_name, 100)

def validate_username(username):
    """Validate username input"""
    if not username:
        return True, ""  # Username is optional for some services
    
    username = username.strip()
    
    if len(username) > 100:
        return False, "Username must be less than 100 characters"
    
    # Allow alphanumeric, dots, hyphens, underscores, @ symbol
    if not re.match(r'^[a-zA-Z0-9\.\-_@]+$', username):
        return False, "Username contains invalid characters"
    
    return True, sanitize_input(username, 100)

def rate_limit_key():
    """Generate rate limit key based on IP address"""
    return request.remote_addr

def secure_headers():
    """Return security headers as a dictionary"""
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
    }

def log_security_event(event_type, user_id=None, ip_address=None, details=None):
    """Log security events for monitoring (simplified version)"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    ip = ip_address or request.remote_addr
    
    log_entry = {
        'timestamp': timestamp,
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip,
        'details': details or {}
    }
    
    # In a real application, this would write to a proper logging system
    # For now, we'll use print for simplicity
    print(f"SECURITY LOG: {log_entry}")

def require_rate_limit(func):
    """Decorator to require rate limiting checks"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        if is_ip_blocked(ip):
            log_security_event('RATE_LIMIT_EXCEEDED', ip_address=ip)
            abort(429)  # Too Many Requests
        return func(*args, **kwargs)
    return wrapper