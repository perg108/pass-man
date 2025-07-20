import os
import secrets

class Config:
    """Application configuration with security best practices"""
    
    # Security: Use environment variable for secret key, fallback to secure generation
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Database configuration
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'password_manager.db')
    
    # Security settings
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour session timeout
    
    # Rate limiting settings
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
    LOGIN_ATTEMPT_WINDOW = int(os.environ.get('LOGIN_ATTEMPT_WINDOW', '300'))  # 5 minutes
    
    # Security headers
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'False').lower() == 'true'
    
    # Development vs Production
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = os.environ.get('TESTING', 'False').lower() == 'true'
    
    # Host and port configuration
    HOST = os.environ.get('HOST', '127.0.0.1')  # Default to localhost only
    PORT = int(os.environ.get('PORT', '5000'))

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    HOST = '127.0.0.1'  # Only localhost in development

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    FORCE_HTTPS = True
    
class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DATABASE_PATH = ':memory:'  # In-memory database for testing

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}