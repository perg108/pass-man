#!/usr/bin/env python3
"""
SecurePass Setup Checker
This script verifies that all required dependencies are available.
"""

import sys
import importlib

def check_python_version():
    """Check if Python version is compatible"""
    print(f"Python version: {sys.version}")
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ is required")
        return False
    print("✅ Python version is compatible")
    return True

def check_module(module_name, package_name=None):
    """Check if a module can be imported"""
    try:
        importlib.import_module(module_name)
        print(f"✅ {package_name or module_name} is available")
        return True
    except ImportError:
        print(f"❌ {package_name or module_name} is not installed")
        return False

def main():
    print("SecurePass Setup Checker")
    print("=" * 25)
    print()
    
    # Check Python version
    python_ok = check_python_version()
    print()
    
    # Check required modules
    modules = [
        ('flask', 'Flask'),
        ('flask_login', 'Flask-Login'),
        ('argon2', 'argon2-cffi'),
        ('cryptography', 'cryptography'),
        ('sqlite3', 'sqlite3 (built-in)'),
        ('secrets', 'secrets (built-in)'),
        ('hmac', 'hmac (built-in)'),
        ('hashlib', 'hashlib (built-in)'),
        ('base64', 'base64 (built-in)'),
        ('json', 'json (built-in)'),
        ('os', 'os (built-in)'),
        ('datetime', 'datetime (built-in)')
    ]
    
    print("Checking required modules:")
    all_modules_ok = True
    for module, package in modules:
        if not check_module(module, package):
            all_modules_ok = False
    
    print()
    
    if python_ok and all_modules_ok:
        print("🎉 All dependencies are satisfied!")
        print("You can run the password manager with: python app.py")
        return True
    else:
        print("❌ Some dependencies are missing.")
        print("\nTo install missing packages, run:")
        print("python -m pip install Flask Flask-Login argon2-cffi cryptography")
        return False

if __name__ == "__main__":
    success = main()
    input("\nPress Enter to exit...")
    sys.exit(0 if success else 1)