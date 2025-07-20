@echo off
echo SecurePass Password Manager Setup
echo ===================================
echo.
echo Checking for Python installation...
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH.
    echo.
    echo Please install Python 3.7+ from one of these sources:
    echo 1. Official Python website: https://www.python.org/downloads/
    echo 2. Microsoft Store: Search for "Python 3.11" or "Python 3.12"
    echo 3. Anaconda: https://www.anaconda.com/products/distribution
    echo.
    echo After installation, restart this script.
    pause
    exit /b 1
)

echo Python found! Installing dependencies...
echo.
python -m pip install --upgrade pip
python -m pip install Flask==2.3.3 Flask-Login==0.6.3 argon2-cffi==23.1.0 cryptography==41.0.7 werkzeug==2.3.7

if %errorlevel% neq 0 (
    echo.
    echo Error installing dependencies. Please check your internet connection
    echo and try running the following command manually:
    echo.
    echo python -m pip install Flask Flask-Login argon2-cffi cryptography
    echo.
    pause
    exit /b 1
)

echo.
echo Dependencies installed successfully!
echo Starting SecurePass Password Manager...
echo.
echo The application will be available at: http://localhost:5000
echo Press Ctrl+C to stop the server when you're done.
echo.
python app.py

if %errorlevel% neq 0 (
    echo.
    echo Error starting the application. Please check the error messages above.
    pause
)