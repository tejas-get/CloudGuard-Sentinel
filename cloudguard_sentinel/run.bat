@echo off
echo ============================================
echo   CloudGuard Sentinel - Setup and Run
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python from https://python.org
    echo Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

echo [1/4] Python found.

:: Create virtual environment if not exists
if not exist "venv" (
    echo [2/4] Creating virtual environment...
    python -m venv venv
) else (
    echo [2/4] Virtual environment already exists.
)

:: Activate venv
echo [3/4] Activating virtual environment...
call venv\Scripts\activate.bat

:: Install dependencies
echo [4/4] Installing dependencies...
pip install -r requirements.txt --quiet

echo.
echo ============================================
echo   Starting CloudGuard Sentinel...
echo   Open your browser at: http://localhost:5000
echo.
echo   Login credentials:
echo   admin / Admin@1234  (Admin role)
echo   alice / Alice@1234  (User role)
echo   bob   / Bob@1234    (User role)
echo.
echo   Press CTRL+C to stop the server.
echo ============================================
echo.

python app.py
pause
