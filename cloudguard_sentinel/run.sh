#!/bin/bash
echo "============================================"
echo "  CloudGuard Sentinel - Setup and Run"
echo "============================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed."
    echo "Install it from https://python.org"
    exit 1
fi

echo "[1/4] Python found: $(python3 --version)"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[2/4] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[2/4] Virtual environment already exists."
fi

# Activate
echo "[3/4] Activating virtual environment..."
source venv/bin/activate

# Install
echo "[4/4] Installing dependencies..."
pip install -r requirements.txt --quiet

echo ""
echo "============================================"
echo "  Starting CloudGuard Sentinel..."
echo "  Open browser at: http://localhost:5000"
echo ""
echo "  Login credentials:"
echo "  admin / Admin@1234  (Admin role)"
echo "  alice / Alice@1234  (User role)"
echo "  bob   / Bob@1234    (User role)"
echo ""
echo "  Press CTRL+C to stop the server."
echo "============================================"
echo ""

python app.py
