#!/usr/bin/env bash
# APIShield - Simple One-Command Launcher

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=========================================="
echo "Starting APIShield..."
echo "=========================================="

# Free port 8000 if occupied
fuser -k 8000/tcp 2>/dev/null || true

# Run app using the venv
if [ -f "./venv/bin/python" ]; then
    ./venv/bin/python app.py
else
    python3 app.py
fi
