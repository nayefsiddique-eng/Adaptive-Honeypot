#!/bin/bash
echo "==================================================="
echo "  PRAETOR Adaptive Honeypot - Live Demo Script"
echo "==================================================="

echo "[1/3] Launching FastAPI backend server..."
./venv/bin/python -m uvicorn backend.main:app --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!

# Ensure backend process is killed when the script exits or is interrupted
trap "kill $BACKEND_PID" EXIT INT TERM

echo "[2/3] Waiting for backend to boot (6 seconds)..."
sleep 6

echo "[3/3] Resetting database to empty..."
./venv/bin/python -c "import requests; print(requests.post('http://localhost:8000/api/admin/reset-demo').json())"

echo "[*] Starting Live Attacker Simulator..."
./venv/bin/python scripts/simulate_attacks.py --count 200 --delay 0.3 --session-delay 0.5
