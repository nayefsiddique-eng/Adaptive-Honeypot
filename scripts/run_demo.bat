@echo off
echo ===================================================
echo   PRAETOR Adaptive Honeypot - Live Demo Script
echo ===================================================
echo.
echo [1/3] Launching FastAPI Backend Server...
start "PRAETOR Backend" cmd /c "venv\Scripts\python.exe -m uvicorn backend.main:app --port 8000"

echo [2/3] Waiting for backend to boot (6 seconds)...
ping 127.0.0.1 -n 7 > nul

echo [3/3] Resetting database to empty...
venv\Scripts\python.exe -c "import requests; print(requests.post('http://localhost:8000/api/admin/reset-demo').json())"

echo [*] Starting Live Attacker Simulator...
venv\Scripts\python.exe scripts/simulate_attacks.py --count 200 --delay 0.3 --session-delay 0.5
