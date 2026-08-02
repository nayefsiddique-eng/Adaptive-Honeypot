# PRAETOR Adaptive Honeypot Runbook

This guide contains the exact commands required to set up, train, run, and verify the PRAETOR Adaptive Honeypot system.

---

## 1. Prerequisites and Installation
Ensure you have Python 3.10+ installed.

### Create and Activate Virtual Environment
```bash
# 1. Create the virtual environment
python -m venv venv

# 2. Activate virtual environment
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Windows (CMD):
.\venv\Scripts\activate.bat
# On Linux/macOS:
source venv/bin/activate
```

### Install Dependencies
```bash
# Install all required packages (including FastAPI, SQLAlchemy, Uvicorn, Scikit-learn, and test dependencies)
pip install -r requirements.txt
```

---

## 2. ML Classifier Training (Optional)
The pre-trained classifiers are located in `ml/models/`. If you need to re-train the classification models:
```bash
# Run the training script (defines feature mappings and trains Random Forest/XGBoost models)
python ml/train_classifier.py
```

---

## 3. Launching the System (Manually)

### Start the FastAPI Backend
```bash
# Run the Uvicorn reload server on port 8000 (enables auto-reloading and starts the background session-reaper task)
python -m uvicorn backend.main:app --reload --port 8000
```

### Run the Attack Simulator
In a separate terminal (with the virtual environment activated):
```bash
# Executes multi-step attack sequences (recon, exploitation, commands) against the live backend
python scripts/simulate_attacks.py --count 50 --delay 0.3 --session-delay 0.5
```

---

## 4. Run Live Demo (Automated Command)
To run a fully automated demo sequence (starts uvicorn, wipes database, and runs the attacker simulator feeding the dashboard in real-time):

- **Windows**:
  ```cmd
  scripts\run_demo.bat
  ```
- **Linux/macOS**:
  ```bash
  chmod +x scripts/run_demo.sh
  ./scripts/run_demo.sh
  ```

Once started, open `frontend/dashboard.html` in your browser to watch the live feed and the reinforcement learning curve update dynamically.

---

## 5. Administrative Reset operations

### Clear Database (Reset Session, Logs, and RL Q-table)
```bash
# Call the admin reset endpoint to clear all tables between demo runs
curl -X POST http://localhost:8000/api/admin/reset-demo
```

### Manually Close Sessions (Force Q-learning Update)
```bash
# Forces all active sessions to terminate immediately, finalising their rewards and updating the Q-table
curl -X POST http://localhost:8000/api/admin/close-sessions
```

---

## 6. Verification and Testing
To run the automated reinforcement learning convergence test (verifies policy improvement by asserting that rewards in the latter 50 cycles are higher than the first 50 cycles):

- **Windows (PowerShell)**:
  ```powershell
  $env:PYTHONPATH="."
  pytest tests/test_rl_learning.py -s
  ```
- **Linux/macOS**:
  ```bash
  PYTHONPATH=. pytest tests/test_rl_learning.py -s
  ```
