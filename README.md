# PRAETOR

PRAETOR is an autonomous, multi-protocol cyber deception platform that combines real-time machine learning classification with Cooperative Multi-Agent Reinforcement Learning (CMARL) to dynamically adapt honeypot environments in response to active threat actors.

---

## Overview

PRAETOR addresses the limitations of static honeypots by dynamically mutating network, service, and emulation characteristics. When an attacker interacts with one of the honeypot endpoints, the system extracts traffic and payload features, classifies the attacker persona, and leverages a multi-agent reinforcement learning loop to adapt deception profiles in real time. This keeps adversaries engaged, collects deep forensic telemetry, and provides clear, rule-based explainability of all deception actions to security analysts.

---

## Architecture

```
                       +---------------------------------------+
                       |       UNTRUSTED ATTACKER PLANE        |
                       |                                       |
                       |  [SSH :2222]   [HTTP :8080]  [Telnet] |
                       +-------------------+-------------------+
                                           |
                                (HTTP POST Ingest Telemetry)
                                           v
                       +-------------------+-------------------+
                       |        ISOLATED TELEMETRY BRIDGE      |
                       |                                       |
                       |        [POST /api/logs/ingest]        |
                       +-------------------+-------------------+
                                           |
                                (Internal Processing)
                                           v
                       +-------------------+-------------------+
                       |        SECURE MANAGEMENT PLANE        |
                       |                                       |
                       |  [Feature Extractor]                  |
                       |  [ML Ensemble & CMARL Decision Core]  |
                       |  [SQLite Database & Cyber-HUD API]    |
                       +-------------------+-------------------+
                                           ^
                                (Authenticated Admin Access)
                                           |
                       +-------------------+-------------------+
                       |          SECURITY ANALYST             |
                       |                                       |
                       |       [Cyber-HUD Web Interface]       |
                       +---------------------------------------+
```

---

## Key Capabilities

* **SSH Honeypot:** Genuine, multi-stage interactive SSH environment emulating system commands, interactive filesystems, and credentials.
* **HTTP Decoy:** Genuine decoy web server emulating exposed credentials, configuration files, and common login vectors.
* **Telnet Honeypot:** Legacy shell emulator representing common embedded/networking hardware interfaces.
* **Stateful Deception:** Maintains consistent interactive session states even across dynamic profile transitions.
* **ML Classification:** Real-time adversary identification using Random Forest, XGBoost, and anomaly detection.
* **Risk Scoring:** Fuses volume, location, reputation, and payload indicators to dynamically compute an attacker risk score (0-100).
* **Adaptive RL/CMARL:** Coordinated multi-agent Q-learning engine (Network, Service, and Intelligence agents) working to optimize attacker engagement.
* **Telemetry:** Forensic keystroke tracking, file hash isolation, and connection profiling.
* **Forensic/Session Tracking:** Chronological attack timelines, MITRE Engage mapping, and attacker transition graphs.
* **Dashboard:** Unified web visualization console displaying active threats, ML diagnostics, and learning curves.
* **Production Isolation:** Multi-plane container separation limiting lateral movement.

---

## Architecture Flow

```
  Attacker
    │
    ▼
  Honeypot (SSH, HTTP, Telnet)
    │
    ▼
  Telemetry Dispatch
    │
    ▼
  Feature Extraction (Entropy, payload parsing)
    │
    ▼
  Risk Assessment & ML Persona Prediction
    │
    ▼
  Adaptive CMARL Decision Choice
    │
    ▼
  Deception Action (Emulation shift, latency delay)
    │
    ▼
  Session & Reward Tracking
    │
    ▼
  Dashboard & Research Metrics Updates
```

---

## Security Architecture

* **Attacker Plane:** Attacker-facing listeners are isolated, low-privilege nodes with no access to external networks or the management host.
* **Telemetry Plane:** A unidirectional bridge where honeypot sensors POST raw events to `/api/logs/ingest`. It rate-limits and sanitizes incoming payloads.
* **Management Plane:** The trusted zone hosting the FastAPI backend, DB, and ML/RL algorithms. It binds strictly to `127.0.0.1`.
* **Container Isolation:** The honeypot runs in a container with `read_only: true`, no host network access, all capabilities dropped (`cap_drop: [ALL]`), and privilege escalation disabled (`no-new-privileges: true`).
* **Secret Separation:** Secrets (`SECRET_KEY`, `ADMIN_API_KEY`, `MANAGEMENT_API_KEY`) are managed strictly via `.env` files (excluded from Git).
* **Read-only Filesystem:** Application code is mounted read-only inside Docker; write permissions are restricted to transient folders.
* **Non-Root Execution:** The Docker container drops all privileges to a non-root `praetor` user.
* **Capability Dropping:** All default Linux capabilities are explicitly stripped from the container configuration.
* **Management API Isolation:** Administrative and analytic routes require authentication headers and bind to localhost.

---

## Project Structure

```
adaptive-honeypot/
├── backend/                  # Application core
│   ├── api/                  # FastAPI routers and route endpoints
│   ├── core/                 # CMARL decision core and feature extractors
│   ├── honeypot/             # SSH, HTTP, and Telnet honeypot servers
│   ├── middleware/           # Rate limiting and security headers
│   ├── models/               # SQLAlchemy schema definitions
│   ├── services/             # Integrations (GeoIP, feeds)
│   ├── config.py             # Settings and validation
│   └── main.py               # Uvicorn entrypoint
├── docs/                     # Documentation files
│   ├── ARCHITECTURE.md       # Component design documentation
│   ├── PRODUCTION_DEPLOYMENT.md # Production environment setup
│   ├── RELATED_WORK.md       # Prior work comparisons
│   └── SECURITY.md           # Security architecture guide
├── frontend/                 # Cyber-HUD client interface
├── ml/                       # Machine learning classifiers and training
├── scripts/                  # Simulation and isolation validation utilities
├── tests/                    # Test suite and regression tests
├── pyproject.toml            # Project configuration
└── requirements.txt          # Python dependencies
```

---

## Requirements

* Python 3.12 or 3.14 (Python 3.14 tested)
* Virtual environment tool (`venv`)
* SQLite (for local development)
* Windows or Linux host OS

---

## Local Development

Execute the following commands from the project root inside a Windows PowerShell environment:

1. **Activate Virtual Environment:**
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

2. **Install Package in Editable Mode:**
   ```powershell
   pip install -e .
   ```

3. **Train the ML Models (Optional - falls back to heuristic-only mode if skipped):**
   ```powershell
   python ml/train_classifier.py
   ```

4. **Start FastAPI Backend Server:**
   ```powershell
   python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
   ```

5. **Launch Honeypot Decoys (Separate Shell):**
   ```powershell
   $env:PYTHONPATH="."
   python scripts/run_honeypots.py
   ```

---

## Access Points

* **Management API:** `http://127.0.0.1:8000` (Local Development)
* **FastAPI Docs:** `http://127.0.0.1:8000/docs` (Local Development)
* **SSH Honeypot:** `127.0.0.1:2222` (Attack Interface)
* **HTTP Decoy:** `127.0.0.1:8080` (Attack Interface)
* **Telnet Honeypot:** `127.0.0.1:2323` (Attack Interface)

*Note: All interfaces are bound to loopback for development-only safety.*

---

## Production Deployment

Refer to [PRODUCTION_DEPLOYMENT.md](file:///c:/Users/Admin%20pc/Desktop/Adaptive-Honeypot-main/docs/PRODUCTION_DEPLOYMENT.md) for full orchestration templates.

Production environments rely on isolated network planes where:
* The attacker subnet cannot communicate with internal assets.
* Honeypot containers run on a private, non-routable bridge and can only send telemetry inbound to the management API.

---

## Security

Refer to [SECURITY.md](file:///c:/Users/Admin%20pc/Desktop/Adaptive-Honeypot-main/docs/SECURITY.md) for vulnerability reporting guidelines, security controls, and trust boundary breakdowns.

---

## Testing

To run the full test suite verifying CMARL convergence and security controls:

```powershell
python -m pytest
```

To run the verification checks with warnings promoted to errors:

```powershell
python -m pytest -W error
```

*Verified status:* 19 passed, 0 failed, 0 warnings.

---

## Validation

Verify that your local or containerized production deployment meets the 13 network plane isolation requirements:

```powershell
python scripts/validate_production_isolation.py
```

---

## Research / Evaluation

PRAETOR contains evaluation scripts within the `ml/` and `scripts/` directories to validate:
* Model convergence timelines over episodes (`ml/evaluate_models.py`).
* Anomaly classification accuracy, precision, recall, and F1 metrics.
* Dynamic policy adaptation under synthetic attacker playbooks.

All quantitative evaluation thresholds in tests serve as stability baselines and policy quality bounds.

---

## Limitations

* **Infrastructure Dependency:** Production security relies on network-level segregation (VLANs, firewalls) and host operating system configurations.
* **Virtualization Isolation:** Virtual machine or container segmentation is required to ensure compromise of a honeypot endpoint does not expose the host kernel.
* **Management Privacy:** The management panel and API must remain isolated from public network access.
* **Intentional Vulnerabilities:** The honeypots are designed to appear vulnerable to attackers. Any misconfiguration of the surrounding sandbox could lead to host compromise.
* **No Claim of Absolute Security:** Absolute security cannot be guaranteed, and this platform should only be run in designated research environments.

---

## License

Distributed under the MIT License. See [LICENSE](file:///c:/Users/Admin%20pc/Desktop/Adaptive-Honeypot-main/LICENSE) for more information.

---

## Disclaimer

PRAETOR is intended for authorized defensive research, threat intelligence collection, and controlled educational deployments. Do not expose this software to untrusted networks without adequate isolation, containment policies, and firewalls.
