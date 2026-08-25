import json
import uuid
from datetime import datetime, UTC
from pathlib import Path
from backend.config import settings

LOG_DIR = Path(settings.LOG_DIR)
LOG_DIR.mkdir(exist_ok=True)

def generate_session_id():
    return str(uuid.uuid4())

def log_event(ip: str, port: int, protocol: str, payload: str = "", metadata: dict = {}):
    event = {
        "session_id": generate_session_id(),
        "timestamp": datetime.now(UTC).isoformat(),
        "ip_address": ip,
        "port": port,
        "protocol": protocol,
        "payload": payload,
        "metadata": metadata
    }
    log_file = LOG_DIR / f"traffic_{datetime.now(UTC).strftime('%Y%m%d')}.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(event) + "\n")
    return event
