import random
from typing import Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from backend.models.session import AttackerSession
from backend.models.attack import AttackLog
import backend.core.cooperative_rl_engine as coop_rl
import backend.core.decision_engine as decision_engine

# Attacker Personas config profiles
ATTACKER_PERSONAS = {
    "script_kiddie": {
        "persistence": 0.20,
        "speed_delay": 2.0,
        "attack_types": ["port_scan", "xss"],
        "description": "Uses public tools, leaves immediately if connection is delayed"
    },
    "botnet": {
        "persistence": 0.50,
        "speed_delay": 0.1,
        "attack_types": ["brute_force", "port_scan"],
        "description": "High-speed automated brute-forcing tools"
    },
    "insider": {
        "persistence": 0.70,
        "speed_delay": 1.5,
        "attack_types": ["path_traversal", "command_injection"],
        "description": "Targeted file exploration seeking configuration keys"
    },
    "red_team": {
        "persistence": 0.85,
        "speed_delay": 1.0,
        "attack_types": ["sql_injection", "path_traversal", "command_injection"],
        "description": "Methodical stealth operations seeking database extracts"
    },
    "apt": {
        "persistence": 0.95,
        "speed_delay": 0.5,
        "attack_types": ["sql_injection", "command_injection", "malware_delivery"],
        "description": "Highly sophisticated intruder deploying malware binaries"
    }
}

class DeceptionDigitalTwin:
    """
    Deception Experimentation Sandbox that simulates adversarial engagements,
    validates defensive layouts, and runs offline policy training for CMARL.
    """
    def __init__(self, db: Session):
        self.db = db

    def simulate_adversary_session(self, persona_key: str) -> Dict[str, Any]:
        """
        Simulates a session engagement with a specific attacker persona.
        Returns: Forensic metrics detailing engagement effectiveness.
        """
        persona = ATTACKER_PERSONAS.get(persona_key, ATTACKER_PERSONAS["script_kiddie"])
        attack_chain = persona["attack_types"]
        persistence = persona["persistence"]
        
        session_id = f"twin_sess_{random.randint(100000, 999999)}"
        ip_address = f"192.168.10.{random.randint(10, 250)}"
        
        # Initialize Twin Session record
        session = AttackerSession(
            session_id=session_id,
            ip_address=ip_address,
            is_active=True,
            rl_state="start",
            rl_action="default:low"
        )
        self.db.add(session)
        self.db.commit()
        
        time_elapsed = 0.0
        intel_collected_count = 0
        successful_deceptions = 0
        depth = 0
        
        history_logs = []
        
        for step, attack in enumerate(attack_chain):
            depth += 1
            # Query cooperative action choice
            history_bucket = "new" if step == 0 else "returning"
            state_str = coop_rl.serialize_state(attack, history_bucket, "low")
            coordinator = coop_rl.CooperativeRLCoordinator(self.db)
            coexistence_action, selected_agents, _ = coordinator.select_coordinated_strategy(state_str)
            
            chosen_profile = coexistence_action.split(":")[0]
            chosen_level = coexistence_action.split(":")[1] if ":" in coexistence_action else "low"
            
            # Log simulated attack payload
            log = AttackLog(
                session_id=session_id,
                ip_address=ip_address,
                attack_type=attack,
                payload=f"Simulated {attack} payload",
                confidence=0.90,
                risk_score=75.0,
                deception_action=coexistence_action
            )
            self.db.add(log)
            history_logs.append(log)
            
            # Measure effectiveness
            deception_profile = decision_engine.get_deception_profile(chosen_profile)
            delay = (deception_profile.get("response_delay_ms", 0) / 1000.0) + persona["speed_delay"]
            time_elapsed += delay
            
            if chosen_profile == attack:
                successful_deceptions += 1
                intel_collected_count += 5
                # The attacker is successfully deceived and remains engaged
                continue
            else:
                intel_collected_count += 1
                # Probability check if attacker discovers deception and exits early
                if random.random() > persistence:
                    break

        # Finalize and close the simulated session
        session.is_active = False
        session.session_duration = time_elapsed
        session.interaction_depth = depth
        session.rl_deception_score = successful_deceptions / len(attack_chain) if attack_chain else 0.0
        self.db.commit()
        
        # Perform learning updates for the twin session run
        final_dec_score = session.rl_deception_score
        coop_rl.update_q_table_for_session(self.db, session_id, "twin_start", "brute_force:high", final_dec_score)
        
        return {
            "session_id": session_id,
            "persona": persona_key,
            "dwell_time_seconds": round(time_elapsed, 2),
            "interaction_depth": depth,
            "deception_success_ratio": round(successful_deceptions / len(attack_chain), 2) if attack_chain else 0.0,
            "intelligence_points_collected": intel_collected_count
        }

    def run_offline_rl_training(self, episodes: int = 50) -> List[Dict[str, Any]]:
        """
        Runs batch simulations across various threat personas to populate the Q-learning tables entirely offline.
        """
        personas = list(ATTACKER_PERSONAS.keys())
        results = []
        for _ in range(episodes):
            p = random.choice(personas)
            res = self.simulate_adversary_session(p)
            results.append(res)
        return results
