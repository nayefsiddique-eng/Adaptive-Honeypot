import math
from typing import Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from backend.models.attack import AttackLog
from backend.models.session import AttackerSession

# Map attack types to standard MITRE ATT&CK techniques
MITRE_ATTACK_MAPPING = {
    "brute_force": {"id": "T1110", "name": "Brute Force", "stage": "Credential Access"},
    "port_scan": {"id": "T1046", "name": "Network Service Discovery", "stage": "Discovery"},
    "sql_injection": {"id": "T1190", "name": "Exploit Public-Facing Application", "stage": "Initial Access"},
    "xss": {"id": "T1189", "name": "Drive-by Compromise", "stage": "Initial Access"},
    "command_injection": {"id": "T1203", "name": "Exploitation for Client Execution", "stage": "Execution"},
    "malware_delivery": {"id": "T1105", "name": "Ingress Tool Transfer", "stage": "Command and Control"},
    "path_traversal": {"id": "T1083", "name": "File and Directory Discovery", "stage": "Discovery"},
    "unknown": {"id": "T1595", "name": "Active Scanning", "stage": "Reconnaissance"}
}

# Transition matrix probabilities (prior probabilities representing typical attack paths)
TTP_TRANSITION_PROBS = {
    "T1046": {"T1190": 0.4, "T1110": 0.3, "T1083": 0.2, "T1046": 0.1},  # Discovery -> Exploit / Brute Force
    "T1110": {"T1203": 0.5, "T1105": 0.3, "T1110": 0.2},                # Brute Force -> Execution / Tool Transfer
    "T1190": {"T1083": 0.4, "T1203": 0.4, "T1190": 0.2},                # Exploit -> Discovery / Execution
    "T1083": {"T1105": 0.6, "T1083": 0.2, "T1595": 0.2},                # File Discovery -> Ingress / Active Scan
    "T1203": {"T1105": 0.7, "T1203": 0.2, "T1046": 0.1},                # Execution -> Ingress Tool Transfer
    "T1105": {"T1110": 0.3, "T1105": 0.3, "unknown": 0.4}               # Tool Transfer -> Loop
}

def get_mitre_details(attack_type: str) -> Dict[str, str]:
    return MITRE_ATTACK_MAPPING.get(attack_type, MITRE_ATTACK_MAPPING["unknown"])

def build_attack_sequence(session_logs: List[AttackLog]) -> List[str]:
    """
    Sorts attack logs chronologically and extracts their MITRE technique IDs.
    """
    sorted_logs = sorted(session_logs, key=lambda x: x.timestamp)
    return [get_mitre_details(log.attack_type)["id"] for log in sorted_logs]

def predict_next_mitre_technique(sequence: List[str]) -> Tuple[str, float]:
    """
    Predicts the next MITRE ATT&CK technique based on historical state transitions.
    """
    if not sequence:
        return "T1046", 0.5  # Default to Network Service Discovery
        
    last_ttp = sequence[-1]
    transitions = TTP_TRANSITION_PROBS.get(last_ttp, TTP_TRANSITION_PROBS["T1046"])
    
    # Select the transition with the highest probability
    best_ttp = max(transitions, key=transitions.get)
    return best_ttp, transitions[best_ttp]

def infer_attacker_objective(sequence: List[str]) -> str:
    """
    Infers the adversary's primary objective based on the observed sequence of techniques.
    """
    if not sequence:
        return "Reconnaissance"
        
    stages = [MITRE_ATTACK_MAPPING.get(
        next((k for k, v in MITRE_ATTACK_MAPPING.items() if v["id"] == ttp), "unknown"),
        {"stage": "Reconnaissance"}
    )["stage"] for ttp in sequence]
    
    # Heuristics based on kill chain depth
    if "Command and Control" in stages:
        return "System Compromise & Exfiltration"
    if "Execution" in stages:
        return "Arbitrary Shell Execution"
    if "Credential Access" in stages:
        return "Privilege Escalation / Lateral Movement"
    if "Discovery" in stages or "Initial Access" in stages:
        return "Vulnerability Probing & Mapping"
        
    return "Reconnaissance"

def calculate_fingerprint(sequence: List[str]) -> Dict[str, float]:
    """
    Computes a normalized frequency vector (fingerprint) of the attacker's techniques.
    """
    fingerprint = {v["id"]: 0.0 for v in MITRE_ATTACK_MAPPING.values()}
    if not sequence:
        return fingerprint
        
    for ttp in sequence:
        if ttp in fingerprint:
            fingerprint[ttp] += 1.0
            
    total = sum(fingerprint.values())
    if total > 0:
        for k in fingerprint:
            fingerprint[k] /= total
            
    return fingerprint

def calculate_cosine_similarity(vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
    dot_product = sum(vec1[k] * vec2.get(k, 0.0) for k in vec1)
    norm1 = math.sqrt(sum(v**2 for v in vec1.values()))
    norm2 = math.sqrt(sum(v**2 for v in vec2.values()))
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return dot_product / (norm1 * norm2)

def analyze_campaign_similarity(db: Session, current_session_id: str, current_sequence: List[str]) -> Tuple[str, float]:
    """
    Identifies the historically logged session most similar to the current active session.
    """
    current_fp = calculate_fingerprint(current_sequence)
    
    # Query other non-active completed sessions
    other_sessions = db.query(AttackerSession).filter(
        AttackerSession.session_id != current_session_id
    ).limit(30).all()
    
    best_match_id = "None"
    best_score = 0.0
    
    for s in other_sessions:
        # Retrieve logs for this historical session
        hist_logs = db.query(AttackLog).filter(AttackLog.session_id == s.session_id).all()
        hist_seq = build_attack_sequence(hist_logs)
        hist_fp = calculate_fingerprint(hist_seq)
        
        sim = calculate_cosine_similarity(current_fp, hist_fp)
        if sim > best_score:
            best_score = sim
            best_match_id = s.session_id
            
    return best_match_id, round(best_score, 4)

def estimate_attacker_properties(sequence: List[str]) -> Dict[str, Any]:
    """
    Predicts likely persistence and dwell time based on the TTP count.
    """
    length = len(sequence)
    persistence_prob = min(0.95, 0.1 + (length * 0.15))
    expected_dwell_seconds = 15.0 + (length * 30.0)
    
    return {
        "persistence_probability": round(persistence_prob, 2),
        "expected_dwell_time_seconds": expected_dwell_seconds
    }
