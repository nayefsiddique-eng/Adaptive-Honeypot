from typing import Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from backend.models.attack import AttackLog
from backend.models.session import AttackerSession
import backend.core.behavior_intelligence as behavior_intel
import backend.core.threat_intel_fusion as threat_fusion
import backend.core.cooperative_rl_engine as coop_rl

# Copy of standard DECEPTION_PROFILES configuration to keep it backward compatible
DECEPTION_PROFILES = {
    "brute_force": {
        "state": "credential_trap",
        "fake_services": ["ssh:22", "ftp:21", "rdp:3389"],
        "fake_banners": {"ssh": "SSH-2.0-OpenSSH_7.4 (CentOS Linux)", "ftp": "220 ProFTPD 1.3.5 Server ready", "rdp": "Windows Server 2016 Standard"},
        "response_delay_ms": 2000,
        "fake_credentials_accepted": True,
        "decoy_files": ["passwords.txt", "credentials.csv", "admin_backup.zip"],
        "description": "Slow down attacker with delayed responses and fake credential acceptance"
    },
    "port_scan": {
        "state": "port_expansion",
        "fake_services": ["http:8080", "mysql:3306", "redis:6379", "mongodb:27017"],
        "fake_banners": {"http": "Apache/2.4.29 (Ubuntu)", "mysql": "5.7.32-MySQL Community Server"},
        "response_delay_ms": 500,
        "fake_credentials_accepted": False,
        "decoy_files": [],
        "description": "Expose fake vulnerable services to waste attacker reconnaissance time"
    },
    "sql_injection": {
        "state": "database_decoy",
        "fake_services": ["http:80", "mysql:3306"],
        "fake_banners": {"http": "Apache/2.2.22 (Debian)", "mysql": "5.5.62-MySQL Community Server"},
        "response_delay_ms": 100,
        "fake_credentials_accepted": False,
        "decoy_files": ["database_dump.sql", "users_table.csv", "schema.sql"],
        "description": "Return fake database records to study attacker data interests"
    },
    "xss": {
        "state": "web_decoy",
        "fake_services": ["http:80", "http:443"],
        "fake_banners": {"http": "nginx/1.14.0 (Ubuntu)"},
        "response_delay_ms": 100,
        "fake_credentials_accepted": False,
        "decoy_files": ["config.js", "api_keys.json"],
        "description": "Serve vulnerable-looking web pages with tracking pixels"
    },
    "command_injection": {
        "state": "shell_trap",
        "fake_services": ["ssh:22", "http:8080"],
        "fake_banners": {"ssh": "SSH-2.0-OpenSSH_6.6 (Ubuntu)"},
        "response_delay_ms": 300,
        "fake_credentials_accepted": True,
        "decoy_files": ["id_rsa", "authorized_keys", "shadow", "passwd"],
        "description": "Simulate a compromised shell to study attacker post-exploitation behavior"
    },
    "malware_delivery": {
        "state": "malware_sink",
        "fake_services": ["http:80", "ftp:21"],
        "fake_banners": {"http": "Apache/2.4.18 (Ubuntu)", "ftp": "220 vsftpd 2.3.5"},
        "response_delay_ms": 200,
        "fake_credentials_accepted": True,
        "decoy_files": ["setup.exe", "update.bat", "install.sh", "payload.ps1"],
        "description": "Accept malware uploads and serve fake executables for analysis"
    },
    "path_traversal": {
        "state": "filesystem_decoy",
        "fake_services": ["http:80"],
        "fake_banners": {"http": "Apache/2.2.15 (CentOS)"},
        "response_delay_ms": 150,
        "fake_credentials_accepted": False,
        "decoy_files": ["../../etc/passwd", "../../etc/shadow", "../../var/log/auth.log"],
        "description": "Return fake sensitive files to study attacker information gathering"
    },
    "unknown": {
        "state": "default",
        "fake_services": ["http:80", "ssh:22"],
        "fake_banners": {"http": "Apache/2.4.29", "ssh": "SSH-2.0-OpenSSH_7.6"},
        "response_delay_ms": 0,
        "fake_credentials_accepted": False,
        "decoy_files": [],
        "description": "Default honeypot state with minimal deception"
    }
}

def get_deception_profile(attack_type: str) -> Dict[str, Any]:
    return DECEPTION_PROFILES.get(attack_type, DECEPTION_PROFILES["unknown"])

def decide_honeypot_action(attack_type: str, confidence: float, risk_score: float, attacker_history: Dict[str, Any] = {}) -> Dict[str, Any]:
    """
    Backward-compatible fallback mapping for standard rule-based profiles.
    """
    profile = get_deception_profile(attack_type)
    return {
        "action": "full_deception" if risk_score >= 80 else "active_deception" if risk_score >= 50 else "monitor",
        "profile": profile,
        "priority": "critical" if risk_score >= 80 else "medium",
        "confidence": confidence
    }

def detect_attack_chain(attack_type: str, session_logs: List[AttackLog]) -> Tuple[int, str]:
    """
    Computes kill chain metrics for attacker telemetry.
    """
    unique_types = {log.attack_type for log in session_logs}
    progress = len(unique_types)
    if "command_injection" in unique_types or "malware_delivery" in unique_types:
        return progress, "Exfiltration / Exploitation Stage"
    elif "sql_injection" in unique_types or "path_traversal" in unique_types:
        return progress, "Intrusion / Exploit Stage"
    return progress, "Reconnaissance Stage"

class AutonomousDecisionEngine:
    """
    The unified brain of PRAETOR. Fuses ML classification, GeoIP, threat intelligence feeds,
    keystroke history, and Cooperative RL outcomes to generate context-aware deception strategies.
    """
    def __init__(self, db: Session):
        self.db = db

    def evaluate_decision_state(self, ip_address: str, current_session_id: str, attack_type: str, confidence: float) -> Dict[str, Any]:
        # 1. Gather all fusion intelligence signals
        intel_profile = threat_fusion.fuse_attacker_intelligence(self.db, ip_address, current_session_id)
        
        # 2. Extract session historical sequence
        session_logs = self.db.query(AttackLog).filter(AttackLog.session_id == current_session_id).all()
        sequence = behavior_intel.build_attack_sequence(session_logs)
        
        # 3. Predict intent details
        next_ttp, ttp_prob = behavior_intel.predict_next_mitre_technique(sequence)
        expected_obj = behavior_intel.infer_attacker_objective(sequence)
        attributes = behavior_intel.estimate_attacker_properties(sequence)
        
        # 4. Invoke the Cooperative Q-learning Coordinator
        history_bucket = behavior_intel.get_history_bucket(len(session_logs))
        state_str = coop_rl.serialize_state(attack_type, history_bucket, "low")
        coordinator = coop_rl.CooperativeRLCoordinator(self.db)
        coexistence_action, selected_agents, rl_confidence = coordinator.select_coordinated_strategy(state_str)
        
        # 5. Formulate unified decision context
        chosen_profile = coexistence_action.split(":")[0]
        chosen_level = coexistence_action.split(":")[1] if ":" in coexistence_action else "low"
        profile_details = get_deception_profile(chosen_profile)
        
        # 6. Formulate reasoning trace
        reasoning_trace = (
            f"Adversary classified as {intel_profile['threat_actor_profile']} with {confidence*100:.1f}% confidence. "
            f"Behavior sequence mapped {len(sequence)} TTP transitions. "
            f"Cooperative agents selected strategy '{coexistence_action}' (Network Agent level: '{chosen_level}'). "
            f"Deception is targeted at mitigating expected '{expected_obj}' objectives."
        )

        return {
            "recommended_strategy": coexistence_action,
            "profile_details": profile_details,
            "confidence_score": round((confidence + rl_confidence) / 2.0, 4),
            "reasoning_trace": reasoning_trace,
            "expected_attacker_objective": expected_obj,
            "expected_deception_effectiveness": 0.90 if chosen_profile == attack_type else 0.40,
            "predicted_next_ttp": next_ttp,
            "threat_fusion": intel_profile,
            "attacker_properties": attributes,
            "agents_decisions": selected_agents
        }