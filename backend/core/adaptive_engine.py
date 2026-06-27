from typing import Dict, Any

# Map of active ports currently "exposed" by the dynamic honeypot.
# In a real environment, this might interface with iptables/nftables.
# Here it is simulated dynamically for threat analytics.
DYNAMIC_PORT_STATES = {}

def decide_behavior(
    attack_type: str, 
    confidence: float, 
    risk_score: float, 
    attacker_history: Dict[str, Any]
) -> Dict[str, Any]:
    """
    True Adaptive Behavior Engine.
    Determines deception response, level of interaction, exposed services,
    and simulated ports based on attack data, risk, and historical reputation.
    """
    total_sessions = attacker_history.get("total_sessions", 1)
    attack_count = attacker_history.get("attack_count", 1)
    prev_types = attacker_history.get("previous_attack_types", [])
    ip_address = attacker_history.get("ip_address", "unknown")
    
    # Base response
    response = {
        "action": "monitor",
        "interaction_level": "low",
        "honeypot_state": "default",
        "fake_services": [],
        "fake_banners": {},
        "response_delay_ms": 0,
        "fake_credentials_accepted": False,
        "decoy_files": [],
        "exposed_ports": [80, 22],
        "reasoning": ""
    }

    # 1. Deception profile customization based on attack type
    if attack_type == "brute_force":
        response["honeypot_state"] = "credential_trap"
        response["fake_services"] = ["ssh:22", "ftp:21"]
        response["fake_banners"] = {
            "ssh": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "ftp": "220 vsftpd 3.0.3"
        }
        response["fake_credentials_accepted"] = True
        response["response_delay_ms"] = 1000
        response["decoy_files"] = ["passwords.txt", "admin_config.yml"]

    elif attack_type == "sql_injection":
        response["honeypot_state"] = "database_decoy"
        response["fake_services"] = ["http:80", "mysql:3306"]
        response["fake_banners"] = {
            "http": "Apache/2.4.41 (Ubuntu)",
            "mysql": "5.7.35-log MySQL Community Server"
        }
        response["decoy_files"] = ["db_backup.sql", "users.csv"]
        response["response_delay_ms"] = 200

    elif attack_type == "malware_delivery":
        response["honeypot_state"] = "malware_sink"
        response["fake_services"] = ["http:80", "ftp:21", "smb:445"]
        response["fake_banners"] = {
            "http": "nginx/1.18.0",
            "smb": "Windows Server 2019 Standard"
        }
        response["fake_credentials_accepted"] = True
        response["decoy_files"] = ["agent.sh", "installer.msi"]
        response["response_delay_ms"] = 300

    elif attack_type == "port_scan":
        response["honeypot_state"] = "port_expansion"
        response["fake_services"] = ["http:8080", "redis:6379", "mongodb:27017"]
        response["fake_banners"] = {
            "http": "Apache/2.2.15 (CentOS)",
            "redis": "Redis key-value store 6.0"
        }
        response["response_delay_ms"] = 50

    elif attack_type == "command_injection":
        response["honeypot_state"] = "shell_trap"
        response["fake_services"] = ["ssh:22", "http:8080"]
        response["fake_banners"] = {
            "ssh": "SSH-2.0-OpenSSH_7.4"
        }
        response["fake_credentials_accepted"] = True
        response["decoy_files"] = ["id_rsa", "authorized_keys", "passwd"]
        response["response_delay_ms"] = 400

    elif attack_type == "path_traversal":
        response["honeypot_state"] = "filesystem_decoy"
        response["fake_services"] = ["http:80"]
        response["fake_banners"] = {
            "http": "nginx/1.14.2"
        }
        response["decoy_files"] = ["/etc/passwd", "/etc/shadow", "/var/log/auth.log"]
        response["response_delay_ms"] = 100

    # 2. Adjust Interaction Depth & Action based on Confidence Score
    if confidence >= 0.85:
        response["action"] = "engage"
        response["interaction_level"] = "high"
    elif confidence >= 0.50:
        response["action"] = "engage"
        response["interaction_level"] = "medium"
    else:
        response["action"] = "monitor"
        response["interaction_level"] = "low"

    # 3. Escalate response based on Attacker History and Frequency
    # If repeated attacks or multiple sessions occur, we escalate the deception depth
    if total_sessions > 3 or attack_count > 15:
        response["interaction_level"] = "high"
        response["response_delay_ms"] += 1000  # Intentionally slow down attacker to keep them engaged longer
        response["decoy_files"].extend(["flag.txt", "restricted_intel.json"])
        
        # Add high-interaction flags
        if attack_type == "brute_force":
            response["honeypot_state"] = "interactive_shell_trap"
        elif attack_type == "sql_injection":
            response["honeypot_state"] = "fake_blind_sqli_db"

    # 4. Dynamic Port Exposure
    # If the attacker has repeatedly scanned us (e.g. port scan is in history or attack count is high)
    # expose additional simulated ports to waste their time
    if "port_scan" in prev_types or attack_count >= 5:
        # Dynamically expand ports exposed to this attacker
        response["exposed_ports"] = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080]
        # Expose extra simulated fake services
        if attack_count >= 10:
            response["fake_services"].extend(["ftp:21", "mysql:3306", "smb:445"])
            response["fake_banners"]["ftp"] = "220 FTP Server Ready"
            response["fake_banners"]["mysql"] = "5.6.40-log MySQL Community Server"
            response["fake_banners"]["smb"] = "Windows 10 Pro SMB Service"

    # 5. Reasoning Text summarizing adaptation
    response["reasoning"] = (
        f"Attack {attack_type} (conf {confidence:.0%}, risk {risk_score}) "
        f"with {attack_count} previous events across {total_sessions} sessions "
        f"triggered adaptation state '{response['honeypot_state']}' with "
        f"interaction '{response['interaction_level']}'."
    )

    interaction_level_map = {"low": 0, "medium": 1, "high": 2, "deep": 3}
    interaction_level = response["interaction_level"]
    deception_score = (
        (interaction_level_map.get(interaction_level, 0) / 3.0) * 0.40 +
        (len(response["fake_services"]) / 5.0) * 0.20 +
        (len(response["decoy_files"]) / 6.0) * 0.20 +
        (min(response["response_delay_ms"], 2000) / 2000.0) * 0.20
    )
    response["deception_score"] = min(round(deception_score, 4), 1.0)

    return response