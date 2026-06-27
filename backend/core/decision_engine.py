from typing import Dict, Any

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
    profile = get_deception_profile(attack_type)
    attack_count = attacker_history.get("attack_count", 0)
    if confidence < 0.6:
        action = "monitor"
        priority = "low"
    elif risk_score >= 80:
        action = "full_deception"
        priority = "critical"
    elif risk_score >= 60:
        action = "active_deception"
        priority = "high"
    elif risk_score >= 40:
        action = "partial_deception"
        priority = "medium"
    else:
        action = "monitor"
        priority = "low"
    if attack_count > 10:
        action = "full_deception"
        priority = "critical"
    return {
        "action": action,
        "priority": priority,
        "honeypot_state": profile["state"],
        "fake_services": profile["fake_services"],
        "fake_banners": profile["fake_banners"],
        "response_delay_ms": profile["response_delay_ms"],
        "fake_credentials_accepted": profile["fake_credentials_accepted"],
        "decoy_files": profile["decoy_files"],
        "description": profile["description"],
        "reasoning": f"Attack '{attack_type}' confidence {confidence:.0%} risk {risk_score} triggers '{action}'"
    }


KNOWN_CHAINS = {
    "recon_to_exploit": ["port_scan", "sql_injection"],
    "recon_to_brute": ["port_scan", "brute_force"],
    "recon_to_rce": ["port_scan", "command_injection"],
    "lateral_movement": ["brute_force", "command_injection"],
    "data_exfiltration": ["sql_injection", "path_traversal"],
    "full_kill_chain": ["port_scan", "brute_force", "command_injection", "malware_delivery"],
}

def detect_attack_chain(previous_attack_types: list) -> dict:
    if not previous_attack_types:
        return {
            "chain_detected": False,
            "chain_name": None,
            "chain_progress": 0,
            "chain_total": 0,
            "completion_pct": 0.0
        }
    
    best_chain = None
    best_progress = 0
    best_total = 0
    best_pct = -1.0
    
    for chain_name, chain_steps in KNOWN_CHAINS.items():
        matched = [step for step in chain_steps if step in previous_attack_types]
        progress = len(matched)
        total = len(chain_steps)
        pct = progress / total if total > 0 else 0.0
        
        if progress > 0:
            if (pct > best_pct) or (pct == best_pct and progress > best_progress):
                best_pct = pct
                best_chain = chain_name
                best_progress = progress
                best_total = total
                
    chain_detected = best_progress >= 2
    return {
        "chain_detected": chain_detected,
        "chain_name": best_chain,
        "chain_progress": best_progress,
        "chain_total": best_total,
        "completion_pct": round(best_pct * 100.0, 2) if best_chain else 0.0
    }