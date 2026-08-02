from typing import Dict, Any
import re

COMMON_PASSWORDS = ["admin", "password", "123456", "root", "test", "guest", "letmein"]
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080]
MALWARE_EXTENSIONS = [".exe", ".bat", ".sh", ".ps1", ".py", ".php", ".jsp"]

def extract_features(ip: str, port: int, protocol: str, payload: str, metadata: dict) -> Dict[str, Any]:
    features = {}
    features["port"] = port
    features["is_known_vuln_port"] = int(port in SCAN_PORTS)
    features["is_ssh"] = int(port == 22)
    features["is_http"] = int(port in [80, 8080])
    features["is_ftp"] = int(port == 21)
    features["is_rdp"] = int(port == 3389)
    payload_lower = payload.lower() if payload else ""
    features["payload_length"] = len(payload) if payload else 0
    features["has_common_password"] = int(any(p in payload_lower for p in COMMON_PASSWORDS))
    features["has_malware_extension"] = int(any(ext in payload_lower for ext in MALWARE_EXTENSIONS))
    features["has_sql_injection"] = int(any(kw in payload_lower for kw in ["select ", "union ", "drop ", "insert ", "' or ", "1=1"]))
    features["has_xss"] = int(any(kw in payload_lower for kw in ["<script", "javascript:", "onerror=", "onload="]))
    features["has_path_traversal"] = int("../" in payload or "..\\" in payload) if payload else 0
    features["has_command_injection"] = int(any(kw in payload_lower for kw in ["; ls", "; cat", "| whoami", "&& id", "`id`"]))
    features["protocol_tcp"] = int(protocol.upper() == "TCP")
    features["protocol_udp"] = int(protocol.upper() == "UDP")
    features["protocol_ssh"] = int(protocol.upper() == "SSH")
    features["protocol_http"] = int(protocol.upper() == "HTTP")
    features["protocol_dns"] = int(protocol.upper() == "DNS")
    features["login_attempts"] = metadata.get("login_attempts", 0)
    features["unique_usernames"] = metadata.get("unique_usernames", 0)
    features["unique_passwords"] = metadata.get("unique_passwords", 0)
    features["commands_executed"] = metadata.get("commands_executed", 0)
    features["files_requested"] = metadata.get("files_requested", 0)
    features["ports_scanned"] = metadata.get("ports_scanned", 0)

    # Feature 6 - Additional Attack Heuristics
    features["has_ssrf"] = int(any(kw in payload_lower for kw in ["localhost", "169.254.169.254", "file://", "dict://"]))
    features["has_ldap_injection"] = int(any(kw in payload_lower for kw in [")(", "*)(", "ldap://"]))
    features["has_deserialization"] = int(any(kw in payload_lower or kw in (payload or "") for kw in ["rO0AB", "ACED0005", "__reduce__"]))

    # Feature 1 - TTP Fingerprinting
    # 1.1 Timing Pattern
    request_timestamps = metadata.get("request_timestamps", [])
    timing_pattern = "slow_drip"
    if len(request_timestamps) >= 2:
        try:
            parsed_ts = []
            for t in request_timestamps:
                if isinstance(t, (int, float)):
                    parsed_ts.append(float(t))
                elif isinstance(t, str):
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(t.replace('Z', '+00:00'))
                        parsed_ts.append(dt.timestamp())
                    except ValueError:
                        parsed_ts.append(float(t))
            parsed_ts.sort()
            diffs = [parsed_ts[i] - parsed_ts[i-1] for i in range(1, len(parsed_ts))]
            if diffs:
                avg_diff = sum(diffs) / len(diffs)
                max_diff = max(diffs)
                min_diff = min(diffs)
                diff_range = max_diff - min_diff
                if avg_diff < 2.0:
                    timing_pattern = "rapid_burst"
                elif diff_range < 0.5 and avg_diff > 0.0:
                    timing_pattern = "periodic"
                else:
                    timing_pattern = "slow_drip"
        except Exception:
            pass

    # 1.2 Tool Signature
    user_agent = metadata.get("user_agent", "").lower() if metadata else ""
    ports_scanned = metadata.get("ports_scanned", 0)
    login_attempts = metadata.get("login_attempts", 0)
    unique_passwords = metadata.get("unique_passwords", 0)

    tool_signature = "custom"
    if "sqlmap" in payload_lower or "sqlmap" in user_agent or "--dbs" in payload_lower or "--dump" in payload_lower:
        tool_signature = "sqlmap"
    elif "nmap" in user_agent or (ports_scanned > 10 and protocol.upper() == "TCP"):
        tool_signature = "nmap"
    elif "hydra" in user_agent or (login_attempts > 20 and unique_passwords > 10):
        tool_signature = "hydra"
    elif "meterpreter" in payload_lower or "msf" in payload_lower or "x86/shikata_ga_nai" in payload_lower or "metasploit" in user_agent:
        tool_signature = "metasploit"

    # 1.3 Evasion Attempts
    evasion_attempts = 0
    if payload:
        url_encodings = len(re.findall(r"%[0-9a-fA-F]{2}", payload))
        null_bytes = payload.count("\x00") + payload.count("%00") + payload.count("\\x00") + payload.count("\\u0000")
        base64_padding = payload.count("=") + payload.count("%3d") + payload.count("%3D")
        evasion_attempts = url_encodings + null_bytes + base64_padding

    # 1.4 Attack Chain Stage
    is_exploit = any(
        features.get(k) == 1 for k in [
            "has_sql_injection", "has_xss", "has_path_traversal", 
            "has_command_injection", "has_ssrf", "has_ldap_injection", "has_deserialization"
        ]
    )
    is_weaponize = (
        features.get("has_malware_extension") == 1 or 
        any(kw in payload_lower for kw in ["wget ", "curl ", "powershell", "certutil", "tftp", "ftp -s"])
    )
    is_post_exploit = (
        metadata.get("commands_executed", 0) > 0 or 
        "post_exploit" in payload_lower or
        "whoami" in payload_lower or 
        "cat /etc/" in payload_lower or 
        "net user" in payload_lower
    )
    
    if is_post_exploit:
        attack_chain_stage = "post_exploit"
    elif is_exploit:
        attack_chain_stage = "exploit"
    elif is_weaponize:
        attack_chain_stage = "weaponize"
    else:
        attack_chain_stage = "recon"

    # Assemble fingerprint
    ttp_fingerprint = {
        "timing_pattern": timing_pattern,
        "tool_signature": tool_signature,
        "evasion_attempts": evasion_attempts,
        "attack_chain_stage": attack_chain_stage
    }

    features["ttp_fingerprint"] = ttp_fingerprint
    return features


def classify_attack_heuristic(features: Dict[str, Any]) -> str:
    if features.get("has_command_injection"):
        return "command_injection"
    if features.get("has_sql_injection"):
        return "sql_injection"
    if features.get("has_xss"):
        return "xss"
    if features.get("has_path_traversal"):
        return "path_traversal"
    if features.get("has_malware_extension"):
        return "malware_delivery"
    # Route Feature 6 heuristics
    if features.get("has_ssrf"):
        return "ssrf"
    if features.get("has_ldap_injection"):
        return "ldap_injection"
    if features.get("has_deserialization"):
        return "deserialization"
    if features.get("port") == 53 or features.get("protocol_dns"):
        return "dns_tunneling"
    if features.get("login_attempts", 0) > 20 and features.get("unique_usernames", 0) > 10:
        return "credential_stuffing"
    if features.get("login_attempts", 0) > 5 or features.get("has_common_password"):
        return "brute_force"
    if features.get("ports_scanned", 0) > 3 or features.get("is_known_vuln_port"):
        return "port_scan"
    return "unknown"