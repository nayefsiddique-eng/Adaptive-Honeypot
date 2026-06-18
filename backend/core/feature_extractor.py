from typing import Dict, Any

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
    payload_lower = payload.lower()
    features["payload_length"] = len(payload)
    features["has_common_password"] = int(any(p in payload_lower for p in COMMON_PASSWORDS))
    features["has_malware_extension"] = int(any(ext in payload_lower for ext in MALWARE_EXTENSIONS))
    features["has_sql_injection"] = int(any(kw in payload_lower for kw in ["select ", "union ", "drop ", "insert ", "' or ", "1=1"]))
    features["has_xss"] = int(any(kw in payload_lower for kw in ["<script", "javascript:", "onerror=", "onload="]))
    features["has_path_traversal"] = int("../" in payload or "..\\" in payload)
    features["has_command_injection"] = int(any(kw in payload_lower for kw in ["; ls", "; cat", "| whoami", "&& id", "`id`"]))
    features["protocol_tcp"] = int(protocol.upper() == "TCP")
    features["protocol_udp"] = int(protocol.upper() == "UDP")
    features["protocol_ssh"] = int(protocol.upper() == "SSH")
    features["protocol_http"] = int(protocol.upper() == "HTTP")
    features["login_attempts"] = metadata.get("login_attempts", 0)
    features["unique_usernames"] = metadata.get("unique_usernames", 0)
    features["unique_passwords"] = metadata.get("unique_passwords", 0)
    features["commands_executed"] = metadata.get("commands_executed", 0)
    features["files_requested"] = metadata.get("files_requested", 0)
    features["ports_scanned"] = metadata.get("ports_scanned", 0)
    return features


def classify_attack_heuristic(features: Dict[str, Any]) -> str:
    if features["has_command_injection"]:
        return "command_injection"
    if features["has_sql_injection"]:
        return "sql_injection"
    if features["has_xss"]:
        return "xss"
    if features["has_path_traversal"]:
        return "path_traversal"
    if features["has_malware_extension"]:
        return "malware_delivery"
    if features["login_attempts"] > 5 or features["has_common_password"]:
        return "brute_force"
    if features["ports_scanned"] > 3 or features["is_known_vuln_port"]:
        return "port_scan"
    return "unknown"