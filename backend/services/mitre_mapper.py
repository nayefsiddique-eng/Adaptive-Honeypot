MITRE_MAP = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110"
    },
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046"
    },
    "sql_injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190"
    },
    "xss": {
        "technique_id": "T1059.007",
        "technique_name": "JavaScript Execution",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/007"
    },
    "command_injection": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059"
    },
    "malware_delivery": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1105"
    },
    "path_traversal": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083"
    },
    "ldap_injection": {
        "technique_id": "T1558",
        "technique_name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1558"
    },
    "ssrf": {
        "technique_id": "T1090.002",
        "technique_name": "External Proxy",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1090/002"
    },
    "deserialization": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059"
    },
    "dns_tunneling": {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/004"
    },
    "credential_stuffing": {
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/004"
    },
    "unknown": {
        "technique_id": "T0000",
        "technique_name": "Unclassified",
        "tactic": "Unknown",
        "url": "https://attack.mitre.org"
    }
}

def map_to_mitre(attack_type: str) -> dict:
    return MITRE_MAP.get(attack_type, MITRE_MAP["unknown"])
