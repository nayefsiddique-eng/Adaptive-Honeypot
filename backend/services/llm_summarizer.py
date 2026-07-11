import os
import httpx2 as httpx
import time
from typing import Dict, Any

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

LAST_GEMINI_CALL = 0.0

# Stats counters for cache metrics
gemini_cache_hits = 0
gemini_cache_queries = 0

async def generate_attack_summary(
    attack_type: str, 
    confidence: float, 
    risk_score: float, 
    payload: str, 
    ip: str, 
    history: Dict[str, Any]
) -> Dict[str, str]:
    """
    Generates a security analyst threat summary for an attack log.
    Calls Gemini API if key is present, rate limit allows, and falls back to template engine.
    """
    global LAST_GEMINI_CALL
    now = time.time()
    
    # Try calling Gemini only if API key is present and rate limit (>2s since last call) is satisfied
    if GEMINI_API_KEY and (now - LAST_GEMINI_CALL >= 2.0):
        LAST_GEMINI_CALL = now
        try:
            # Feature 4 - Compressed prompt
            prompt = (
                f"Security incident — respond ONLY in JSON with keys: description, summary, recommendation.\n"
                f"IP:{ip} Type:{attack_type} Confidence:{confidence:.0%} Risk:{risk_score}/100 "
                f"History:{history.get('attack_count',0)} attacks Chain:{history.get('chain_name','none')}\n"
                f"Payload(truncated):{payload[:150]}"
            )

            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
            headers = {"Content-Type": "application/json"}
            req_body = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "maxOutputTokens": 300  # Cap output size
                }
            }
            
            async with httpx.AsyncClient() as client:
                res = await client.post(url, headers=headers, json=req_body, timeout=8.0)
                if res.status_code == 200:
                    res_data = res.json()
                    import json
                    text_content = res_data["candidates"][0]["content"]["parts"][0]["text"]
                    parsed = json.loads(text_content)
                    return {
                        "description": parsed.get("description", ""),
                        "summary": parsed.get("summary", ""),
                        "recommendation": parsed.get("recommendation", "")
                    }
        except Exception:
            pass

    # Heuristic template fallback
    desc = f"Detection engines identified {attack_type.replace('_', ' ')} attempts from IP address {ip}."
    
    if attack_type == "brute_force":
        summary = (
            f"The adversary is executing high-frequency password guessing attempts targeting simulated authentication endpoints. "
            f"Given the confidence score of {confidence:.0%}, this is highly likely an automated script scanner attempting "
            f"to discover weak credentials. The local risk score of {risk_score}/100 reflects the volume of attempts."
        )
        recommendation = (
            "Escalate interaction level in the honeypot credential trap. Accept fake credentials after 3 attempts "
            "to capture post-authentication commands. Implement local rate limiting or fail2ban rules in production."
        )
    elif attack_type == "sql_injection":
        summary = (
            f"An exploitation attempt was detected targeting HTTP endpoints with SQL command sequences. "
            f"The payload contains SQL injection syntaxes designed to query database structures or bypass authentication. "
            f"The attacker sophistication is evaluated as moderate, possibly using automated tools like sqlmap."
        )
        recommendation = (
            "Activate the database decoy profile. Serve fake database tables and schemas to monitor queries "
            "and identify specific information targets. Ensure production applications use prepared statements."
        )
    elif attack_type == "malware_delivery":
        summary = (
            f"A malware delivery attempt was intercepted. The attacker is trying to upload files containing extensions "
            f"known for malicious payloads. The system is engaged in capturing payload hashes to support IOC correlation."
        )
        recommendation = (
            "Engage malware sink state. Allow file upload to complete, compute cryptographic hashes, and isolate "
            "the uploaded artifacts for dynamic sandbox analysis. Quarantine the IP."
        )
    elif attack_type == "port_scan":
        summary = (
            f"Reconnaissance activity was observed. The attacker scanned multiple ports within a short timeframe. "
            f"This represents scanning behavior aimed at service discovery and mapping the system footprint."
        )
        recommendation = (
            "Expose fake port services and banners dynamically to expand the honeypot attack surface. "
            "Slow down connection handshakes to map the scanner's search parameters."
        )
    elif attack_type == "command_injection":
        summary = (
            f"A high-criticality attack was detected attempting command execution via system shells. "
            f"The request contains shell execution syntax aimed at getting system configurations."
        )
        recommendation = (
            "Escalate to shell trap environment. Serve a simulated restricted terminal shell to capture "
            "the commands executed by the attacker and retrieve their shell payloads."
        )
    elif attack_type == "path_traversal":
        summary = (
            f"Adversary is attempting directory traversal to read restricted server files (such as /etc/passwd). "
            f"This is indicative of information gathering before escalating attacks."
        )
        recommendation = (
            "Deploy filesystem decoy. Return fake file systems containing dummy user records and decoy tokens "
            "to study the attacker's search patterns."
        )
    elif attack_type == "ssrf":
        summary = (
            f"Server-Side Request Forgery (SSRF) attempt detected. The attacker tried to coerce the server to "
            f"fetch local resources or loopback addresses. The confidence is {confidence:.0%}."
        )
        recommendation = (
            "Restrict outgoing connections from the honeypot backend. Implement IP/domain blocklists and disable "
            "unused URL protocols like file:// and dict://."
        )
    elif attack_type == "ldap_injection":
        summary = (
            f"LDAP Injection attempt detected. The attacker is using LDAP filter syntax to bypass authentication or "
            f"query Active Directory objects. Risk score is {risk_score}/100."
        )
        recommendation = (
            "Expose fake directory structures to study search queries. Ensure production LDAP calls sanitize input filters."
        )
    elif attack_type == "deserialization":
        summary = (
            f"Insecure Deserialization payload detected (Java/Python object serialization markers). The attacker is "
            f"attempting remote code execution (RCE) via serialized payloads."
        )
        recommendation = (
            "Reject raw serialization formats at endpoint entry. Ensure all external input uses safe serialization (e.g., JSON)."
        )
    elif attack_type == "dns_tunneling":
        summary = (
            f"DNS Tunneling traffic detected. The attacker is attempting data exfiltration or Command and Control (C2) "
            f"channel establishment via DNS query payloads."
        )
        recommendation = (
            "Monitor TXT/CNAME query lengths. Blacklist domains matching data exfiltration characteristics."
        )
    elif attack_type == "credential_stuffing":
        summary = (
            f"Credential Stuffing attack detected. The attacker is scanning authentication portals using large lists "
            f"of leaked username-password pairs."
        )
        recommendation = (
            "Enable multi-factor authentication (MFA) on critical portals. Implement intelligent account lockout policies."
        )
    else:
        summary = (
            f"Anomalous traffic was detected from source {ip}. The behavior does not fully align with standard signatures, "
            f"resulting in an unclassified/unknown designation by ML models. Anomaly scores indicate possible custom tooling."
        )
        recommendation = (
            "Enable passive monitoring. Log all request parameters and payload structure to train new classifier "
            "signatures for custom attacker scripts."
        )

    return {
        "description": desc,
        "summary": summary,
        "recommendation": recommendation
    }
