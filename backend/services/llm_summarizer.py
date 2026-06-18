import os
import httpx
from typing import Dict, Any

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

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
    Calls Gemini API if available, else falls back to a highly realistic local templates engine.
    """
    prompt = (
        f"Analyze this security incident:\n"
        f"- Attacker IP: {ip}\n"
        f"- Incident Type: {attack_type}\n"
        f"- Classifier Confidence: {confidence:.2%}\n"
        f"- Risk Severity: {risk_score}/100\n"
        f"- History: {history.get('attack_count', 0)} total attacks from this source\n"
        f"- Payload snippet: {payload[:300]}\n"
        f"Generate a professional JSON response with three keys:\n"
        f"1. 'description': Brief explanation of what was detected.\n"
        f"2. 'summary': Deep analysis of the attacker intent, sophistication, and patterns.\n"
        f"3. 'recommendation': Specific tactical steps to mitigate or handle this interaction."
    )

    if GEMINI_API_KEY:
        try:
            # Call Google Gemini API (using standard Gemini API format)
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
            headers = {"Content-Type": "application/json"}
            req_body = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "responseMimeType": "application/json"
                }
            }
            async with httpx.AsyncClient() as client:
                res = await client.post(url, headers=headers, json=req_body, timeout=8.0)
                if res.status_code == 200:
                    res_data = res.json()
                    import json
                    text_content = res_data["candidates"][0]["content"]["parts"][0]["text"]
                    # Parse output as json
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
