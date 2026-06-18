import os
import hashlib
import requests
from typing import Dict, Any

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

def get_abuseipdb_score(ip_address: str) -> float:
    """
    Check AbuseIPDB database for the IP reputation.
    Returns score from 0.0 to 100.0.
    """
    if not ABUSEIPDB_API_KEY or ip_address in ("127.0.0.1", "localhost", "::1"):
        # Deterministic simulation
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
        # 10% chance of high reputation score, 90% chance of lower scores
        if ip_hash % 10 == 0:
            return round(70.0 + (ip_hash % 30), 2)
        return round((ip_hash % 40) + 10.0, 2)

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90"
        }
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return float(data.get("data", {}).get("abuseConfidenceScore", 0.0))
    except Exception:
        pass
    return 0.0

def get_alienvault_score(ip_address: str) -> float:
    """
    Check AlienVault OTX for IP threat history.
    Returns threat score 0.0 to 100.0 based on pulse count.
    """
    if not OTX_API_KEY or ip_address in ("127.0.0.1", "localhost", "::1"):
        # Deterministic simulation
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
        if ip_hash % 8 == 0:
            return round(50.0 + (ip_hash % 45), 2)
        return round(float(ip_hash % 25), 2)

    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
        headers = {
            "X-OTX-API-KEY": OTX_API_KEY
        }
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            # Map pulse count to score (max 100.0)
            score = min(len(pulses) * 10.0, 100.0)
            return score
    except Exception:
        pass
    return 0.0

def evaluate_ip_threat(ip_address: str) -> Dict[str, Any]:
    """
    Combines intelligence sources to compute a threat intelligence summary.
    """
    abuse_score = get_abuseipdb_score(ip_address)
    otx_score = get_alienvault_score(ip_address)
    
    # Combined reputation score: higher is worse (more dangerous)
    # 0 = safe/unknown, 100 = confirmed malicious
    reputation_score = round((abuse_score * 0.6) + (otx_score * 0.4), 2)
    
    return {
        "ip_address": ip_address,
        "abuseipdb_score": abuse_score,
        "alienvault_score": otx_score,
        "reputation_score": reputation_score,
        "classification": "high_risk" if reputation_score >= 70 else "medium_risk" if reputation_score >= 30 else "low_risk"
    }
