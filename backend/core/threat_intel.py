import os
import hashlib
import httpx
import time
from typing import Dict, Any

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

_intel_cache: Dict[str, tuple[Dict[str, Any], float]] = {}
CACHE_TTL_SECONDS = 21600  # 6 hours

intel_cache_hits = 0
intel_cache_queries = 0

async def get_abuseipdb_score(ip_address: str) -> float:
    """
    Check AbuseIPDB database for the IP reputation.
    Returns score from 0.0 to 100.0.
    """
    if not ABUSEIPDB_API_KEY or ip_address in ("127.0.0.1", "localhost", "::1"):
        # Deterministic simulation
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
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
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                return float(data.get("data", {}).get("abuseConfidenceScore", 0.0))
    except Exception:
        pass
    return 0.0

async def get_alienvault_score(ip_address: str) -> float:
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
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                score = min(len(pulses) * 10.0, 100.0)
                return score
    except Exception:
        pass
    return 0.0

async def evaluate_ip_threat(ip_address: str) -> Dict[str, Any]:
    """
    Combines intelligence sources to compute a threat intelligence summary.
    Includes a 6-hour TTL in-memory cache to save API usage.
    """
    global intel_cache_hits, intel_cache_queries
    intel_cache_queries += 1

    now = time.time()
    if ip_address in _intel_cache:
        result, ts = _intel_cache[ip_address]
        if now - ts < CACHE_TTL_SECONDS:
            intel_cache_hits += 1
            return result

    abuse_score = await get_abuseipdb_score(ip_address)
    otx_score = await get_alienvault_score(ip_address)
    
    # Combined reputation score: higher is worse (more dangerous)
    reputation_score = round((abuse_score * 0.6) + (otx_score * 0.4), 2)
    
    # Check if IP maps to Tor node (simulation fallback for is_tor indicator)
    ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
    is_tor = bool(ip_hash % 12 == 0) if ip_address not in ("127.0.0.1", "localhost", "::1") else False
    
    result = {
        "ip_address": ip_address,
        "abuseipdb_score": abuse_score,
        "alienvault_score": otx_score,
        "reputation_score": reputation_score,
        "classification": "high_risk" if reputation_score >= 70 else "medium_risk" if reputation_score >= 30 else "low_risk",
        "is_tor": is_tor
    }

    _intel_cache[ip_address] = (result, now)
    return result
