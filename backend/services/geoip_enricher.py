import os
import hashlib
import time
import httpx
from typing import Dict, Any
from backend.config import settings

LOCATIONS = [
    {"country": "United States", "city": "Washington", "isp": "Amazon Technologies", "latitude": 38.9072, "longitude": -77.0369},
    {"country": "China", "city": "Beijing", "isp": "China Telecom", "latitude": 39.9042, "longitude": 116.4074},
    {"country": "Russia", "city": "Moscow", "isp": "Rostelecom", "latitude": 55.7558, "longitude": 37.6173},
    {"country": "Brazil", "city": "Sao Paulo", "isp": "Telesp", "latitude": -23.5505, "longitude": -46.6333},
    {"country": "Germany", "city": "Frankfurt", "isp": "Deutsche Telekom", "latitude": 50.1109, "longitude": 8.6821},
    {"country": "India", "city": "Mumbai", "isp": "Reliance Jio", "latitude": 19.0760, "longitude": 72.8777},
    {"country": "Ukraine", "city": "Kyiv", "isp": "Kyivstar", "latitude": 50.4501, "longitude": 30.5234},
    {"country": "Netherlands", "city": "Amsterdam", "isp": "DigitalOcean", "latitude": 52.3676, "longitude": 4.9041},
    {"country": "France", "city": "Paris", "isp": "OVH SAS", "latitude": 48.8566, "longitude": 2.3522},
    {"country": "United Kingdom", "city": "London", "isp": "Linode LLC", "latitude": 51.5074, "longitude": -0.1278}
]

_geoip_cache: Dict[str, tuple] = {}
_CACHE_TTL_SECONDS = 21600

def _is_private_or_local(ip_address: str) -> bool:
    if ip_address in ("127.0.0.1", "localhost", "::1"):
        return True
    return ip_address.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                   "172.2", "172.30.", "172.31.", "192.168."))

def _live_lookup(ip_address: str) -> Dict[str, Any]:
    resp = httpx.get(
        f"http://ip-api.com/json/{ip_address}",
        params={"fields": "status,country,city,isp,lat,lon"},
        timeout=2.5,
    )
    data = resp.json()
    if data.get("status") != "success":
        raise ValueError("ip-api lookup unsuccessful")
    return {
        "country": data.get("country") or "Unknown Country",
        "city": data.get("city") or "Unknown City",
        "isp": data.get("isp") or "Unknown ISP",
        "latitude": data.get("lat", 0.0),
        "longitude": data.get("lon", 0.0),
        "source": "live",
    }

def enrich_ip(ip_address: str) -> Dict[str, Any]:
    """
    Real, free GeoIP lookup via ip-api.com, cached per-IP for 6 hours.
    Falls back to a deterministic mock only if the live lookup fails.
    Always includes a "source" key: "live", "local", or "simulated".
    """
    if _is_private_or_local(ip_address):
        return {
            "country": "Localhost",
            "city": "Internal Network",
            "isp": "Local Loopback",
            "latitude": 0.0,
            "longitude": 0.0,
            "source": "local",
        }

    cached = _geoip_cache.get(ip_address)
    if cached and (time.time() - cached[1]) < _CACHE_TTL_SECONDS:
        return cached[0]

    try:
        result = _live_lookup(ip_address)
        _geoip_cache[ip_address] = (result, time.time())
        return result
    except Exception:
        pass

    ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
    loc = LOCATIONS[ip_hash % len(LOCATIONS)]
    result = {
        "country": loc["country"],
        "city": loc["city"],
        "isp": loc["isp"],
        "latitude": loc["latitude"],
        "longitude": loc["longitude"],
        "source": "simulated",
    }
    _geoip_cache[ip_address] = (result, time.time())
    return result
