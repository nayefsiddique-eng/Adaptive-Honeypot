import os
import hashlib
from typing import Dict, Any
from backend.config import settings

# List of realistic attack source profiles for the fallback engine
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

def enrich_ip(ip_address: str) -> Dict[str, Any]:
    """
    Enriches an IP address with GeoIP details (Country, City, ISP, Latitude, Longitude).
    Attempts to use MaxMind database; falls back to deterministic mock mapping.
    """
    # 127.0.0.1 or localhost check
    if ip_address in ("127.0.0.1", "localhost", "::1"):
        return {
            "country": "Localhost",
            "city": "Internal Network",
            "isp": "Local Loopback",
            "latitude": 0.0,
            "longitude": 0.0
        }

    # Attempt to use real MaxMind database if it exists
    if os.path.exists(settings.GEOIP_DB_PATH):
        try:
            import geoip2.database
            with geoip2.database.Reader(settings.GEOIP_DB_PATH) as reader:
                response = reader.city(ip_address)
                # Try to get ISP from another DB or fallback
                isp = "Unknown ISP"
                try:
                    # If we had MaxMind ASN database, we'd check here.
                    # We can use a simple lookup if possible.
                    pass
                except Exception:
                    pass
                return {
                    "country": response.country.name or "Unknown Country",
                    "city": response.city.name or "Unknown City",
                    "isp": isp,
                    "latitude": response.location.latitude or 0.0,
                    "longitude": response.location.longitude or 0.0
                }
        except Exception as e:
            # Fallback on errors reading the database
            pass

    # Deterministic fallback based on IP hashing
    ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
    loc = LOCATIONS[ip_hash % len(LOCATIONS)]
    return {
        "country": loc["country"],
        "city": loc["city"],
        "isp": loc["isp"],
        "latitude": loc["latitude"],
        "longitude": loc["longitude"]
    }
