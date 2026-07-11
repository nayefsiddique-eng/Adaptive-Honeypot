from typing import Dict, Any

ENTERPRISE_PROFILES = {
    "enterprise_default": {
        "deception_aggressiveness": 0.5,
        "risk_tolerance_threshold": 50.0,
        "max_engagement_dwell_time_seconds": 300,
        "enrichment_verbosity": "standard"
    },
    "finance": {
        "deception_aggressiveness": 0.3, # Low risk profile
        "risk_tolerance_threshold": 30.0,
        "max_engagement_dwell_time_seconds": 120,
        "enrichment_verbosity": "high"
    },
    "healthcare": {
        "deception_aggressiveness": 0.2, # Highly sensitive profile
        "risk_tolerance_threshold": 25.0,
        "max_engagement_dwell_time_seconds": 90,
        "enrichment_verbosity": "maximum"
    },
    "cloud": {
        "deception_aggressiveness": 0.8, # Aggressive profiling
        "risk_tolerance_threshold": 70.0,
        "max_engagement_dwell_time_seconds": 600,
        "enrichment_verbosity": "standard"
    },
    "research": {
        "deception_aggressiveness": 0.9, # Deep containment profiling
        "risk_tolerance_threshold": 80.0,
        "max_engagement_dwell_time_seconds": 1200,
        "enrichment_verbosity": "debug"
    }
}

class EnterprisePolicyEngine:
    """
    Manages configurable policy profiles (Finance, Healthcare, Cloud, Research),
    adjusting aggressiveness levels and risk tolerances dynamically.
    """
    def __init__(self, profile_key: str = "enterprise_default"):
        self.profile = ENTERPRISE_PROFILES.get(profile_key, ENTERPRISE_PROFILES["enterprise_default"])

    def get_policy_config(self) -> Dict[str, Any]:
        return self.profile
