from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.models.attack import AttackLog
from backend.models.session import AttackerSession
from backend.models.reputation import AttackerReputation
import backend.core.behavior_intelligence as behavior_intel

def fuse_attacker_intelligence(db: Session, ip_address: str, current_session_id: str) -> Dict[str, Any]:
    """
    Fuses GeoIP, external reputations, historical incident logs, and graph TTP metrics
    to construct a comprehensive profile of the adversary.
    """
    # 1. Fetch reputation history from database
    rep = db.query(AttackerReputation).filter(AttackerReputation.ip_address == ip_address).first()
    historical_count = rep.attack_count if rep else 0
    base_reputation_score = rep.reputation_score if rep else 50.0
    
    # 2. Fetch current session logs
    session_logs = db.query(AttackLog).filter(AttackLog.session_id == current_session_id).all()
    current_sequence = behavior_intel.build_attack_sequence(session_logs)
    
    # 3. GeoIP Lookup (using fallback metadata)
    country = "Unknown"
    if rep and rep.country:
        country = rep.country
        
    # 4. Check for campaign similarity
    similar_session_id, similarity_score = behavior_intel.analyze_campaign_similarity(
        db, current_session_id, current_sequence
    )
    
    # 5. Classify the threat actor profile
    ttp_set = set(current_sequence)
    unique_ttp_count = len(ttp_set)
    
    if unique_ttp_count >= 4 or "T1203" in ttp_set:
        actor_profile = "Advanced Persistent Threat (APT) / Targeted Intruder"
        adaptive_confidence = 0.92
    elif "T1110" in ttp_set and len(session_logs) > 15:
        actor_profile = "High-Volume Brute-Force Botnet"
        adaptive_confidence = 0.85
    elif unique_ttp_count == 1 and len(session_logs) < 5:
        actor_profile = "Opportunistic Vulnerability Scanner"
        adaptive_confidence = 0.70
    else:
        actor_profile = "General Script Kiddie / Exploratory Threat"
        adaptive_confidence = 0.60

    # 6. Calculate a unified threat severity score (0-100)
    # Merges frequency, payload risk, and external rating
    severity_modifier = 20 if actor_profile.startswith("Advanced") else 10 if "Brute-Force" in actor_profile else 0
    unified_severity_score = min(100.0, (100.0 - base_reputation_score) * 0.7 + (len(session_logs) * 2.0) + severity_modifier)

    return {
        "ip_address": ip_address,
        "country": country,
        "historical_incident_count": historical_count,
        "threat_actor_profile": actor_profile,
        "campaign_cluster": f"CAMPAIGN-{country.upper()}-{unique_ttp_count}TTP" if country != "Unknown" else "GLOBAL-EXPLORATIVE",
        "campaign_similarity": {
            "matched_session_id": similar_session_id,
            "cosine_similarity": similarity_score
        },
        "unified_severity_score": round(unified_severity_score, 2),
        "adaptive_threat_confidence": adaptive_confidence
    }
