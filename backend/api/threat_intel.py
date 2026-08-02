from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.reputation import AttackerReputation
from backend.core.threat_intel import evaluate_ip_threat

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])

@router.get("/top-threats")
def get_top_threats(limit: int = 10, db: Session = Depends(get_db)):
    """
    List worst attackers by lowest reputation score.
    """
    threats = db.query(AttackerReputation).order_by(AttackerReputation.reputation_score.asc()).limit(limit).all()
    return threats

@router.get("/{ip_address}")
async def get_ip_reputation(ip_address: str, db: Session = Depends(get_db)):
    """
    Look up local threat intelligence and external source data for an IP address.
    """
    # 1. Fetch from database first to see if profile exists
    reputation = db.query(AttackerReputation).filter(AttackerReputation.ip_address == ip_address).first()
    
    # 2. Query external/mock indicators (async await)
    intel = await evaluate_ip_threat(ip_address)
    
    # 3. Combine details
    local_details = {}
    if reputation:
        local_details = {
            "total_sessions": reputation.total_sessions,
            "attack_count": reputation.attack_count,
            "average_risk": reputation.average_risk,
            "previous_attack_types": reputation.previous_attack_types,
            "local_reputation_score": reputation.reputation_score,
            "country": reputation.country,
            "city": reputation.city,
            "isp": reputation.isp,
            "last_seen": reputation.last_seen
        }
    else:
        local_details = {
            "total_sessions": 0,
            "attack_count": 0,
            "average_risk": 0.0,
            "previous_attack_types": [],
            "local_reputation_score": 100.0,
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "last_seen": None
        }

    return {
        "ip_address": ip_address,
        "external_intel": intel,
        "local_history": local_details,
        "overall_score": reputation.reputation_score if reputation else (100.0 - intel["reputation_score"])
    }
