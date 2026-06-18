from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models.attack import AttackLog
from backend.services.mitre_mapper import map_to_mitre

router = APIRouter(prefix="/api/attacks", tags=["Attacks Telemetry"])

@router.get("/summary")
def get_attacks_summary(db: Session = Depends(get_db)):
    """
    Returns counts of attacks grouped by type and mapping of MITRE techniques.
    """
    # 1. Group by Attack Type
    type_results = db.query(
        AttackLog.attack_type,
        func.count(AttackLog.id)
    ).group_by(AttackLog.attack_type).all()
    attack_types = {r[0]: r[1] for r in type_results}

    # 2. Group by MITRE technique
    mitre_results = db.query(
        AttackLog.mitre_technique,
        func.count(AttackLog.id)
    ).group_by(AttackLog.mitre_technique).all()
    
    mitre_techniques = {}
    for r in mitre_results:
        tech_id = r[0]
        count = r[1]
        
        # Look up tech name or fallback
        # Find which attack type maps to this technique to get its name
        tech_details = {"technique_name": "Unclassified", "tactic": "Unknown"}
        for attack_type in attack_types:
            mapped = map_to_mitre(attack_type)
            if mapped["technique_id"] == tech_id:
                tech_details = mapped
                break
                
        mitre_techniques[tech_id] = {
            "technique_name": tech_details.get("technique_name", "Unclassified"),
            "tactic": tech_details.get("tactic", "Unknown"),
            "count": count
        }

    return {
        "attack_types": attack_types,
        "mitre_techniques": mitre_techniques
    }

@router.get("/top-ips")
def get_top_ips(db: Session = Depends(get_db)):
    """
    Returns top 10 IP addresses by attack volume and their max risk score.
    """
    results = db.query(
        AttackLog.ip_address,
        func.count(AttackLog.id).label("attack_count"),
        func.max(AttackLog.risk_score).label("max_risk")
    ).group_by(
        AttackLog.ip_address
    ).order_by(
        func.count(AttackLog.id).desc()
    ).limit(10).all()

    top_ips = []
    for r in results:
        top_ips.append({
            "ip_address": r[0],
            "attack_count": r[1],
            "max_risk": round(float(r[2]), 2)
        })
    return top_ips
