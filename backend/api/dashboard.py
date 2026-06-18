from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models.attack import AttackLog

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard Telemetry"])

@router.get("")
def get_dashboard_data(db: Session = Depends(get_db)):
    """
    Returns aggregated metrics for the honeypot cockpit dashboard widgets.
    """
    total_attacks = db.query(AttackLog).count()
    
    unique_ips_count = db.query(func.count(func.distinct(AttackLog.ip_address))).scalar() or 0
    
    avg_risk = db.query(func.avg(AttackLog.risk_score)).scalar() or 0.0
    avg_risk = round(float(avg_risk), 2)
    
    # Attack Type Breakdown
    breakdown_results = db.query(
        AttackLog.attack_type,
        func.count(AttackLog.id)
    ).group_by(AttackLog.attack_type).all()
    breakdown = {r[0]: r[1] for r in breakdown_results}

    # Top 5 IPs by Risk Score
    top_5_results = db.query(
        AttackLog.ip_address,
        func.max(AttackLog.risk_score).label("max_risk")
    ).group_by(AttackLog.ip_address).order_by(func.max(AttackLog.risk_score).desc()).limit(5).all()
    
    top_5_ips = [{"ip_address": r[0], "risk_score": r[1]} for r in top_5_results]

    # Classification Counts by Severity
    critical_count = db.query(AttackLog).filter(AttackLog.risk_score >= 80.0).count()
    high_count = db.query(AttackLog).filter(AttackLog.risk_score >= 60.0, AttackLog.risk_score < 80.0).count()
    medium_count = db.query(AttackLog).filter(AttackLog.risk_score >= 40.0, AttackLog.risk_score < 60.0).count()
    low_count = db.query(AttackLog).filter(AttackLog.risk_score < 40.0).count()

    return {
        "total_attacks": total_attacks,
        "unique_ips": unique_ips_count,
        "attack_type_breakdown": breakdown,
        "top_5_ips_by_risk": top_5_ips,
        "avg_risk_score": avg_risk,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count
    }
