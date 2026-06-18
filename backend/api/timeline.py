from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from backend.database import get_db
from backend.models.attack import AttackLog

router = APIRouter(prefix="/api/timeline", tags=["Timeline Analytics"])

@router.get("")
def get_attack_timeline(db: Session = Depends(get_db)):
    """
    Get attacks per hour (last 24 hours) and attacks per day (last 30 days) with risk trends.
    """
    now = datetime.utcnow()

    # 1. Hourly aggregation (last 24 hours)
    twenty_four_hours_ago = now - timedelta(hours=24)
    # Using SQLite's strftime to group by hour
    hourly_results = db.query(
        func.strftime("%Y-%m-%d %H:00:00", AttackLog.timestamp).label("hour"),
        func.count(AttackLog.id).label("count"),
        func.avg(AttackLog.risk_score).label("avg_risk")
    ).filter(
        AttackLog.timestamp >= twenty_four_hours_ago
    ).group_by(
        "hour"
    ).order_by(
        "hour"
    ).all()

    hourly_data = []
    # Fill in potential zero-count hours to ensure continuous chart rendering
    for i in range(24):
        h_time = (now - timedelta(hours=23-i)).replace(minute=0, second=0, microsecond=0)
        h_str = h_time.strftime("%Y-%m-%d %H:00:00")
        
        # Search in results
        match = next((r for r in hourly_results if r.hour == h_str), None)
        if match:
            hourly_data.append({
                "time": h_time.strftime("%H:00"),
                "count": match.count,
                "avg_risk": round(match.avg_risk, 1)
            })
        else:
            hourly_data.append({
                "time": h_time.strftime("%H:00"),
                "count": 0,
                "avg_risk": 0.0
            })

    # 2. Daily aggregation (last 30 days)
    thirty_days_ago = now - timedelta(days=30)
    daily_results = db.query(
        func.strftime("%Y-%m-%d", AttackLog.timestamp).label("day"),
        func.count(AttackLog.id).label("count"),
        func.avg(AttackLog.risk_score).label("avg_risk")
    ).filter(
        AttackLog.timestamp >= thirty_days_ago
    ).group_by(
        "day"
    ).order_by(
        "day"
    ).all()

    daily_data = []
    for i in range(30):
        d_time = now - timedelta(days=29-i)
        d_str = d_time.strftime("%Y-%m-%d")
        
        match = next((r for r in daily_results if r.day == d_str), None)
        if match:
            daily_data.append({
                "date": d_str,
                "count": match.count,
                "avg_risk": round(match.avg_risk, 1)
            })
        else:
            daily_data.append({
                "date": d_str,
                "count": 0,
                "avg_risk": 0.0
            })

    # 3. Calculate Trend Summary (e.g. percentage increase/decrease compared to previous period)
    yesterday = now - timedelta(days=1)
    day_before_yesterday = now - timedelta(days=2)
    
    attacks_last_24h = db.query(AttackLog).filter(AttackLog.timestamp >= yesterday).count()
    attacks_prev_24h = db.query(AttackLog).filter(
        AttackLog.timestamp >= day_before_yesterday,
        AttackLog.timestamp < yesterday
    ).count()

    trend_pct = 0.0
    if attacks_prev_24h > 0:
        trend_pct = round(((attacks_last_24h - attacks_prev_24h) / attacks_prev_24h) * 100.0, 2)
    elif attacks_last_24h > 0:
        trend_pct = 100.0  # Infinite growth starting from 0

    return {
        "hourly": hourly_data,
        "daily": daily_data,
        "metrics": {
            "attacks_last_24h": attacks_last_24h,
            "attacks_prev_24h": attacks_prev_24h,
            "trend_percentage": trend_pct
        }
    }
