from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models.attack import AttackLog
from backend.services.geoip_enricher import enrich_ip

from backend.api.auth import require_management_key

router = APIRouter(
    prefix="/api/geoip",
    tags=["GeoIP"],
    dependencies=[Depends(require_management_key)]
)

@router.get("/status")
def geoip_status():
    try:
        result = enrich_ip("8.8.8.8")
        return {"mode": result.get("source", "simulated")}
    except Exception:
        return {"mode": "simulated"}

@router.get("/lookup")
def lookup_geoip(ip: str):
    return enrich_ip(ip)

@router.get("/attack-map")
def get_attack_map_data(db: Session = Depends(get_db)):
    results = db.query(
        AttackLog.country,
        AttackLog.city,
        AttackLog.latitude,
        AttackLog.longitude,
        func.count(AttackLog.id).label("count")
    ).filter(
        AttackLog.latitude.isnot(None),
        AttackLog.longitude.isnot(None)
    ).group_by(
        AttackLog.country,
        AttackLog.city,
        AttackLog.latitude,
        AttackLog.longitude
    ).all()

    map_data = []
    for r in results:
        if r.latitude == 0.0 and r.longitude == 0.0:
            continue
        map_data.append({
            "country": r.country,
            "city": r.city,
            "latitude": r.latitude,
            "longitude": r.longitude,
            "count": r.count
        })
    return map_data

@router.get("/countries")
def get_top_countries(limit: int = 5, db: Session = Depends(get_db)):
    results = db.query(
        AttackLog.country,
        func.count(AttackLog.id).label("count")
    ).group_by(
        AttackLog.country
    ).order_by(
        func.count(AttackLog.id).desc()
    ).limit(limit).all()

    return [{"country": r.country, "count": r.count} for r in results]
