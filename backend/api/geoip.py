from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models.attack import AttackLog
from backend.services.geoip_enricher import enrich_ip

router = APIRouter(prefix="/api/geoip", tags=["GeoIP"])

@router.get("/lookup")
def lookup_geoip(ip: str):
    """
    Look up GeoIP details for a specific IP.
    """
    return enrich_ip(ip)

@router.get("/attack-map")
def get_attack_map_data(db: Session = Depends(get_db)):
    """
    Get aggregated geolocation coordinates and attack counts for mapping.
    """
    # Group by country, city, latitude, and longitude
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
        # Ignore local or zero coords if they skew the visual map
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
    """
    Get top countries by attack volume.
    """
    results = db.query(
        AttackLog.country,
        func.count(AttackLog.id).label("count")
    ).group_by(
        AttackLog.country
    ).order_by(
        func.count(AttackLog.id).desc()
    ).limit(limit).all()

    return [{"country": r.country, "count": r.count} for r in results]
