from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.sql import func
from backend.database import Base

class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True, nullable=True)
    ip_address = Column(String, index=True)
    port = Column(Integer)
    protocol = Column(String)
    attack_type = Column(String)
    confidence = Column(Float)
    risk_score = Column(Float)
    mitre_technique = Column(String)
    country = Column(String)
    city = Column(String)
    isp = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    raw_payload = Column(String)
    features = Column(JSON)
    response_time_ms = Column(Float, default=0.0)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())