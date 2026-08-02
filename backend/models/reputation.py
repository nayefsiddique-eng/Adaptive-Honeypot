from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.sql import func
from backend.database import Base

class AttackerReputation(Base):
    __tablename__ = "attacker_reputation"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    total_sessions = Column(Integer, default=0)
    attack_count = Column(Integer, default=0)
    average_risk = Column(Float, default=0.0)
    previous_attack_types = Column(JSON, default=[])
    reputation_score = Column(Float, default=100.0)
    abuse_ip_db_score = Column(Float, default=0.0)
    alien_vault_score = Column(Float, default=0.0)
    country = Column(String, default="Unknown")
    city = Column(String, default="Unknown")
    isp = Column(String, default="Unknown")
    latitude = Column(Float, default=0.0)
    longitude = Column(Float, default=0.0)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
