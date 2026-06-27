from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean
from sqlalchemy.sql import func
from backend.database import Base

class AttackerSession(Base):
    __tablename__ = "attacker_sessions"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    session_id = Column(String, unique=True)
    attack_count = Column(Integer, default=0)
    attack_types = Column(JSON, default=[])
    risk_score = Column(Float, default=0.0)
    honeypot_state = Column(String, default="default")
    fake_services = Column(JSON, default=[])
    is_active = Column(Boolean, default=True)
    session_duration = Column(Float, default=0.0)
    commands_issued = Column(JSON, default=[])
    payload_hashes = Column(JSON, default=[])
    interaction_depth = Column(Integer, default=0)
    deception_score_avg = Column(Float, default=0.0)
    attack_chain_name = Column(String, nullable=True)
    attack_chain_progress = Column(Integer, default=0)
    llm_summary = Column(JSON, nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now())