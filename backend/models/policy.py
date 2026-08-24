from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from backend.database import Base

class RLPolicy(Base):
    __tablename__ = "rl_policies"

    id = Column(Integer, primary_key=True, index=True)
    state = Column(String, index=True, nullable=False)
    action = Column(String, index=True, nullable=False)
    q_value = Column(Float, default=0.0)
    last_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class DeceptionTransition(Base):
    __tablename__ = "deception_transitions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True, nullable=False)
    trigger_event = Column(String, nullable=False)
    prev_profile = Column(String, nullable=True)
    action_taken = Column(String, nullable=False)
    next_profile = Column(String, nullable=True)
    risk_before = Column(Float, default=0.0)
    risk_after = Column(Float, default=0.0)
    reward = Column(Float, default=0.0)
    interaction_depth = Column(Integer, default=1)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
