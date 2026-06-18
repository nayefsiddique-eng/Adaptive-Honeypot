from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from backend.database import get_db
from backend.models.attack import AttackLog
from backend.core.decision_engine import decide_honeypot_action, get_deception_profile

router = APIRouter()

class DecisionRequest(BaseModel):
    attack_type: str
    confidence: float
    risk_score: float
    ip_address: str

@router.post("/evaluate")
def evaluate(req: DecisionRequest, db: Session = Depends(get_db)):
    history = db.query(AttackLog).filter(AttackLog.ip_address == req.ip_address).all()
    attacker_history = {
        "attack_count": len(history),
        "attack_types": list(set(h.attack_type for h in history)),
        "max_risk": max((h.risk_score for h in history), default=0)
    }
    decision = decide_honeypot_action(req.attack_type, req.confidence, req.risk_score, attacker_history)
    decision["attacker_history"] = attacker_history
    return decision

@router.get("/profile/{attack_type}")
def get_profile(attack_type: str):
    return get_deception_profile(attack_type)