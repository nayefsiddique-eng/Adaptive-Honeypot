from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from backend.database import get_db
from backend.models.attack import AttackLog
from backend.models.session import AttackerSession
from backend.models.reputation import AttackerReputation
from backend.core.decision_engine import decide_honeypot_action, get_deception_profile, DECEPTION_PROFILES
from backend.core.cooperative_rl_engine import choose_rl_action, serialize_state, get_history_bucket

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

@router.post("/evaluate_rl")
def evaluate_rl(req: DecisionRequest, db: Session = Depends(get_db)):
    # 1. Fetch attacker reputation to get total sessions count
    reputation = db.query(AttackerReputation).filter(AttackerReputation.ip_address == req.ip_address).first()
    total_sessions = reputation.total_sessions if reputation else 1
    
    # 2. Get active session for this IP to find current interaction level
    session = db.query(AttackerSession).filter(
        AttackerSession.ip_address == req.ip_address,
        AttackerSession.is_active == True
    ).order_by(AttackerSession.last_seen.desc()).first()
    
    current_level = "low"
    if session:
        depth_map = {0: "low", 1: "low", 2: "medium", 3: "high", 4: "high"}
        current_level = depth_map.get(session.interaction_depth or 0, "low")
        
    # 3. Call Q-learning engine to select action
    action_str, policy_confidence, explored, _ = choose_rl_action(db, req.attack_type, total_sessions, current_level)
    
    parts = action_str.split(":")
    profile_key = parts[0]
    level = parts[1] if len(parts) > 1 else "low"
    
    # 4. Get corresponding deception profile
    profile = get_deception_profile(profile_key)
    
    # 5. Map the chosen level to priority and action name for backward compatibility
    action_map = {"low": "monitor", "medium": "active_deception", "high": "full_deception"}
    priority_map = {"low": "low", "medium": "high", "high": "critical"}
    
    action = action_map.get(level, "monitor")
    priority = priority_map.get(level, "low")
    
    # 6. Calculate deception score for this setup
    interaction_level_map = {"low": 0, "medium": 1, "high": 2}
    deception_score = (
        (interaction_level_map.get(level, 0) / 2.0) * 0.40 +
        (len(profile["fake_services"]) / 5.0) * 0.20 +
        (len(profile["decoy_files"]) / 6.0) * 0.20 +
        (min(profile["response_delay_ms"], 2000) / 2000.0) * 0.20
    )
    deception_score = min(round(deception_score, 4), 1.0)
    
    # 7. Log (state, action) pairing on the active session for later reward attribution
    state_str = serialize_state(req.attack_type, get_history_bucket(total_sessions), current_level)
    if session:
        try:
            session.rl_state = state_str
            session.rl_action = action_str
            session.rl_deception_score = deception_score
            db.commit()
        except Exception as e:
            db.rollback()
            
    # For attacker history response formatting
    history = db.query(AttackLog).filter(AttackLog.ip_address == req.ip_address).all()
    attacker_history = {
        "attack_count": len(history),
        "attack_types": list(set(h.attack_type for h in history)),
        "max_risk": max((h.risk_score for h in history), default=0)
    }
    
    return {
        "action": action,
        "priority": priority,
        "honeypot_state": profile["state"],
        "fake_services": profile["fake_services"],
        "fake_banners": profile["fake_banners"],
        "response_delay_ms": profile["response_delay_ms"],
        "fake_credentials_accepted": profile["fake_credentials_accepted"],
        "decoy_files": profile["decoy_files"],
        "description": profile["description"],
        "reasoning": f"RL selected action '{action_str}' based on state '{state_str}' (confidence: {policy_confidence:.1%}, explored: {explored})",
        "attacker_history": attacker_history,
        "policy_confidence": policy_confidence,
        "explored": explored
    }

@router.get("/profile/{attack_type}")
def get_profile(attack_type: str):
    return get_deception_profile(attack_type)