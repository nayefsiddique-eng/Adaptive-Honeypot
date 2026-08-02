from fastapi import APIRouter
from backend.core.adaptive_engine import decide_behavior

router = APIRouter(prefix="/api/adaptive", tags=["Adaptive"])

@router.get("/simulate")
def simulate(attack_type: str = "brute_force", confidence: float = 0.94, risk_score: float = 75.0):
    attacker_history = {
        "total_sessions": 1,
        "attack_count": 1,
        "previous_attack_types": [attack_type],
        "ip_address": "simulated_test_ip"
    }

    result = decide_behavior(
        attack_type=attack_type,
        confidence=confidence,
        risk_score=risk_score,
        attacker_history=attacker_history
    )

    return {
        "attack_type": attack_type,
        "confidence": confidence,
        "risk_score": risk_score,
        "decision": result
    }
