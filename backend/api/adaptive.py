from fastapi import APIRouter
from backend.core.adaptive_engine import decide_behavior

router = APIRouter(prefix="/api/adaptive", tags=["Adaptive"])

@router.get("/simulate")
def simulate():

    attack_type = "brute_force"
    confidence = 0.94

    result = decide_behavior(
        attack_type,
        confidence
    )

    return {
        "attack_type": attack_type,
        "confidence": confidence,
        "decision": result
    }
