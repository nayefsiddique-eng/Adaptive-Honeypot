from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from backend.database import get_db
from backend.core.digital_twin import DeceptionDigitalTwin, ATTACKER_PERSONAS

router = APIRouter(prefix="/api/digital-twin", tags=["Digital Twin Simulation"])

class SimulationRequest(BaseModel):
    persona: str

class TrainingRequest(BaseModel):
    episodes: int = 50

@router.get("/personas")
def list_personas():
    """
    Retrieve configured attacker personas and description profiles.
    """
    return ATTACKER_PERSONAS

@router.post("/simulate")
def run_simulation(req: SimulationRequest, db: Session = Depends(get_db)):
    """
    Triggers a live twin session simulating the selected adversary persona.
    """
    if req.persona not in ATTACKER_PERSONAS:
        raise HTTPException(status_code=400, detail="Invalid threat persona specified.")
        
    twin = DeceptionDigitalTwin(db)
    return twin.simulate_adversary_session(req.persona)

@router.post("/train-offline")
def run_offline_training(req: TrainingRequest, db: Session = Depends(get_db)):
    """
    Triggers batch simulations to train cooperative agent Q-policies entirely offline.
    """
    if req.episodes < 1 or req.episodes > 500:
        raise HTTPException(status_code=400, detail="Training episodes count must be between 1 and 500.")
        
    twin = DeceptionDigitalTwin(db)
    results = twin.run_offline_rl_training(req.episodes)
    return {
        "status": "success",
        "episodes_simulated": len(results),
        "average_dwell_time": round(sum(r["dwell_time_seconds"] for r in results) / len(results), 2) if results else 0.0,
        "average_deception_success_ratio": round(sum(r["deception_success_ratio"] for r in results) / len(results), 2) if results else 0.0
    }
