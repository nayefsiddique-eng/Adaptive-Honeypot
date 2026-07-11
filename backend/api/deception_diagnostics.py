from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from backend.database import get_db
from backend.core.deception_diagnostics import DeceptionDiagnosticsEngine
from backend.core.policy_version import PolicyVersionManager
from backend.core.enterprise_policy import EnterprisePolicyEngine, ENTERPRISE_PROFILES

router = APIRouter(prefix="/api/diagnostics", tags=["Deception Diagnostics"])

class RollbackRequest(BaseModel):
    version: str

@router.get("/effectiveness/{session_id}")
def get_deception_effectiveness(session_id: str, db: Session = Depends(get_db)):
    engine = DeceptionDiagnosticsEngine(db)
    res = engine.calculate_deception_effectiveness(session_id)
    if "status" in res and res["status"] == "error":
        raise HTTPException(status_code=404, detail=res["message"])
    return res

@router.get("/return-on-deception/{session_id}")
def get_return_on_deception(session_id: str, db: Session = Depends(get_db)):
    engine = DeceptionDiagnosticsEngine(db)
    res = engine.calculate_return_on_deception(session_id)
    if "status" in res and res["status"] == "error":
        raise HTTPException(status_code=404, detail=res["message"])
    return res

@router.get("/policies")
def list_policy_versions():
    manager = PolicyVersionManager()
    return manager.list_versions()

@router.post("/policies/rollback")
def rollback_policy(req: RollbackRequest):
    manager = PolicyVersionManager()
    res = manager.rollback_to_version(req.version)
    if "status" in res and res["status"] == "error":
        raise HTTPException(status_code=400, detail=res["message"])
    return res

@router.get("/enterprise-profiles")
def list_enterprise_profiles():
    return ENTERPRISE_PROFILES

@router.get("/enterprise-profiles/{profile_key}")
def get_enterprise_profile(profile_key: str):
    if profile_key not in ENTERPRISE_PROFILES:
        raise HTTPException(status_code=404, detail="Enterprise profile key not found.")
    engine = EnterprisePolicyEngine(profile_key)
    return engine.get_policy_config()
