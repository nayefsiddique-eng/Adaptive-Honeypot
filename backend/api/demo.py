from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import logging
from backend.database import get_db
from backend.core.demo_engine import run_closed_loop_simulation
from backend.models.attack import AttackLog
from backend.models.session import AttackerSession
from backend.models.reputation import AttackerReputation
from backend.models.policy import RLPolicy

logger = logging.getLogger("demo_api")
router = APIRouter(prefix="/api/demo", tags=["Demo Controller"])

@router.post("/start")
async def start_demo(db: Session = Depends(get_db)):
    logger.info("[DEMO] POST /api/demo/start endpoint invoked.")
    try:
        events = await run_closed_loop_simulation(db, session_count=10, step_delay=0.01)
        logger.info("[DEMO] POST /api/demo/start execution finished successfully.")
        return {
            "status": "success",
            "message": "Demo started successfully.",
            "events_generated": events
        }
    except Exception as e:
        logger.error(f"[DEMO] Failure during execution of demo start: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal demo failure: {str(e)}")

@router.post("/reset")
def reset_demo_endpoint(db: Session = Depends(get_db)):
    logger.info("[DEMO] POST /api/demo/reset endpoint invoked.")
    try:
        db.query(AttackLog).delete()
        db.query(AttackerSession).delete()
        db.query(AttackerReputation).delete()
        db.query(RLPolicy).delete()
        db.commit()
        logger.info("[DEMO] Reset complete. Databases cleared.")
        return {"status": "success", "message": "Demo reset complete."}
    except Exception as e:
        db.rollback()
        logger.error(f"[DEMO] Failure during execution of demo reset: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal reset failure: {str(e)}")
