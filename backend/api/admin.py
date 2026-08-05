from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.attack import AttackLog
from backend.models.session import AttackerSession
from backend.models.reputation import AttackerReputation
from backend.models.policy import RLPolicy
from backend.config import settings

router = APIRouter(prefix="/api/admin", tags=["Admin Operations"])

def require_admin_key(x_admin_key: str = Header(default=None)):
    """Destructive admin operations require a shared-secret header.
    Without this, any page (or CORS-allowed origin) could wipe the database
    or force session closure with a single unauthenticated POST."""
    if not x_admin_key or x_admin_key != settings.ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-Admin-Key header.")
    return True

@router.post("/reset-demo")
def reset_demo(db: Session = Depends(get_db), _auth: bool = Depends(require_admin_key)):
    try:
        db.query(AttackLog).delete()
        db.query(AttackerSession).delete()
        db.query(AttackerReputation).delete()
        db.query(RLPolicy).delete()
        db.commit()
        return {"status": "success", "message": "Database tables cleared successfully."}
    except Exception as e:
        db.rollback()
        return {"status": "error", "message": f"Database transaction lock or connection issue: {str(e)}"}

@router.post("/close-sessions")
def close_sessions(db: Session = Depends(get_db), _auth: bool = Depends(require_admin_key)):
    """
    Manually close all sessions to trigger Q-learning updates immediately.
    """
    try:
        from backend.core.cooperative_rl_engine import update_q_table_for_session
        active_sessions = db.query(AttackerSession).filter(AttackerSession.is_active == True).all()
        closed_count = 0
        for session in active_sessions:
            session.is_active = False
            if session.rl_state and session.rl_action:
                update_q_table_for_session(
                    db=db,
                    session_id=session.session_id,
                    state_str=session.rl_state,
                    action_str=session.rl_action,
                    deception_score=session.rl_deception_score or 0.0
                )
            closed_count += 1
        db.commit()
        return {"status": "success", "closed_sessions_count": closed_count}
    except Exception as e:
        db.rollback()
        return {"status": "error", "message": f"Database transaction issue: {str(e)}"}

@router.post("/guided-demo")
def execute_guided_demo(db: Session = Depends(get_db), _auth: bool = Depends(require_admin_key)):
    """
    Triggers an automated, multi-stage attack scenario to demonstrate PRAETOR's capabilities.
    """
    from backend.core.demo_engine import GuidedDeceptionDemo
    demo = GuidedDeceptionDemo(db)
    return demo.execute_guided_scenario()
