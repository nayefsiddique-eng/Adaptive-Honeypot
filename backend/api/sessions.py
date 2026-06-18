from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.session import AttackerSession
from backend.models.attack import AttackLog
from backend.services.llm_summarizer import generate_attack_summary
from backend.services.cluster_engine import cluster_attacker_ips

router = APIRouter(prefix="/api/sessions", tags=["Session Recording"])

@router.get("")
def list_sessions(limit: int = 50, db: Session = Depends(get_db)):
    """
    List all recorded attacker sessions.
    """
    sessions = db.query(AttackerSession).order_by(AttackerSession.last_seen.desc()).limit(limit).all()
    return sessions

@router.get("/clusters")
def get_attacker_clusters(db: Session = Depends(get_db)):
    """
    K-Means attacker clustering endpoint.
    """
    return cluster_attacker_ips(db)

@router.get("/{session_id}")
def get_session(session_id: str, db: Session = Depends(get_db)):
    """
    Get detailed metrics of a specific session.
    """
    session = db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session

@router.get("/{session_id}/recording")
def get_session_recording(session_id: str, db: Session = Depends(get_db)):
    """
    Returns the full interactive timeline of events, commands, payload hashes,
    and interaction details for a given session.
    """
    session = db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events = db.query(AttackLog).filter(AttackLog.session_id == session_id).order_by(AttackLog.timestamp.asc()).all()

    return {
        "session_id": session_id,
        "ip_address": session.ip_address,
        "first_seen": session.first_seen,
        "last_seen": session.last_seen,
        "is_active": session.is_active,
        "duration_seconds": session.session_duration,
        "attack_count": session.attack_count,
        "attack_types": session.attack_types,
        "overall_risk": session.risk_score,
        "honeypot_state": session.honeypot_state,
        "fake_services": session.fake_services,
        "interaction_depth": session.interaction_depth,
        "commands_issued": session.commands_issued,
        "payload_hashes": session.payload_hashes,
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "port": e.port,
                "protocol": e.protocol,
                "attack_type": e.attack_type,
                "confidence": e.confidence,
                "risk_score": e.risk_score,
                "mitre_technique": e.mitre_technique,
                "response_time_ms": e.response_time_ms,
                "payload_snippet": e.raw_payload[:200] if e.raw_payload else ""
            }
            for e in events
        ]
    }

@router.get("/{session_id}/summary")
async def get_session_llm_summary(session_id: str, db: Session = Depends(get_db)):
    """
    Generates an LLM threat summary for the entire session.
    """
    session = db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events = db.query(AttackLog).filter(AttackLog.session_id == session_id).all()
    
    # Collate raw payloads
    combined_payloads = "\n".join(
        [e.raw_payload[:150] for e in events if e.raw_payload][:5]
    )

    history = {
        "attack_count": session.attack_count,
        "total_sessions": 1,
        "previous_attack_types": session.attack_types
    }

    # Generate summary based on first/most prominent attack type
    primary_attack = session.attack_types[0] if session.attack_types else "unknown"
    avg_confidence = (
        sum(e.confidence for e in events) / len(events) if events else 0.0
    )

    summary = await generate_attack_summary(
        attack_type=primary_attack,
        confidence=avg_confidence,
        risk_score=session.risk_score,
        payload=combined_payloads,
        ip=session.ip_address,
        history=history
    )

    return summary
