import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.session import AttackerSession
from backend.models.attack import AttackLog
import backend.services.llm_summarizer as summarizer
from backend.services.cluster_engine import cluster_attacker_ips

router = APIRouter(prefix="/api/sessions", tags=["Session Recording"])

@router.get("")
def list_sessions(limit: int = 50, db: Session = Depends(get_db)):
    """
    List all recorded attacker sessions, enriched with TTP fingerprinting.
    """
    sessions = db.query(AttackerSession).order_by(AttackerSession.last_seen.desc()).limit(limit).all()
    res = []
    for s in sessions:
        # Get latest attack log to extract ttp_fingerprint
        latest_log = db.query(AttackLog).filter(AttackLog.session_id == s.session_id).order_by(AttackLog.timestamp.desc()).first()
        ttp = latest_log.ttp_fingerprint if latest_log else None
        if isinstance(ttp, str):
            try:
                ttp = json.loads(ttp)
            except Exception:
                pass
        
        # Calculate full chain result for dashboard progress bar
        from backend.core.decision_engine import detect_attack_chain
        chain_res = detect_attack_chain(s.attack_types)
        
        res.append({
            "id": s.id,
            "ip_address": s.ip_address,
            "session_id": s.session_id,
            "attack_count": s.attack_count,
            "attack_types": s.attack_types,
            "risk_score": s.risk_score,
            "honeypot_state": s.honeypot_state,
            "fake_services": s.fake_services,
            "is_active": s.is_active,
            "session_duration": s.session_duration,
            "commands_issued": s.commands_issued,
            "payload_hashes": s.payload_hashes,
            "interaction_depth": s.interaction_depth,
            "first_seen": s.first_seen,
            "last_seen": s.last_seen,
            "deception_score_avg": s.deception_score_avg,
            "attack_chain_name": s.attack_chain_name,
            "attack_chain_progress": s.attack_chain_progress,
            "attack_chain": chain_res,
            "llm_summary": s.llm_summary,
            "ttp_fingerprint": ttp
        })
    return res

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
        "deception_score_avg": session.deception_score_avg,
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
    Generates an LLM threat summary for the entire session with DB caching.
    """
    session = db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    summarizer.gemini_cache_queries += 1

    # Return cached value if present
    if session.llm_summary:
        summarizer.gemini_cache_hits += 1
        if isinstance(session.llm_summary, str):
            try:
                return json.loads(session.llm_summary)
            except Exception:
                pass
        return session.llm_summary

    events = db.query(AttackLog).filter(AttackLog.session_id == session_id).all()
    
    # Collate raw payloads
    combined_payloads = "\n".join(
        [e.raw_payload[:150] for e in events if e.raw_payload][:5]
    )

    history = {
        "attack_count": session.attack_count,
        "total_sessions": 1,
        "previous_attack_types": session.attack_types,
        "chain_name": session.attack_chain_name or "none"
    }

    # Generate summary based on first/most prominent attack type
    primary_attack = session.attack_types[0] if session.attack_types else "unknown"
    avg_confidence = (
        sum(e.confidence for e in events) / len(events) if events else 0.0
    )

    summary = await summarizer.generate_attack_summary(
        attack_type=primary_attack,
        confidence=avg_confidence,
        risk_score=session.risk_score,
        payload=combined_payloads,
        ip=session.ip_address,
        history=history
    )

    # Save to database
    session.llm_summary = summary
    db.commit()

    return summary

@router.get("/{session_id}/behavior_timeline")
def get_session_behavior_timeline(session_id: str, db: Session = Depends(get_db)):
    """
    Returns a time-ordered list of events for a session with delta timing.
    """
    session = db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    events = db.query(AttackLog).filter(AttackLog.session_id == session_id).order_by(AttackLog.timestamp.asc()).all()
    
    timeline = []
    first_timestamp = None
    previous_attack_types = []
    
    for idx, e in enumerate(events):
        if idx == 0:
            first_timestamp = e.timestamp
            delta_seconds = 0
        else:
            delta_seconds = int((e.timestamp - first_timestamp).total_seconds())
            
        if e.attack_type not in previous_attack_types:
            previous_attack_types.append(e.attack_type)
            
        # Reconstruct attacker history at this step
        attacker_history = {
            "ip_address": e.ip_address,
            "total_sessions": 1,
            "attack_count": idx + 1,
            "previous_attack_types": list(previous_attack_types)
        }
        
        from backend.core.adaptive_engine import decide_behavior
        deception = decide_behavior(
            attack_type=e.attack_type,
            confidence=e.confidence,
            risk_score=e.risk_score,
            attacker_history=attacker_history
        )
        deception_state = deception["honeypot_state"]
        
        timeline.append({
            "timestamp": e.timestamp.isoformat() + "Z",
            "attack_type": e.attack_type,
            "risk_score": e.risk_score,
            "mitre_technique": e.mitre_technique,
            "deception_state": deception_state,
            "delta_seconds": delta_seconds
        })
        
    return timeline

@router.get("/{session_id}/explain")
def get_session_explanation(session_id: str, db: Session = Depends(get_db)):
    """
    Exposes explainability metrics (SHAP contributions, counterfactuals, policies) for a session.
    """
    from backend.core.explanation_engine import DeceptionExplanationEngine
    latest_log = db.query(AttackLog).filter(AttackLog.session_id == session_id).order_by(AttackLog.timestamp.desc()).first()
    if not latest_log:
        raise HTTPException(status_code=404, detail="No logs found for this session")
        
    engine = DeceptionExplanationEngine(db)
    return engine.generate_decision_explanation(session_id, latest_log.id)

@router.get("/{session_id}/report")
def get_session_markdown_report(session_id: str, db: Session = Depends(get_db)):
    """
    Returns a copy-pasteable Markdown brief summarizing the incident and actions.
    """
    from backend.core.explanation_engine import DeceptionExplanationEngine
    engine = DeceptionExplanationEngine(db)
    return {"report": engine.generate_soc_markdown_report(session_id)}

@router.get("/{session_id}/graph")
def get_session_behavior_graph(session_id: str, db: Session = Depends(get_db)):
    """
    Calculates dynamic behavior sequence graph and next TTP prediction vectors.
    """
    import backend.core.behavior_intelligence as behavior_intel
    logs = db.query(AttackLog).filter(AttackLog.session_id == session_id).order_by(AttackLog.timestamp.asc()).all()
    if not logs:
        raise HTTPException(status_code=404, detail="No logs found for session")
        
    sequence = behavior_intel.build_attack_sequence(logs)
    next_ttp, probability = behavior_intel.predict_next_mitre_technique(sequence)
    objective = behavior_intel.infer_attacker_objective(sequence)
    attributes = behavior_intel.estimate_attacker_properties(sequence)
    similar_sess, similarity = behavior_intel.analyze_campaign_similarity(db, session_id, sequence)
    
    # Structure node/edge link representation
    nodes = []
    edges = []
    seen_nodes = set()
    
    for idx, ttp in enumerate(sequence):
        details = next((v for v in behavior_intel.MITRE_ATTACK_MAPPING.values() if v["id"] == ttp), {"name": "Unknown", "stage": "Reconnaissance"})
        if ttp not in seen_nodes:
            seen_nodes.add(ttp)
            nodes.append({
                "id": ttp,
                "label": f"{details['name']} ({ttp})",
                "stage": details["stage"]
            })
        if idx > 0:
            edges.append({
                "source": sequence[idx - 1],
                "target": ttp,
                "weight": 1
            })
            
    return {
        "session_id": session_id,
        "sequence": sequence,
        "nodes": nodes,
        "edges": edges,
        "predictions": {
            "probable_next_mitre_technique": next_ttp,
            "transition_probability": probability,
            "expected_attacker_objective": objective,
            "expected_dwell_time_seconds": attributes["expected_dwell_time_seconds"],
            "persistence_probability": attributes["persistence_probability"]
        },
        "campaign_cluster": {
            "similar_session_id": similar_sess,
            "similarity_score": similarity
        }
    }
