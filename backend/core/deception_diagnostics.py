from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.models.session import AttackerSession
from backend.models.attack import AttackLog

class DeceptionDiagnosticsEngine:
    """
    Computes Deception Effectiveness Scores (DES) and Return on Deception (RoD)
    to mathematically evaluate defensive posture performance.
    """
    def __init__(self, db: Session):
        self.db = db

    def calculate_deception_effectiveness(self, session_id: str) -> Dict[str, Any]:
        session = self.db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
        if not session:
            return {"status": "error", "message": "Session not found."}
            
        logs = self.db.query(AttackLog).filter(AttackLog.session_id == session_id).all()
        avg_confidence = sum(log.confidence for log in logs) / len(logs) if logs else 0.5
        
        duration = session.session_duration or 1.0
        depth = session.interaction_depth or 1
        intel_points = len(logs) * 5
        
        # Normalized parameters
        norm_duration = min(1.0, duration / 180.0)
        norm_depth = min(1.0, depth / 10.0)
        norm_intel = min(1.0, intel_points / 100.0)
        
        # Weighted Deception Effectiveness Score (DES)
        des = (0.3 * norm_duration) + (0.3 * norm_depth) + (0.2 * norm_intel) + (0.2 * avg_confidence)
        
        return {
            "session_id": session_id,
            "dwell_time_seconds": round(duration, 2),
            "interaction_depth": depth,
            "intelligence_collected": intel_points,
            "policy_confidence": round(avg_confidence, 4),
            "deception_effectiveness_score": round(des, 4)
        }

    def calculate_return_on_deception(self, session_id: str) -> Dict[str, Any]:
        session = self.db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
        if not session:
            return {"status": "error", "message": "Session not found."}
            
        logs = self.db.query(AttackLog).filter(AttackLog.session_id == session_id).all()
        
        intel_value = len(logs) * 5.0
        analyst_usefulness = 10.0 if session.interaction_depth >= 3 else 2.0
        
        # Estimated resource consumption costs
        cpu_cost = 0.05 * (session.interaction_depth or 1)
        mem_cost = 0.12 * (session.interaction_depth or 1)
        storage_cost = len(logs) * 0.01
        
        total_cost = cpu_cost + mem_cost + storage_cost
        if total_cost == 0:
            total_cost = 0.01
            
        # Return on Deception (RoD) Ratio
        rod = (intel_value + analyst_usefulness) / total_cost
        
        return {
            "session_id": session_id,
            "forensic_intelligence_value": intel_value,
            "analyst_usefulness_rating": analyst_usefulness,
            "computed_operational_cost": round(total_cost, 4),
            "return_on_deception_ratio": round(rod, 4)
        }
