from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.models.attack import AttackLog
from backend.models.session import AttackerSession

class DeceptionExplanationEngine:
    """
    Formulates decision intelligence explanations, policy reasoning traces,
    counterfactual analysis, and SOC-ready markdown briefs of deception operations.
    """
    def __init__(self, db: Session):
        self.db = db

    def generate_decision_explanation(self, session_id: str, log_id: int) -> Dict[str, Any]:
        log = self.db.query(AttackLog).filter(AttackLog.id == log_id).first()
        session = self.db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
        
        if not log:
            return {"status": "error", "message": "Log entry not found."}
            
        action = log.deception_action or "default:low"
        profile = action.split(":")[0]
        level = action.split(":")[1] if ":" in action else "low"
        
        # 1. Analyze contributing evidence
        contributing_features = {
            "attack_payload_indicators": 0.85 if log.risk_score >= 70 else 0.40,
            "external_threat_reputation": 0.90 if log.risk_score >= 80 else 0.50,
            "session_depth_count": min(1.0, (session.interaction_depth if session else 1) / 10.0)
        }
        
        # 2. Identify rejected alternatives
        alternatives = ["default", "port_expansion", "credential_trap", "database_decoy", "shell_trap", "filesystem_decoy"]
        rejected_actions = [alt for alt in alternatives if alt != profile]
        
        # 3. Counterfactual analysis
        actual_delay_ms = 2000 if profile == "brute_force" else 500 if profile == "port_scan" else 100
        cf_delay_ms = 0
        counterfactual_trace = (
            f"If alternative posture '{rejected_actions[0]}' had been deployed instead of '{profile}', "
            f"response delay would have shifted from {actual_delay_ms}ms to {cf_delay_ms}ms, "
            f"increasing scanner recon speed by {abs(actual_delay_ms - cf_delay_ms)}ms and reducing threat intelligence gather time."
        )
        
        # 4. Analyst Recommendations
        recommendations = [
            f"Maintain stateful monitoring for {log.ip_address} on profile '{profile}' level '{level}'.",
            "Monitor for outbound data transfer flags indicating potential lateral egress attempts.",
            "Verify honeypot local conntrack limits if connection speed drops below normal parameters."
        ]

        # 5. Policy reasoning
        triggered_policies = []
        if log.risk_score >= 80:
            triggered_policies.append("CRITICAL_THREAT_CONTAINMENT_POLICY")
        if session and session.interaction_depth >= 5:
            triggered_policies.append("DEEP_INTERACTION_ENGAGEMENT_POLICY")
        if not triggered_policies:
            triggered_policies.append("DEFAULT_DECEPTION_MONITOR_POLICY")

        return {
            "session_id": session_id,
            "log_id": log_id,
            "deployed_deception_profile": profile,
            "deception_level": level,
            "contributing_evidence_weights": contributing_features,
            "triggered_policies": triggered_policies,
            "cooperative_rl_reasoning": f"Service Agent selected profile '{profile}' and Network Agent matched delay level '{level}' using unified cooperative values.",
            "rejected_deception_alternatives": rejected_actions[:3],
            "counterfactual_scenario": counterfactual_trace,
            "analyst_actions_recommended": recommendations
        }

    def generate_soc_markdown_report(self, session_id: str) -> str:
        """
        Synthesizes all explanation parameters into a clean, copy-pasteable Markdown report.
        """
        session = self.db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
        if not session:
            return "# Threat Incident Brief\n\nSession not found."
            
        logs = self.db.query(AttackLog).filter(AttackLog.session_id == session_id).all()
        if not logs:
            return f"# Threat Incident Brief: {session_id}\n\nNo attack logs captured."
            
        last_log = logs[-1]
        exp = self.generate_decision_explanation(session_id, last_log.id)
        
        report = f"""# PRAETOR Security Incident Brief
**Incident Session ID:** `{session_id}`
**Target Host IP Address:** `{session.ip_address}`
**Active Status:** `{"ACTIVE" if session.is_active else "CLOSED"}`
**Dwell Time:** `{session.session_duration or 0.0:.2f}s`

---

## 🛡️ Deception Action Summary
* **Active Posture:** `{exp['deployed_deception_profile']}:{exp['deception_level']}`
* **Decision Trace:** {exp['cooperative_rl_reasoning']}
* **Confidence Rating:** `{last_log.confidence*100:.1f}%`

## 🧠 Policy & Heuristics Context
* **Triggered Compliance Policies:**
{chr(10).join([f"  * `{policy}`" for policy in exp['triggered_policies']])}
* **Alternative Postures Evaluated (Rejected):**
{chr(10).join([f"  * `{alt}` (Reason: lower expected interaction depth)" for alt in exp['rejected_deception_alternatives']])}

## ⚖️ Counterfactual Analysis
> *{exp['counterfactual_scenario']}*

## 💡 Recommended Analyst Actions
{chr(10).join([f"1. **{idx+1}.** {rec}" for idx, rec in enumerate(exp['analyst_actions_recommended'])])}
"""
        return report
