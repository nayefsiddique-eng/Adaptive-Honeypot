import time
import hashlib
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from backend.database import get_db
from backend.models.attack import AttackLog
from backend.models.session import AttackerSession
from backend.models.reputation import AttackerReputation
from backend.core.feature_extractor import extract_features, classify_attack_heuristic
from backend.core.traffic_logger import log_event
from backend.services.mitre_mapper import map_to_mitre
from backend.services.classifier import predict, models_loaded
from backend.services.geoip_enricher import enrich_ip
from backend.core.threat_intel import evaluate_ip_threat
from backend.core.adaptive_engine import decide_behavior
from backend.core.decision_engine import detect_attack_chain, get_deception_profile
from backend.core.cooperative_rl_engine import choose_rl_action, serialize_state, get_history_bucket

router = APIRouter()

class LogRequest(BaseModel):
    ip_address: str
    port: int
    protocol: str
    payload: Optional[str] = ""
    metadata: Optional[dict] = {}

def calculate_risk_score(features: dict, attack_type: str, confidence: float) -> float:
    severity_map = {
        "brute_force": 60, "port_scan": 40, "sql_injection": 80,
        "xss": 70, "command_injection": 90, "malware_delivery": 95,
        "path_traversal": 65, "unknown": 20,
        # Feature 6 - Additional Attack Types
        "ldap_injection": 85, "ssrf": 75, "deserialization": 90,
        "dns_tunneling": 70, "credential_stuffing": 65
    }
    score = severity_map.get(attack_type, 20)
    score += min(features.get("login_attempts", 0) * 2, 20)
    score += min(features.get("ports_scanned", 0) * 3, 15)
    
    # Baseline confidence scaling
    conf_factor = 0.5 + 0.5 * confidence if confidence > 0 else 0.6
    score = score * conf_factor
    return min(round(score, 2), 100.0)

@router.post("/ingest")
async def ingest_log(req: LogRequest, db: Session = Depends(get_db)):
    start_time = time.time()
    
    # 1. Log Raw Traffic
    raw_event = log_event(req.ip_address, req.port, req.protocol, req.payload, req.metadata)
    
    # 2. Extract Features & Predict Attack Class
    features = extract_features(req.ip_address, req.port, req.protocol, req.payload, req.metadata)
    ttp_fingerprint = features.pop("ttp_fingerprint", None)

    if models_loaded():
        ml_result = predict(features)
        attack_type = ml_result["attack_type"]
        confidence = ml_result["confidence"]
        is_anomaly = ml_result["is_anomaly"]
        ml_result = {}
    else:
        attack_type = classify_attack_heuristic(features)
        confidence = 0.0
        is_anomaly = False
        ml_result = {}

    mitre = map_to_mitre(attack_type)
    risk_score = calculate_risk_score(features, attack_type, confidence)

    # 3. GeoIP Enrichment
    geo = enrich_ip(req.ip_address)

    # 4. Threat Intel Evaluation
    intel = await evaluate_ip_threat(req.ip_address)

    try:
        # 5. Maintain Attacker Reputation Profile
        reputation = db.query(AttackerReputation).filter(AttackerReputation.ip_address == req.ip_address).first()
        if not reputation:
            reputation = AttackerReputation(
                ip_address=req.ip_address,
                total_sessions=1,
                attack_count=1,
                previous_attack_types=[attack_type],
                country=geo["country"],
                city=geo["city"],
                isp=geo["isp"],
                latitude=geo["latitude"],
                longitude=geo["longitude"],
                abuse_ip_db_score=intel["abuseipdb_score"],
                alien_vault_score=intel["alienvault_score"],
                reputation_score=max(0.0, 100.0 - intel["reputation_score"])
            )
            db.add(reputation)
        else:
            reputation.attack_count += 1
            
            # Handle JSON mutation detection in SQLAlchemy
            prev_attacks = list(reputation.previous_attack_types)
            if attack_type not in prev_attacks:
                prev_attacks.append(attack_type)
                reputation.previous_attack_types = prev_attacks
                
            # Recalculate combined reputation (local frequency + intelligence feeds)
            local_freq_penalty = min(reputation.attack_count * 2.0, 40.0)
            external_feed_penalty = intel["reputation_score"] * 0.60
            reputation.reputation_score = max(0.0, round(100.0 - local_freq_penalty - external_feed_penalty, 2))
            
            # Ensure coordinates are saved if not present
            if reputation.latitude == 0.0 and geo["latitude"] != 0.0:
                reputation.latitude = geo["latitude"]
                reputation.longitude = geo["longitude"]
                reputation.country = geo["country"]
                reputation.city = geo["city"]
                reputation.isp = geo["isp"]

        # 6. Session Lifecycle & Recording Updates
        time_limit = datetime.utcnow() - timedelta(minutes=30)
        session = db.query(AttackerSession).filter(
            AttackerSession.ip_address == req.ip_address,
            AttackerSession.is_active == True,
            # Compare SQLite timestamps safely
            AttackerSession.last_seen >= time_limit
        ).first()

        now_dt = datetime.utcnow()

        if not session:
            # Create a new session
            session_id = raw_event["session_id"]
            session = AttackerSession(
                ip_address=req.ip_address,
                session_id=session_id,
                attack_count=1,
                attack_types=[attack_type],
                risk_score=risk_score,
                honeypot_state="default",
                fake_services=[],
                is_active=True,
                session_duration=0.0,
                commands_issued=[],
                payload_hashes=[],
                deception_score_avg=0.0,
                attack_chain_name=None,
                attack_chain_progress=0
            )
            db.add(session)
            reputation.total_sessions += 1
        else:
            session_id = session.session_id
            session.attack_count += 1
            
            # Update attack type list
            sess_types = list(session.attack_types)
            if attack_type not in sess_types:
                sess_types.append(attack_type)
                session.attack_types = sess_types
                
            session.risk_score = max(session.risk_score, risk_score)
            
            # Calculate session duration
            first_seen_naive = session.first_seen.replace(tzinfo=None)
            session.session_duration = max(0.0, (now_dt - first_seen_naive).total_seconds())

        # Record command execution inputs (CLI-based payloads)
        session_commands = list(session.commands_issued)
        if attack_type == "command_injection" and req.payload:
            session_commands.append(req.payload.strip())
        elif attack_type == "brute_force" and req.payload:
            session_commands.append(f"AUTHENTICATION TRY: {req.payload.strip()}")
        session.commands_issued = session_commands

        # Append payload hashes
        session_hashes = list(session.payload_hashes)
        if req.payload:
            p_hash = hashlib.sha256(req.payload.encode()).hexdigest()
            if p_hash not in session_hashes:
                session_hashes.append(p_hash)
        session.payload_hashes = session_hashes

        # 7. Execute Adaptive Behavior Engine
        current_depth = session.interaction_depth or 0
        depth_map = {0: "low", 1: "low", 2: "medium", 3: "high", 4: "high"}
        current_level = depth_map.get(current_depth, "low")
        
        action_str, policy_confidence, explored, selected = choose_rl_action(db, attack_type, reputation.total_sessions, current_level)
        state_str = serialize_state(attack_type, get_history_bucket(reputation.total_sessions), current_level)
        
        session.rl_state = state_str
        session.rl_action = action_str
        session.rl_network_action = selected.get("network", "default:medium")
        session.rl_intel_action = selected.get("intel", "delayed_response")
        
        parts = action_str.split(":")
        profile_key = parts[0]
        level = parts[1] if len(parts) > 1 else "low"
        
        profile = get_deception_profile(profile_key)
        
        action_map = {"low": "monitor", "medium": "active_deception", "high": "full_deception"}
        deception = {
            "action": action_map.get(level, "monitor"),
            "interaction_level": level,
            "honeypot_state": profile["state"],
            "fake_services": profile["fake_services"],
            "fake_banners": profile["fake_banners"],
            "response_delay_ms": profile["response_delay_ms"],
            "fake_credentials_accepted": profile["fake_credentials_accepted"],
            "decoy_files": profile["decoy_files"],
            "exposed_ports": [80, 22] if level == "low" else [21, 22, 23, 80, 443, 445, 3306, 3389, 8080],
            "reasoning": f"RL selected action '{action_str}' based on state '{state_str}'",
            "deception_score": 0.0
        }
        
        # Calculate deception score
        interaction_level_map = {"low": 0, "medium": 1, "high": 2}
        deception_score = (
            (interaction_level_map.get(level, 0) / 2.0) * 0.40 +
            (len(profile["fake_services"]) / 5.0) * 0.20 +
            (len(profile["decoy_files"]) / 6.0) * 0.20 +
            (min(profile["response_delay_ms"], 2000) / 2000.0) * 0.20
        )
        deception["deception_score"] = min(round(deception_score, 4), 1.0)
        session.rl_deception_score = deception["deception_score"]

        # Update session details from adaptive engine
        session.honeypot_state = deception["honeypot_state"]
        session.fake_services = deception["fake_services"]
        
        depth_levels = {"low": 1, "medium": 2, "high": 3}
        session.interaction_depth = max(current_depth, depth_levels.get(level, 1))
        session.last_seen = now_dt

        # Feature 2 - Update Deception Score Average
        current_count = session.attack_count
        prev_avg = session.deception_score_avg or 0.0
        session.deception_score_avg = round((prev_avg * (current_count - 1) + deception["deception_score"]) / current_count, 4)

        # Feature 3 - Attack Chain Detection
        chain_result = detect_attack_chain(reputation.previous_attack_types)
        session.attack_chain_name = chain_result["chain_name"]
        session.attack_chain_progress = chain_result["chain_progress"]

        # Measure API Response Latency
        response_time_ms = round((time.time() - start_time) * 1000.0, 3)

        # 8. Save Log to SQLite
        log = AttackLog(
            session_id=session_id,
            ip_address=req.ip_address,
            port=req.port,
            protocol=req.protocol,
            attack_type=attack_type,
            confidence=confidence,
            risk_score=risk_score,
            mitre_technique=mitre["technique_id"],
            country=geo["country"],
            city=geo["city"],
            isp=geo["isp"],
            latitude=geo["latitude"],
            longitude=geo["longitude"],
            raw_payload=req.payload,
            features=features,
            ttp_fingerprint=ttp_fingerprint,
            response_time_ms=response_time_ms
        )
        db.add(log)
        db.commit()
        db.refresh(log)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database transaction failure: {str(e)}")

    return {
        "id": log.id,
        "session_id": session_id,
        "attack_type": attack_type,
        "confidence": confidence,
        "is_anomaly": is_anomaly,
        "risk_score": risk_score,
        "mitre": mitre,
        "geoip": geo,
        "deception": deception,
        "attack_chain": chain_result,
        "response_time_ms": response_time_ms
    }

@router.get("")
def get_logs_by_ip(ip: Optional[str] = None, db: Session = Depends(get_db)):
    if ip:
        logs = db.query(AttackLog).filter(AttackLog.ip_address == ip).order_by(AttackLog.timestamp.desc()).all()
    else:
        logs = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(100).all()
    res = []
    for l in logs:
        sess = db.query(AttackerSession).filter(AttackerSession.session_id == l.session_id).first() if l.session_id else None
        chain_name = sess.attack_chain_name if sess else None
        res.append({
            "id": l.id,
            "session_id": l.session_id,
            "ip_address": l.ip_address,
            "port": l.port,
            "protocol": l.protocol,
            "attack_type": l.attack_type,
            "confidence": l.confidence,
            "risk_score": l.risk_score,
            "mitre_technique": l.mitre_technique,
            "country": l.country,
            "city": l.city,
            "isp": l.isp,
            "latitude": l.latitude,
            "longitude": l.longitude,
            "raw_payload": l.raw_payload,
            "features": l.features,
            "ttp_fingerprint": l.ttp_fingerprint,
            "response_time_ms": l.response_time_ms,
            "timestamp": l.timestamp.isoformat() + "Z" if l.timestamp else None,
            "chain_name": chain_name
        })
    return res

@router.get("/recent")
def get_recent_logs(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(limit).all()
    res = []
    for l in logs:
        sess = db.query(AttackerSession).filter(AttackerSession.session_id == l.session_id).first() if l.session_id else None
        chain_name = sess.attack_chain_name if sess else None
        
        res.append({
            "id": l.id,
            "session_id": l.session_id,
            "ip_address": l.ip_address,
            "port": l.port,
            "protocol": l.protocol,
            "attack_type": l.attack_type,
            "confidence": l.confidence,
            "risk_score": l.risk_score,
            "mitre_technique": l.mitre_technique,
            "country": l.country,
            "city": l.city,
            "isp": l.isp,
            "latitude": l.latitude,
            "longitude": l.longitude,
            "raw_payload": l.raw_payload,
            "features": l.features,
            "ttp_fingerprint": l.ttp_fingerprint,
            "response_time_ms": l.response_time_ms,
            "timestamp": l.timestamp.isoformat() + "Z" if l.timestamp else None,
            "chain_name": chain_name
        })
    return res

@router.get("/{log_id}")
def get_log(log_id: int, db: Session = Depends(get_db)):
    log = db.query(AttackLog).filter(AttackLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log