import random
import logging
from typing import Dict, Any, Tuple, List
from sqlalchemy.orm import Session
from backend.models.policy import RLPolicy
from backend.models.session import AttackerSession
from backend.core.decision_engine import DECEPTION_PROFILES

logger = logging.getLogger("cooperative_rl")

# CMAQL Parameters
ALPHA = 0.1
GAMMA = 0.9
EPSILON_START = 0.3
EPSILON_END = 0.05
EPSILON_DECAY_STEPS = 150

# Agent Action Spaces
NETWORK_ACTIONS = ["low", "medium", "high"]
SERVICE_ACTIONS = ["brute_force", "sql_injection", "command_injection", "path_traversal", "port_scan"]
INTEL_ACTIONS = ["log_keystrokes", "enrich_metadata", "delayed_response"]

class CooperativeRLCoordinator:
    """
    Coordinative architecture that syncs Network, Service, and Intelligence agents' state spaces
    to optimize a joint reward function.
    """
    def __init__(self, db: Session) -> None:
        self.db = db
        
    def get_epsilon(self) -> float:
        try:
            count = self.db.query(RLPolicy).count()
            decay = count / EPSILON_DECAY_STEPS
            return max(EPSILON_END, EPSILON_START - (EPSILON_START - EPSILON_END) * decay)
        except Exception:
            return EPSILON_START

    def get_agent_q(self, agent_name: str, state: str, action: str) -> float:
        state_key = f"{agent_name}:{state}"
        try:
            entry = self.db.query(RLPolicy).filter(RLPolicy.state == state_key, RLPolicy.action == action).first()
            if entry:
                return entry.q_value
        except Exception as e:
            logger.error(f"Error reading Q-value: {e}")
        return 20.0  # Optimistic initial value

    def set_agent_q(self, agent_name: str, state: str, action: str, value: float) -> None:
        state_key = f"{agent_name}:{state}"
        try:
            entry = self.db.query(RLPolicy).filter(RLPolicy.state == state_key, RLPolicy.action == action).first()
            if not entry:
                entry = RLPolicy(state=state_key, action=action, q_value=value)
                self.db.add(entry)
            else:
                entry.q_value = value
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error setting Q-value: {e}")

    def select_coordinated_strategy(self, state_str: str) -> Tuple[str, Dict[str, str], float]:
        """
        Coordinates action selection across the 3 agents.
        Returns: (deception_profile_name:level, agent_actions_dict, confidence)
        """
        epsilon = self.get_epsilon()
        
        selected = {}
        # 1. Network Agent choice
        if random.random() < epsilon:
            selected["network"] = random.choice(NETWORK_ACTIONS)
        else:
            selected["network"] = max(NETWORK_ACTIONS, key=lambda a: self.get_agent_q("net", state_str, a))
            
        # 2. Service Agent choice
        if random.random() < epsilon:
            selected["service"] = random.choice(SERVICE_ACTIONS)
        else:
            selected["service"] = max(SERVICE_ACTIONS, key=lambda a: self.get_agent_q("svc", state_str, a))
            
        # 3. Intelligence Agent choice
        if random.random() < epsilon:
            selected["intel"] = random.choice(INTEL_ACTIONS)
        else:
            selected["intel"] = max(INTEL_ACTIONS, key=lambda a: self.get_agent_q("intl", state_str, a))
            
        # Conflict Resolution & Coordination (Arbitration Rules)
        final_profile = selected["service"]
        final_level = selected["network"]
        
        coexistence_action = f"{final_profile}:{final_level}"
        return coexistence_action, selected, 1.0 - epsilon

    def update_cooperative_rewards(self, state_str: str, actions: Dict[str, str], next_state_str: str, joint_reward: float) -> None:
        """
        Updates Q-tables of all cooperative agents using the single joint reward score.
        """
        for agent_name, agent_key in [("net", "network"), ("svc", "service"), ("intl", "intel")]:
            act = actions.get(agent_key)
            if not act:
                continue
                
            old_q = self.get_agent_q(agent_name, state_str, act)
            
            # Estimate next max Q
            actions_list = NETWORK_ACTIONS if agent_name == "net" else SERVICE_ACTIONS if agent_name == "svc" else INTEL_ACTIONS
            max_next_q = max(self.get_agent_q(agent_name, next_state_str, a) for a in actions_list)
            
            # Bellman Equation Update
            new_q = old_q + ALPHA * (joint_reward + GAMMA * max_next_q - old_q)
            self.set_agent_q(agent_name, state_str, act, new_q)

def calculate_joint_reward(session: AttackerSession, deception_score: float) -> float:
    """
    Computes unified cooperative rewards based on connection longevity,
    penetration depth, and target deception alignment.
    """
    duration = session.session_duration or 0.0
    depth = session.interaction_depth or 1
    
    # Joint Reward Heuristic
    r_time = min(15.0, duration / 10.0) # Reward longer dwell times
    r_depth = depth * 3.0              # Reward deeper interactions
    r_deception = deception_score * 8.0 # Reward alignment with optimal profiles
    
    return round(r_time + r_depth + r_deception, 4)

def update_q_table_for_session(db: Session, session_id: str, state_str: str, action_str: str, deception_score: float) -> None:
    """
    Called by the session reaper background task to finalize cooperative rewards.
    """
    session = db.query(AttackerSession).filter(AttackerSession.session_id == session_id).first()
    if not session:
        return
        
    reward = calculate_joint_reward(session, deception_score)
    session.rl_reward = reward
    
    # Reconstruct coordinated actions dictionary
    svc_act = action_str
    net_act = session.rl_network_action or f"default:medium"
    intl_act = session.rl_intel_action or "delayed_response"
    
    actions_dict = {
        "network": net_act,
        "service": svc_act,
        "intel": intl_act
    }
    
    coordinator = CooperativeRLCoordinator(db)
    # Perform cooperative updates
    coordinator.update_cooperative_rewards(state_str, actions_dict, "terminal_state", reward)

def serialize_state(attack_type: str, history_bucket: str, interaction_level: str) -> str:
    return f"{attack_type}:{history_bucket}:{interaction_level}"

def get_history_bucket(total_sessions: int) -> str:
    if total_sessions <= 1:
        return "new"
    elif total_sessions <= 5:
        return "returning"
    else:
        return "persistent"

def get_q_value(db: Session, state: str, action: str) -> float:
    svc_action = action.split(":")[0] if ":" in action else action
    coordinator = CooperativeRLCoordinator(db)
    return coordinator.get_agent_q("svc", state, svc_action)

def set_q_value(db: Session, state: str, action: str, value: float) -> bool:
    svc_action = action.split(":")[0] if ":" in action else action
    coordinator = CooperativeRLCoordinator(db)
    coordinator.set_agent_q("svc", state, svc_action, value)
    return True

def calculate_reward(session: AttackerSession, deception_score: float) -> float:
    return calculate_joint_reward(session, deception_score)

def choose_rl_action(db: Session, attack_type: str, total_sessions: int, current_level: str) -> Tuple[str, float, bool, Dict[str, str]]:
    """
    Standard interface mapping for API logging ingestion.
    """
    history_bucket = get_history_bucket(total_sessions)
    state_str = serialize_state(attack_type, history_bucket, current_level)
    
    coordinator = CooperativeRLCoordinator(db)
    action_str, selected, confidence = coordinator.select_coordinated_strategy(state_str)
    
    return action_str, confidence, False, selected
