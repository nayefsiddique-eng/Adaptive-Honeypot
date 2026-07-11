import os
import sys
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.database import Base
from backend.models.policy import RLPolicy
from backend.models.session import AttackerSession
from backend.core.rl_engine import choose_rl_action, set_q_value, get_q_value, serialize_state, calculate_reward, ALPHA

def test_rl_learning_convergence():
    """
    Simulates 250 decision cycles and verifies that the Q-learning policy converges
    to select the matching deception action, yielding a higher average reward over time.
    """
    # 1. Setup in-memory SQLite database for testing
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # List of possible attack types
    attack_types = ["sql_injection", "brute_force", "command_injection", "port_scan", "path_traversal"]
    
    rewards_history = []
    
    # 2. Run 250 simulated decision cycles
    total_cycles = 250
    for cycle in range(total_cycles):
        # Pick a random attack type
        attack_type = attack_types[cycle % len(attack_types)]
        total_sessions = 1
        current_level = "low"
        
        # State: attack_type:new:low
        state_str = serialize_state(attack_type, "new", current_level)
        
        # Select action using Q-learning (epsilon-greedy)
        # Note: get_epsilon will decay epsilon dynamically based on the count of RLPolicy records in DB.
        # To simulate updates decaying epsilon, we write entries.
        action_str, confidence, explored = choose_rl_action(db, attack_type, total_sessions, current_level)
        
        # 3. Attacker feedback simulator (the environment)
        # If the honeypot action's profile matches the attack type, the attacker is convinced and stays
        chosen_profile = action_str.split(":")[0]
        chosen_level = action_str.split(":")[1] if ":" in action_str else "low"
        
        if chosen_profile == attack_type:
            # Optimal action: matches attack type. Attacker stays engaged.
            # Reward: high deception score, high depth, longer duration
            sim_deception_score = 0.9 if chosen_level == "high" else 0.6 if chosen_level == "medium" else 0.3
            sim_session = AttackerSession(
                session_duration=45.0 if chosen_level == "high" else 20.0,
                interaction_depth=3 if chosen_level == "high" else 2
            )
            reward = calculate_reward(sim_session, sim_deception_score)
        else:
            # Suboptimal action: mismatched deception. Attacker leaves immediately.
            sim_deception_score = 0.1
            sim_session = AttackerSession(
                session_duration=1.0,
                interaction_depth=1
            )
            reward = calculate_reward(sim_session, sim_deception_score)
            
        rewards_history.append(reward)
        
        # 4. Perform Q-value Bellman update for this terminal step
        old_q = get_q_value(db, state_str, action_str)
        new_q = old_q + ALPHA * (reward - old_q)
        set_q_value(db, state_str, action_str, new_q)
        
    # 5. Calculate averages
    first_50 = rewards_history[:50]
    last_50 = rewards_history[-50:]
    
    avg_first_50 = sum(first_50) / len(first_50)
    avg_last_50 = sum(last_50) / len(last_50)
    
    print(f"\n[+] RL Learning Verification Results:")
    print(f"    - Average reward in first 50 cycles: {avg_first_50:.4f}")
    print(f"    - Average reward in last 50 cycles: {avg_last_50:.4f}")
    
    # Cleanup DB connection
    db.close()
    Base.metadata.drop_all(bind=engine)
    
    # Assert that learning converges: reward in last 50 must be significantly higher
    # First 50: random actions (rewards around 5-7 or higher due to optimistic initialization)
    # Last 50: learned matching actions (rewards around 15-25)
    assert avg_last_50 > avg_first_50 + 5.0, f"Policy failed to converge. First 50 avg: {avg_first_50:.2f}, Last 50 avg: {avg_last_50:.2f}"
    assert avg_last_50 >= 16.0, f"Final policy quality is too low. Last 50 avg: {avg_last_50:.2f}"

if __name__ == "__main__":
    test_rl_learning_convergence()
