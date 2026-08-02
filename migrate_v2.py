import sqlite3
import os

db_path = "honeypot.db"

def run_migration():
    path = db_path
    if not os.path.exists(path):
        # Check subdirectories or relative paths
        if os.path.exists("adaptive-honeypot/honeypot.db"):
            path = "adaptive-honeypot/honeypot.db"
        elif os.path.exists("backend/honeypot.db"):
            path = "backend/honeypot.db"
        elif os.path.exists("../honeypot.db"):
            path = "../honeypot.db"
    
    print(f"Connecting to database: {os.path.abspath(path)}")
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    # 1. Alter attack_logs table
    cursor.execute("PRAGMA table_info(attack_logs)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if "ttp_fingerprint" not in columns:
        print("Adding column 'ttp_fingerprint' to 'attack_logs'...")
        cursor.execute("ALTER TABLE attack_logs ADD COLUMN ttp_fingerprint JSON")
    else:
        print("Column 'ttp_fingerprint' already exists in 'attack_logs'.")
        
    # 2. Alter attacker_sessions table
    cursor.execute("PRAGMA table_info(attacker_sessions)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if "deception_score_avg" not in columns:
        print("Adding column 'deception_score_avg' to 'attacker_sessions'...")
        cursor.execute("ALTER TABLE attacker_sessions ADD COLUMN deception_score_avg REAL DEFAULT 0.0")
    else:
        print("Column 'deception_score_avg' already exists in 'attacker_sessions'.")
        
    if "attack_chain_name" not in columns:
        print("Adding column 'attack_chain_name' to 'attacker_sessions'...")
        cursor.execute("ALTER TABLE attacker_sessions ADD COLUMN attack_chain_name TEXT")
    else:
        print("Column 'attack_chain_name' already exists in 'attacker_sessions'.")
        
    if "attack_chain_progress" not in columns:
        print("Adding column 'attack_chain_progress' to 'attacker_sessions'...")
        cursor.execute("ALTER TABLE attacker_sessions ADD COLUMN attack_chain_progress INTEGER DEFAULT 0")
    else:
        print("Column 'attack_chain_progress' already exists in 'attacker_sessions'.")
        
    if "llm_summary" not in columns:
        print("Adding column 'llm_summary' to 'attacker_sessions'...")
        cursor.execute("ALTER TABLE attacker_sessions ADD COLUMN llm_summary JSON")
    else:
        print("Column 'llm_summary' already exists in 'attacker_sessions'.")

    conn.commit()
    conn.close()
    print("Database migration completed.")

if __name__ == "__main__":
    run_migration()
