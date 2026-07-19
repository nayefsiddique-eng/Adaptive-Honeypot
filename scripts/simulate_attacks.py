import os
import sys
import asyncio

# Ensure backend directory is in the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import SessionLocal
from backend.core.demo_engine import run_closed_loop_simulation

def main():
    print("=== Starting MIRAGE Attack Simulator ===")
    print("Running closed-loop simulation directly via unified backend core logic...")
    db = SessionLocal()
    try:
        events = asyncio.run(run_closed_loop_simulation(db, session_count=10, step_delay=0.01))
        print(f"\n=== Simulation Complete. Total events generated: {events} ===")
    except Exception as e:
        print(f"[-] Simulation failed: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    main()
