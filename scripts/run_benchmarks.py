import os
import sys

# Ensure backend directory is in the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.database import Base
from backend.core.research_framework import PRAETORResearchFramework

def main():
    print("[*] Initializing PRAETOR Benchmark Runner...")

    # Use an in-memory SQLite database to simulate clean environment runs
    engine = create_engine("sqlite:///:memory:")
    SessionLocal = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        framework = PRAETORResearchFramework(db)

        print("[*] Running Stress & Scalability Tests...")
        scalability = framework.run_scalability_stress_test(session_count=100)

        report_path = "docs/BENCHMARK_REPORT.md"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        with open(report_path, "w") as f:
            f.write("# PRAETOR Scientific Benchmark & Evaluation Report\n\n")
            f.write("This report reflects a real, timed measurement of the platform's live decision path.\n\n")

            f.write("## Stress & Scalability Performance\n")
            f.write(f"* **Sessions Processed:** `{scalability['sessions_processed']}`\n")
            f.write(f"* **Mean Decision Latency:** `{scalability['mean_decision_latency_ms']:.4f} ms`\n")
            f.write(f"* **Max Decision Latency:** `{scalability['max_decision_latency_ms']:.4f} ms`\n")
            f.write(f"* **Throughput Performance:** `{scalability['system_throughput_sessions_per_sec']:.2f} sessions/sec`\n")
            f.write(f"* **Total Execution Duration:** `{scalability['total_execution_duration_sec']:.4f} s`\n")

        print(f"[+] SUCCESS: Benchmark completed. Report generated at: {report_path}")

    finally:
        db.close()

if __name__ == "__main__":
    main()