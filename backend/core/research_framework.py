import time
import statistics
from typing import Dict, Any
from sqlalchemy.orm import Session

class PRAETORResearchFramework:
    """
    Benchmarking utility for the PRAETOR platform's live decision path.
    """
    def __init__(self, db: Session):
        self.db = db

    def run_scalability_stress_test(self, session_count: int = 100) -> Dict[str, Any]:
        """
        Measures processing latency, throughput, and system stability under load.
        """
        from backend.core.cooperative_rl_engine import choose_rl_action
        latencies = []
        start_time = time.perf_counter()

        for i in range(session_count):
            step_start = time.perf_counter()
            # Execute the actual CMARL coordination decision path
            choose_rl_action(self.db, "brute_force", i + 1, "medium")
            latencies.append((time.perf_counter() - step_start) * 1000.0)

        total_duration = time.perf_counter() - start_time
        throughput = session_count / total_duration

        return {
            "sessions_processed": session_count,
            "mean_decision_latency_ms": round(statistics.mean(latencies), 4),
            "max_decision_latency_ms": round(max(latencies), 4),
            "system_throughput_sessions_per_sec": round(throughput, 2),
            "total_execution_duration_sec": round(total_duration, 4)
        }