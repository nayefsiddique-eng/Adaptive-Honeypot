import requests
import time
import statistics

BASE_URL = "http://127.0.0.1:8000"

def test_negative_scenarios():
    print("--- SCENARIO 1: RESETTING ENVIRONMENT ---")
    reset_res = requests.post(f"{BASE_URL}/api/demo/reset")
    print(f"[+] Reset Response: {reset_res.status_code} -> {reset_res.json()}")

    print("\n--- SCENARIO 2: EMPTY STATE DATA CONSISTENCY ---")
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    sessions = requests.get(f"{BASE_URL}/api/sessions").json()
    logs = requests.get(f"{BASE_URL}/api/logs").json()
    research = requests.get(f"{BASE_URL}/api/research/metrics").json()
    
    print(f"[*] Dashboard Log Count: {dash.get('total_attacks', 0)}")
    print(f"[*] Session List Count: {len(sessions)}")
    print(f"[*] Raw Logs List Count: {len(logs)}")
    print(f"[*] Research Metric Log Count: {research.get('total_attacks', 0)}")
    
    # Assert consistency at empty state
    assert dash.get('total_attacks', 0) == 0
    assert len(sessions) == 0
    assert len(logs) == 0
    print("[OK] Empty state consistency check passed.")

    print("\n--- SCENARIO 3: TRIGGER DEMO INGESTION PIPELINE ---")
    t0 = time.time()
    start_res = requests.post(f"{BASE_URL}/api/demo/start")
    latency = time.time() - t0
    print(f"[+] Demo Ingestion completed in {latency:.2f} seconds. Code: {start_res.status_code}")
    assert start_res.status_code == 200

    print("\n--- SCENARIO 4: POPULATED STATE DATA CONSISTENCY ---")
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    sessions = requests.get(f"{BASE_URL}/api/sessions").json()
    logs = requests.get(f"{BASE_URL}/api/logs").json()
    research = requests.get(f"{BASE_URL}/api/research/metrics").json()
    
    print(f"[*] Dashboard Log Count: {dash.get('total_attacks', 0)}")
    print(f"[*] Session List Count: {len(sessions)}")
    print(f"[*] Raw Logs List Count: {len(logs)}")
    print(f"[*] Research Metric Log Count: {research.get('total_attacks', 0)}")
    
    # Assert consistency on populated state
    db_total = dash.get('total_attacks', 0)
    assert db_total > 0
    assert len(logs) == db_total
    print("[OK] Populated state consistency check passed.")

    print("\n--- SCENARIO 5: LATENCY BENCHMARKS ---")
    latencies = []
    for _ in range(10):
        t_start = time.time()
        requests.get(f"{BASE_URL}/api/dashboard")
        latencies.append((time.time() - t_start) * 1000)
    avg_l = statistics.mean(latencies)
    peak_l = max(latencies)
    print(f"[OK] Average Dashboard API Latency: {avg_l:.2f} ms")
    print(f"[OK] Peak Dashboard API Latency: {peak_l:.2f} ms")

if __name__ == "__main__":
    test_negative_scenarios()
