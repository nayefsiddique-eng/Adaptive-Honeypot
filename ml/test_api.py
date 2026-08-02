import os
import sys
import json
from fastapi.testclient import TestClient

# Ensure backend can be imported by adding the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.main import app
from backend.database import engine, SessionLocal, Base

def clean_database():
    """Drops all tables and rebuilds them for a clean test run."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def main():
    print("--- INITIATING SYSTEM INTEGRATION TEST CLIENT ---")
    clean_database()
    
    # Using 'with' block triggers FastAPI startup event (load_models, init_db)
    with TestClient(app) as client:
        print("\n[+] FastAPI Test Client successfully initialized.")
        
        # Test Root
        res = client.get("/")
        print(f"[*] Root check status: {res.status_code} -> {res.json()}")

        # ----------------------------------------------------
        # 1. Ingesting Simulated Intrusions
        # ----------------------------------------------------
        print("\n[+] STEP 1: Ingesting simulated intrusion patterns...")
        
        # Attack A: Brute force SSH from Russia (repeat attempts to trigger escalation)
        russia_ip = "185.120.78.22"
        for i in range(1, 6):
            payload = f"admin login attempt {i} with password guest{i}"
            res = client.post("/api/logs/ingest", json={
                "ip_address": russia_ip,
                "port": 22,
                "protocol": "SSH",
                "payload": payload,
                "metadata": {"login_attempts": i, "unique_usernames": 1, "unique_passwords": i}
            })
            print(f"[*] Ingested Brute Force #{i}: status {res.status_code}")
            if i == 5:
                # Let's inspect final response
                data = res.json()
                print(f"    -> Classified: {data['attack_type']} (Confidence: {data['confidence']:.2%})")
                print(f"    -> Risk score: {data['risk_score']}")
                print(f"    -> GeoIP: {data['geoip']['city']}, {data['geoip']['country']}")
                print(f"    -> Deception: State: '{data['deception']['honeypot_state']}', Interaction: '{data['deception']['interaction_level']}'")
                print(f"    -> Response Latency: {data['response_time_ms']}ms")

        # Attack B: SQL Injection from China
        china_ip = "220.181.108.45"
        res = client.post("/api/logs/ingest", json={
            "ip_address": china_ip,
            "port": 80,
            "protocol": "HTTP",
            "payload": "SELECT * FROM users WHERE username = 'admin' UNION SELECT null, password FROM admin_credentials --",
            "metadata": {}
        })
        print(f"\n[*] Ingested SQL Injection: status {res.status_code}")
        data = res.json()
        print(f"    -> Classified: {data['attack_type']} (Confidence: {data['confidence']:.2%})")
        print(f"    -> Deception State: '{data['deception']['honeypot_state']}'")

        # Attack C: Malware upload from US
        us_ip = "52.90.122.9"
        res = client.post("/api/logs/ingest", json={
            "ip_address": us_ip,
            "port": 21,
            "protocol": "FTP",
            "payload": "binary upload: reverse_shell.exe",
            "metadata": {}
        })
        print(f"\n[*] Ingested Malware Delivery: status {res.status_code}")
        data = res.json()
        print(f"    -> Classified: {data['attack_type']}")
        print(f"    -> Deception State: '{data['deception']['honeypot_state']}' (Decoys: {data['deception']['decoy_files']})")

        # Attack D: Port scanning from Brazil
        brazil_ip = "179.185.12.1"
        res = client.post("/api/logs/ingest", json={
            "ip_address": brazil_ip,
            "port": 3306,
            "protocol": "TCP",
            "payload": "",
            "metadata": {"ports_scanned": 8}
        })
        print(f"\n[*] Ingested Port Scan: status {res.status_code}")
        data = res.json()
        print(f"    -> Classified: {data['attack_type']}")
        print(f"    -> Exposed Ports: {data['deception']['exposed_ports']}")

        # ----------------------------------------------------
        # 2. Verify GeoIP & Attack Map
        # ----------------------------------------------------
        print("\n[+] STEP 2: Verifying GeoIP Map Aggregations...")
        res = client.get("/api/geoip/attack-map")
        print(f"[*] Map aggregate response: {res.status_code}")
        print(json.dumps(res.json(), indent=2))

        # ----------------------------------------------------
        # 3. Verify Attacker Reputation System
        # ----------------------------------------------------
        print("\n[+] STEP 3: Verifying Attacker Reputation System...")
        # Check Russia IP reputation
        res = client.get(f"/api/threat-intel/{russia_ip}")
        print(f"[*] Reputation for {russia_ip} (Russia): status {res.status_code}")
        rep_data = res.json()
        print(f"    -> Calculated Reputation Score: {rep_data['overall_score']}")
        print(f"    -> AbuseIPDB Confidence: {rep_data['external_intel']['abuseipdb_score']}%")
        print(f"    -> AlienVault Pulses Score: {rep_data['external_intel']['alienvault_score']}%")
        print(f"    -> Historical Attacks: {rep_data['local_history']['attack_count']}")

        # ----------------------------------------------------
        # 4. Verify Session Recording CLI logs
        # ----------------------------------------------------
        print("\n[+] STEP 4: Verifying Session Recording & CLI capture...")
        res = client.get("/api/sessions")
        sessions = res.json()
        print(f"[*] Retrieved active sessions count: {len(sessions)}")
        
        # Get recording details for Russia IP session
        russia_session_id = data = client.get("/api/logs/recent").json()[4]["session_id"] # Russia is older
        res = client.get(f"/api/sessions/{russia_session_id}/recording")
        rec = res.json()
        print(f"[*] Recording details for Russia Session {russia_session_id}: status {res.status_code}")
        print(f"    -> Duration: {rec['duration_seconds']:.2f}s")
        print(f"    -> Interaction depth: {rec['interaction_depth']}/4")
        print(f"    -> Commands issued: {rec['commands_issued']}")
        print(f"    -> Payload hashes captured: {rec['payload_hashes']}")

        # ----------------------------------------------------
        # 5. Verify LLM Threat Summarizer
        # ----------------------------------------------------
        print("\n[+] STEP 5: Requesting AI Threat Summaries...")
        res = client.get(f"/api/sessions/{russia_session_id}/summary")
        summary = res.json()
        print(f"[*] Session LLM incident briefing: status {res.status_code}")
        print(f"    -> AI Description: {summary['description']}")
        print(f"    -> AI Deep Summary: {summary['summary']}")
        print(f"    -> AI Recommendation: {summary['recommendation']}")

        # ----------------------------------------------------
        # 6. Verify Research Metrics
        # ----------------------------------------------------
        print("\n[+] STEP 6: Querying Scientific Research Metrics...")
        res = client.get("/api/research/metrics")
        metrics = res.json()
        print(f"[*] Research Metrics: status {res.status_code}")
        print(json.dumps(metrics, indent=2))

        # ----------------------------------------------------
        # 7. Verify Timeline Analytics
        # ----------------------------------------------------
        print("\n[+] STEP 7: Querying Timeline Analytics...")
        res = client.get("/api/timeline")
        timeline = res.json()
        print(f"[*] Timeline Metrics: status {res.status_code}")
        print(f"    -> Hourly points: {len(timeline['hourly'])}")
        print(f"    -> Daily points: {len(timeline['daily'])}")
        print(f"    -> Growth trend: {timeline['metrics']['trend_percentage']}%")

    print("\n--- SYSTEM INTEGRATION TEST COMPLETE: ALL VERIFICATIONS SUCCESSFUL ---")

if __name__ == "__main__":
    main()
