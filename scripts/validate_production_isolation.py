#!/usr/bin/env python
"""
Production Isolation Validation Script for PRAETOR.
Audits the docker-compose configuration and environment files to verify compliance
with plane separation and container hardening requirements.
"""

import os
import sys

def check_docker_compose():
    compose_path = "docker-compose.prod.yml"
    if not os.path.exists(compose_path):
        print(f"[-] ERROR: {compose_path} not found.")
        return False

    print(f"[*] Auditing {compose_path}...")
    with open(compose_path, "r") as f:
        content = f.read()

    passed = True

    # 1. Check network mode host
    if "network_mode: host" in content or "network_mode: \"host\"" in content:
        print("[-] FAIL: Host networking is enabled. Attacker container must not run in network_mode host.")
        passed = False
    else:
        print("[+] PASS: Host networking is disabled.")

    # 2. Check privileged containers
    if "privileged: true" in content or "privileged: \"true\"" in content:
        print("[-] FAIL: Privileged container mode enabled.")
        passed = False
    else:
        print("[+] PASS: Privileged container mode disabled.")

    # 3. Check Docker socket mounts
    if "docker.sock" in content:
        print("[-] FAIL: Docker socket (/var/run/docker.sock) is mounted.")
        passed = False
    else:
        print("[+] PASS: Docker socket is not mounted.")

    # 4. Check network planes existence
    required_nets = ["attacker_net", "telemetry_net", "management_net"]
    for net in required_nets:
        if net not in content:
            print(f"[-] FAIL: Network '{net}' is missing from compose definition.")
            passed = False
        else:
            print(f"[+] PASS: Network '{net}' is defined.")

    # 5. Check honeypot network isolation
    # Parse lines to check which networks are assigned to honeypot
    lines = content.splitlines()
    in_honeypot = False
    honeypot_nets = []
    in_mgmt = False
    mgmt_ports = []
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("praetor-honeypot:"):
            in_honeypot = True
            in_mgmt = False
        elif stripped.startswith("praetor-management:"):
            in_mgmt = True
            in_honeypot = False
        elif stripped.startswith("networks:") and in_honeypot:
            pass
        elif stripped.startswith("-") and in_honeypot:
            net_name = stripped.replace("-", "").strip()
            if net_name in required_nets:
                honeypot_nets.append(net_name)
        elif stripped.startswith("ports:") and in_mgmt:
            pass
        elif stripped.startswith("-") and in_mgmt:
            port_map = stripped.replace("-", "").replace('"', '').replace("'", "").strip()
            mgmt_ports.append(port_map)
        elif stripped and not stripped.startswith("-") and not stripped.startswith("#") and ":" in stripped and stripped.split(":")[0].strip() in ["praetor-management", "praetor-honeypot", "networks", "volumes"]:
            # exited current service block
            if stripped.split(":")[0].strip() not in ["networks", "ports"]:
                in_honeypot = False
                in_mgmt = False

    if "management_net" in honeypot_nets:
        print("[-] FAIL: Honeypot is directly connected to management_net.")
        passed = False
    else:
        print("[+] PASS: Honeypot is isolated from management_net.")

    # 6. Check management API published ports
    for p in mgmt_ports:
        if "0.0.0.0:" in p or (":" in p and len(p.split(":")) == 2 and not p.startswith("127.0.0.1")):
            print(f"[-] FAIL: Management API exposed publicly on host interface: {p}")
            passed = False
            
    if passed and mgmt_ports:
        print("[+] PASS: Management API is private or bound only to localhost interface.")

    # 7. Check honeypot container hardening (no-new-privileges, cap_drop, read_only, limits)
    if "no-new-privileges:true" not in content.replace(" ", ""):
        print("[-] FAIL: no-new-privileges option is missing for container security.")
        passed = False
    else:
        print("[+] PASS: no-new-privileges is configured.")

    if "cap_drop:" not in content.replace(" ", "") or "-ALL" not in content.replace(" ", ""):
        print("[-] FAIL: cap_drop ALL is missing.")
        passed = False
    else:
        print("[+] PASS: cap_drop ALL is configured.")

    if "read_only:true" not in content.replace(" ", ""):
        print("[-] FAIL: Container filesystem is not read-only.")
        passed = False
    else:
        print("[+] PASS: Container filesystem is read-only.")

    if "limits:" not in content.replace(" ", ""):
        print("[-] FAIL: Production resource limits are missing.")
        passed = False
    else:
        print("[+] PASS: Production resource limits are set.")

    return passed

def check_env_files():
    honeypot_env = ".env.honeypot"
    passed = True

    if not os.path.exists(honeypot_env):
        print(f"[-] ERROR: {honeypot_env} environment file not found.")
        return False

    print(f"[*] Auditing {honeypot_env}...")
    with open(honeypot_env, "r") as f:
        content = f.read()

    sensitive_keys = ["SECRET_KEY", "ADMIN_API_KEY", "MANAGEMENT_API_KEY", "DATABASE_URL"]
    for key in sensitive_keys:
        if f"{key}=" in content:
            print(f"[-] FAIL: Honeypot configuration file contains management secret: {key}")
            passed = False
            
    if passed:
        print("[+] PASS: Honeypot configuration is free of management secrets.")
        
    return passed

def main():
    print("=========================================================")
    print("   PRAETOR Production Deployment Hardening Validator   ")
    print("=========================================================")
    
    compose_ok = check_docker_compose()
    env_ok = check_env_files()
    
    if compose_ok and env_ok:
        print("\n[+] SUCCESS: Production deployment configuration is verified secure and isolated.")
        sys.exit(0)
    else:
        print("\n[-] FAILURE: Production deployment configuration has security isolation violations.")
        sys.exit(1)

if __name__ == "__main__":
    main()
