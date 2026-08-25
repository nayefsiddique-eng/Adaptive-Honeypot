# PRAETOR Production Deployment Guide

This document describes the recommended topologies, host constraints, network configurations, and host-level firewall policies required to run the PRAETOR platform in a production-isolated environment.

---

## 1. Plane Segmentation Topology

To ensure security boundaries are maintained under active adversarial interaction, the platform is divided into two planes:

1. **Attacker/Deception Plane (Untrusted DMZ):**
   * Hosts public honeypots (SSH on `2222`, HTTP on `8080`, Telnet on `2323`).
   * Has absolutely no keys, management credentials, or database files.
   * Can only communicate outwards via `POST /api/logs/ingest` to report logging telemetry.
2. **Management Plane (Trusted Network):**
   * Hosts the FastAPI endpoint (`8000`), SQLite database, dashboard, and ML/RL algorithms.
   * Bound only to localhost (`127.0.0.1`) or a secure private VPN interface on the host OS.
   * Completely unreachable from the public internet or the untrusted honeypot containers.

---

## 2. Deployment Models

### Model A: Dedicated Virtual Machines (Recommended)
This architecture provides the strongest virtualization-level isolation against potential sandbox escapes or kernel exploits.

```
       [ PUBLIC INTERNET ]
               │
      (Port 2222, 8080, 2323)
               │
               ▼
   ┌───────────────────────┐
   │      Honeypot VM      │
   │  (No secrets/DB file) │
   └───────────┬───────────┘
               │
      (Telemetry Egress ONLY)
      (Port 8000 Ingestion)
               │
               ▼
   ┌───────────────────────┐
   │     Management VM     │
   │  (API/DB/ML, Private) │
   └───────────────────────┘
```

* **Honeypot VM:** Exposed to the internet. Runs only the decoy containers.
* **Management VM:** Situated inside a private management segment. Attacker cannot route packets directly to this VM.

---

### Model B: Single-Host Network Isolated Containers
Utilizes strict Docker bridge networks to segment interfaces, bound to different routing interfaces.

```
                  PUBLIC INTERNET
                         │
                  Docker Publish
                         │
             ┌───────────▼───────────┐
             │     attacker_net      │
             └───────────┬───────────┘
                         │
             ┌───────────▼───────────┐
             │   praetor-honeypot    │
             └───────────┬───────────┘
                         │ (Read-only, tmpfs, cap_drop ALL)
             ┌───────────▼───────────┐
             │     telemetry_net     │
             └───────────┬───────────┘
                         │
             ┌───────────▼───────────┐
             │  praetor-management   │
             └───────────┬───────────┘
                         │
             ┌───────────▼───────────┐
             │    management_net     │
             └───────────┬───────────┘
                         │
             ┌───────────▼───────────┐
             │       Database        │ (sqlite, inside management plane only)
             └───────────────────────┘
```

---

## 3. Host Firewall Configuration (Example Policy)

Below is an example firewall script (`iptables`) for host-level isolation under Model B.

```bash
#!/usr/bin/env bash
# =========================================================================
# EXAMPLE FIREWALL ISOLATION RULESET FOR PRAETOR DEPLOYMENTS
# =========================================================================

# Flush existing rules
iptables -F

# Default Policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback (localhost)
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Public Ports: Allow inbound traffic to honeypots
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 2323 -j ACCEPT

# Private Ports: Bind management interface only to local VPN/specified subnet
# Replace eth1 with your internal network interface
iptables -A INPUT -i eth1 -p tcp --dport 8000 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j DROP

# Block honeypot egress to cloud metadata
# Prevents honeypots from scraping credentials from AWS/GCP metadata APIs
iptables -A FORWARD -d 169.254.169.254 -j DROP
```

---

## 4. Cloud Metadata Protection

Honeypots must explicitly be blocked from reaching cloud instance metadata directories.
* **AWS/GCP/OpenStack Metadata IP:** `169.254.169.254`
* Ensure the Docker bridge configuration blocks this route or configure an outbound routing rule in your Cloud Security Group.
