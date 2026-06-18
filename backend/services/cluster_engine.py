import numpy as np
from sqlalchemy.orm import Session
from sqlalchemy import func
from sklearn.cluster import KMeans
from typing import Dict, Any, List
from backend.models.attack import AttackLog

def cluster_attacker_ips(db: Session) -> Dict[str, Any]:
    """
    Retrieves attacker profiles from the database and clusters them into 4 categories
    using K-Means clustering based on behavioral features.
    """
    # Query distinct IP addresses
    ips = db.query(AttackLog.ip_address).distinct().all()
    ips = [ip[0] for ip in ips]

    if len(ips) <= 5:
        return {"status": "insufficient_data"}

    # Extract behavioral features for each IP
    profiles = []
    ip_list = []
    
    for ip in ips:
        logs = db.query(AttackLog).filter(AttackLog.ip_address == ip).all()
        attack_count = len(logs)
        avg_risk = sum(l.risk_score for l in logs) / attack_count if attack_count > 0 else 0.0
        unique_types = len(set(l.attack_type for l in logs))
        
        ports_scanned_total = 0
        login_attempts_total = 0
        
        for l in logs:
            feat = l.features or {}
            ports_scanned_total += feat.get("ports_scanned", 0)
            login_attempts_total += feat.get("login_attempts", 0)
            
        profiles.append([
            float(attack_count),
            float(avg_risk),
            float(unique_types),
            float(ports_scanned_total),
            float(login_attempts_total)
        ])
        ip_list.append(ip)

    X = np.array(profiles)

    # Run K-Means with 4 clusters
    n_clusters = 4
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = kmeans.fit_predict(X)
    centroids = kmeans.cluster_centers_

    # Sort cluster centroids by activity score to map labels deterministically
    # Activity score: weighted combination of attack count, risk, unique types, ports, and login attempts
    centroid_scores = []
    for idx, c in enumerate(centroids):
        # c = [attack_count, avg_risk, unique_types, ports_scanned, login_attempts]
        score = c[0] * 10.0 + c[1] * 2.0 + c[2] * 5.0 + c[3] * 1.0 + c[4] * 1.0
        centroid_scores.append((score, idx))
        
    centroid_scores.sort() # Sort ascending (lowest activity to highest activity)

    label_names = ["script_kiddie", "opportunist", "targeted", "advanced_persistent"]
    idx_to_label = {score_info[1]: label_names[i] for i, score_info in enumerate(centroid_scores)}

    # Map each attacker IP to its cluster label and details
    result_list = []
    for idx, ip in enumerate(ip_list):
        cluster_idx = labels[idx]
        result_list.append({
            "ip": ip,
            "cluster_label": idx_to_label[cluster_idx],
            "feature_vector": [int(X[idx][0]), round(X[idx][1], 2), int(X[idx][2]), int(X[idx][3]), int(X[idx][4])]
        })
        
    return {
        "status": "success",
        "clusters": result_list
    }
