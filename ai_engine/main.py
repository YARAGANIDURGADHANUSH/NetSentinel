import os
import time
import numpy as np
from pymongo import MongoClient
from sklearn.ensemble import IsolationForest

# Fallback configurations for Docker orchestration setups
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/netsentinel")
client = MongoClient(MONGO_URI)
db = client.get_default_database()

print("[+] NetSentinel Unsupervised AI Analytics Core Online.")

def extract_vector(packet):
    """Transforms a raw MongoDB packet document into a high-dimensional vector."""
    try:
        size = packet.get("frame_metadata", {}).get("frame_len", packet.get("size", 64))
        
        # Numeric Protocol Encoding Mapping
        l4_proto = packet.get("transport_layer", {}).get("protocol", "UNKNOWN")
        l4_encoded = 1 if l4_proto == "TCP" else (2 if l4_proto == "UDP" else 0)
        
        l7_proto = packet.get("application_layer", {}).get("protocol_parsed", "RAW")
        l7_encoded = 1 if l7_proto == "HTTP" else (2 if l7_proto == "DNS" else 0)
        
        src_port = packet.get("transport_layer", {}).get("source_port", 0) or 0
        dst_port = packet.get("transport_layer", {}).get("destination_port", 0) or 0
        
        return [float(size), float(l4_encoded), float(l7_encoded), float(src_port), float(dst_port)]
    except Exception:
        return [64.0, 0.0, 0.0, 0.0, 0.0]

def run_anomaly_detection_pipeline():
    while True:
        # Pull latest unanalyzed packets from MongoDB documents
        cursor = db.packets.find({"ai_analyzed": {"$exists": False}}).limit(100)
        packets = list(cursor)
        
        if len(packets) < 10:
            # Need a baseline array footprint to perform vector analytics evaluations
            time.sleep(2)
            continue
            
        vectors = [extract_vector(p) for p in packets]
        X = np.array(vectors)
        
        # Deploy Unsupervised Isolation Forest Model (Contamination set to ~5% alert threshold)
        clf = IsolationForest(contamination=0.05, random_state=42)
        predictions = clf.fit_predict(X)
        
        for idx, packet in enumerate(packets):
            is_anomaly = True if predictions[idx] == -1 else False
            update_payload = {
                "$set": {
                    "ai_analyzed": True,
                    "is_anomaly": is_anomaly
                }
            }
            
            # Dynamic document fields based on structural threat characteristics
            if is_anomaly:
                dst_port = vectors[idx][4]
                if dst_port in [22, 23, 445]:
                    update_payload["$set"]["anomaly_metadata"] = {
                        "threat_type": "Reconnaissance Attack Vector",
                        "severity": "CRITICAL",
                        "flagged_feature": f"Suspicious activity targeted towards infrastructural port {int(dst_port)}"
                    }
                else:
                    update_payload["$set"]["anomaly_metadata"] = {
                        "threat_type": "Micro-Anomaly Volume Spike",
                        "severity": "MEDIUM",
                        "flagged_feature": "Outlier identified in structural packet size array profiles"
                    }
            
            db.packets.update_one({"_id": packet["_id"]}, update_payload)
            
        print(f"[ AI ] Successfully parsed vector metrics batch array. Size: {len(packets)}")
        time.sleep(1)

if __name__ == "__main__":
    run_anomaly_detection_pipeline()
