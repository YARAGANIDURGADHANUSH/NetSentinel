import os
import pickle
import numpy as np
from pymongo import MongoClient
from sklearn.ensemble import IsolationForest

def train_baseline_model():
    # Connect to your microservice database
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/netsentinel")
    client = MongoClient(MONGO_URI)
    db = client.get_default_database()
    
    print("[*] Pulling historical baseline packets for training...")
    packets = list(db.packets.find().limit(1000))
    
    # Fallback to synthetic arrays if the collection hasn't collected live frames yet
    if len(packets) < 50:
        print("[!] Insufficient data in MongoDB. Generating synthetic baseline array tracking [size, L4, L7, sport, dport]...")
        X_train = np.random.normal(loc=[128, 1, 1, 443, 80], scale=[30, 0.5, 0.5, 100, 10], size=(500, 5))
    else:
        # Vector matrix compilation
        vectors = []
        for p in packets:
            size = p.get("size", 64)
            l4 = 1 if p.get("transport_layer", {}).get("protocol") == "TCP" else 2
            l7 = 1 if p.get("application_layer", {}).get("protocol_parsed") == "HTTP" else 0
            sport = p.get("transport_layer", {}).get("source_port", 0) or 0
            dport = p.get("transport_layer", {}).get("destination_port", 0) or 0
            vectors.append([size, l4, l7, sport, dport])
        X_train = np.array(vectors)

    print(f"[*] Training Unsupervised Isolation Forest model on matrix shape: {X_train.shape}")
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X_train)
    
    # Ensure directory framework exists and serialize model artifact
    os.makedirs("models", exist_ok=True)
    with open("models/isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)
        
    print("[+] Model pipeline serialized successfully into 'models/isolation_forest.pkl'")

if __name__ == "__main__":
    train_baseline_model()
