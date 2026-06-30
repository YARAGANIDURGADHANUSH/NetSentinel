from datetime import datetime
from app.core.database import db

async def insert_live_network_packet(packet_dict: dict):
    """Inserts a structured Scapy vector into the MongoDB packets collection."""
    try:
        # Enforce baseline structure with a dynamic field fallback wrapper
        document_payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "size": packet_dict.get("size", 64),
            "network_layer": packet_dict.get("network_layer", {
                "source_ip": "0.0.0.0", 
                "destination_ip": "0.0.0.0"
            }),
            "transport_layer": packet_dict.get("transport_layer", {
                "protocol": "TCP", 
                "source_port": 0, 
                "destination_port": 0
            }),
            "application_layer": packet_dict.get("application_layer", {
                "protocol_parsed": "RAW"
            })
            # Note: 'ai_analyzed', 'is_anomaly', and 'anomaly_metadata' 
            # will be injected dynamically later by the ai_engine microservice!
        }
        
        result = await db.packets.insert_one(document_payload)
        return str(result.inserted_id)
    except Exception as e:
        print(f"[-] Failed to write network document frame to MongoDB: {e}")
        return None
