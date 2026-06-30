import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response
from fastapi.middleware.cors import CORSMiddleware
from bson import ObjectId

# Direct clean internal relative imports matching your project structure
from app.core.database import check_database_health, db

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles microservice application context lifecycles.
    Ensures MongoDB cluster availability prior to accepting network telemetry streams.
    """
    print("[*] NetSentinel Engine boot sequence initiated...")
    is_healthy = await check_database_health()
    if not is_healthy:
        print("[🚨] CRITICAL: System proceeding without active MongoDB data layers!")
    else:
        print("[+] Core Persistence Engine successfully mounted to lifespan state loop.")
    yield
    print("[-] NetSentinel Engine safe shutdown completed.")

# Instantiate main application app framework wrapped in lifecycle manager
app = FastAPI(
    title="NetSentinel // Network Intrusion & Threat Capture Backend",
    version="1.0.0",
    lifespan=lifespan
)

# Configure Cross-Origin Resource Sharing (CORS) rules for decoupling the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits rapid cross-environment network container mapping transitions
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    """Manages active live streaming frontend state connections."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[+] Broadcast Hub channel bound. Total Clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print(f"[-] Broadcast Hub channel torn down. Total Clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Dispatches telemetry data packet payloads simultaneously to all open tabs."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Silently catch and prune stale connections handled inside disconnect blocks
                pass

manager = ConnectionManager()

def serialize_mongodb_document(doc: dict) -> dict:
    """Helper formatting script converting native BSON ObjectIds to clean JSON safe string strings."""
    if not doc:
        return {}
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """
    Catch-all route to handle generic browser asset checks without throwing 500 errors.
    """
    return Response(status_code=204)

@app.get("/api/packets/stats")
async def get_packet_aggregates():
    """
    Aggregates real-time baseline structural metrics straight out of MongoDB.
    Feeds metric tiles on dashboard reload initialization.
    """
    try:
        total = await db.packets.count_documents({})
        http_count = await db.packets.count_documents({"application_layer.protocol_parsed": "HTTP"})
        dns_count = await db.packets.count_documents({"application_layer.protocol_parsed": "DNS"})

        # Pull distinct counts of flagged items processed directly by the Unsupervised AI microservice
        anomalies = await db.packets.count_documents({"is_anomaly": True})

        return {
            "total_analyzed": total,
            "application_layer": {
                "HTTP": http_count,
                "DNS": dns_count,
                "RAW": max(0, total - (http_count + dns_count))
            },
            "ai_anomalies": anomalies
        }
    except Exception as e:
        return {"error": f"Failed to compute operational metrics database aggregates: {str(e)}"}

@app.websocket("/api/packets/stream")
async def websocket_telemetry_stream(websocket: WebSocket):
    """
    Main real-time broadcast engine socket pipeline route.
    Tails the dynamic document arrays stored by Scapy/Kafka and sends them straight to the D3 canvas.
    """
    await manager.connect(websocket)

    # Store cursor location reference marker using ObjectIds to stream sequentially
    last_processed_id = None

    try:
        while True:
            query = {}
            if last_processed_id:
                query["_id"] = {"$gt": ObjectId(last_processed_id)}

            # Fetch batches of newly recorded documents sorted sequentially
            cursor = db.packets.find(query).sort("_id", 1).limit(20)

            has_data = False
            async for document in cursor:
                has_data = True
                serialized_packet = serialize_mongodb_document(document)
                last_processed_id = serialized_packet["_id"]

                # Push the data frame immediately down to the client layout
                await websocket.send_json(serialized_packet)

            # Adaptive sleep tuning: sleep longer if network is idle, loop instantly if traffic bursts
            if not has_data:
                await asyncio.sleep(0.5)
            else:
                await asyncio.sleep(0.05)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[🚨] WebSocket loop context rupture: {e}")
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    # 0.0.0.0 breaks out of the container's isolated local loopback to accept outside host requests
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
