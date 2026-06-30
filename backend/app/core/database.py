import os
from motor.motor_asyncio import AsyncIOMotorClient

# Pull the URI from environment variables or fall back to localhost for native debugging
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")

# Instantiate a non-blocking connection pool
client = AsyncIOMotorClient(MONGO_URI)

# Bind specifically to the netsentinel document database cluster
db = client.netsentinel

async def get_database():
    """Dependency provider hook for FastAPI router endpoints."""
    return db

async def check_database_health():
    """Verifies connection health status during initial cluster startup."""
    try:
        # Trigger a simple administrative command to check connection
        await client.admin.command('ping')
        print("[+] MongoDB Connection Pool initialized successfully.")
        return True
    except Exception as e:
        print(f"[-] MongoDB Connection Failure: {e}")
        return False
