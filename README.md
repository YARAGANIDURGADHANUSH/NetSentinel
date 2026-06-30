NetSentinel v1.0.0
An asynchronous, low-level real-time network security inspection tool engineered to sniff, dissect, and visualize network packets directly from Linux kernel ring buffers.

NetSentinel bypasses high-level capture utilities (such as Scapy or PyShark) by opening raw AF_PACKET sockets directly. It utilizes custom-built binary bit-shifting parsers to extract network telemetry down to the application layer, broadcasting metrics instantly over WebSockets to a responsive web dashboard.

🏗️ System Architecture
The application is modularly split into a high-performance processing backend and a real-time reactive streaming frontend:

Plaintext
netsentinel/
├── backend/
│   ├── app/
│   │   ├── core/           # Database and application configuration
│   │   ├── parsers/        # Custom binary L2/L3/L4/L7 bit-parsers
│   │   │   └── protocols/  # Deep L7 App-Layer decoders (DNS, HTTP)
│   │   ├── services/       # Sniffer background daemon loops
│   │   └── main.py         # FastAPI WebSocket & REST API Engine
│   └── data/               # Persistent SQLite storage volumes
└── frontend/               # React / Tailwind CSS Dashboard 
🔁 The Data Pipeline
Kernel Ingestion: The background SnifferDaemon initiates an AF_PACKET raw socket, capturing raw Ethernet frames directly from the interface card.

Modular Decoding: The packet bytes pass sequentially through the parsing chain:

Layer 2 (Ethernet): Extracts MAC addresses and identifies the EtherType.

Layer 3 (IPv4): Extracts Source/Destination IPs and unmasks the underlying Protocol ID.

Layer 4 (TCP/UDP): Strips transport headers to isolate Source/Destination ports and TCP control flags.

Layer 7 (Application): Performs deep string-matching and label-unpacking to extract HTTP methods/status keys and DNS domain requests.

Async Distribution: Processed frames are concurrently pushed to an active WebSocket connection pool and safely batched off-thread into an SQLite database.

🛠️ Technical Highlights & Implementation Details
Raw Sockets Over High-Level Tools: Engineered raw socket ingestion using standard Python socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)), minimizing translation overhead.

Binary Dissection: Utilizes Python's native struct library to decode networking headers byte-for-byte based on standard RFC network specifications.

Non-Blocking Asynchronous Concurrency: Leverages FastAPI's event loops (loop.sock_recv) to ingest packet sequences smoothly without bottlenecking HTTP REST routes or crashing streaming browser sessions.

Persistent Telemetry: Includes built-in database indexing using thread-safe SQLite bindings to ensure packet histories are safely saved across sessions.

Triage Analysis Control: Frontend includes live stream pausing and targeted application protocol filtering (HTTP, DNS, RAW) to help security analysts effectively isolate network noise.

🚀 Getting Started (Deployment Manual)
Prerequisites
Operating System: Linux or Windows Subsystem for Linux (WSL2) with administrative elevations.

Python Runtime: Python 3.12+

Node Runtime: Node.js v18+

1. Backend Service Launch
Navigate to the backend module, create your virtual environment, install the framework dependencies, and boot the Uvicorn thread coordinator using administrative sudo privileges (required to bind raw packet network interfaces):

Bash
cd backend
# Run from the backend directory using your workspace venv binary
sudo app/venv/bin/python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
💡 Note: If the terminal reports [Errno 100] Network is down, force your virtual adapter card online in a parallel shell using sudo ip link set eth0 up.

2. Frontend Interface Launch
Open a parallel shell, navigate to the frontend directory, install web modules, and spin up the user interface layer:

Bash
cd frontend
npm install
npm start
Open your browser and navigate to http://localhost:3000 to monitor live incoming traffic.
