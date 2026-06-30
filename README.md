# NetSentinel: AI-Powered Network Intrusion & Cyber Threat Visualizer

NetSentinel is a real-time, high-density cyber threat monitoring workspace. Moving past static, rule-based firewall boundaries, it deploys unsupervised deep learning architectures to detect subtle micro-anomalies within massive, high-dimensional live network traffic data arrays.

## 📡 Engineering Architecture Overview

The system operates across three decoupled, high-performance layers:

1. **The AI Core Layer:** Utilizes unsupervised machine learning configurations (Isolation Forests / Autoencoders) to isolate anomalies based on multivariant packet features, network payloads, and entropy profiles.
2. **The Backend Streaming Engine:** Built with Python (FastAPI, Scapy, Asyncio), featuring multi-threaded ring buffers designed to capture, parse, and queue active transport layers without dropping frames. Persistent data attributes map directly to non-relational document sets in MongoDB.
3. **The Full-Stack HUD Interface:** A zero-scroll, high-density React monitoring workspace featuring a live infrastructure topology map driven by D3.js force simulations that dynamically visually isolate target infiltration paths in real time.

---

## 🛠️ Technology Stack & Pipeline Components

### Core Infrastructure
* **Frontend:** React.js, Tailwind CSS, D3.js (Data-Driven Documents)
* **Backend API:** Python 3.10+, FastAPI, WebSockets
* **Traffic Ingestion:** Scapy (Raw Packet Socket Capture Daemon)
* **Data Layer:** MongoDB (Dynamic Dynamic Fields Schema Tracking)
* **DevSecOps:** Docker, Docker-Compose, Kubernetes (Network Isolation Profiles)

### Protocol Parsing Coverage
* **Layer 4 (Transport):** Complete State tracking for TCP Flags (SYN/ACK sequences), UDP Datagrams, and associated Port Bounds.
* **Layer 7 (Application - HTTP):** Plaintext ASCII frame reconstructor, URL parsing path tracking, header field normalization, and metadata isolation hooks.
* **Layer 7 (Application - DNS):** RFC 1035 Domain Variable Bit-Unpacker featuring recursive pointer-jumping verification guards and **Statistical Shannon Entropy Calculation** to neutralize DGA and data-exfiltration vectors.

---

## 🚀 Quick Start Deployment Guide

Ensure you have Docker and Docker-Compose installed on your local environment.

### 1. Clone the Workspace Repository
```bash
git clone [https://github.com/YARAGANIDURGADHANUSH/NetSentinel.git](https://github.com/YARAGANIDURGADHANUSH/NetSentinel.git)
cd NetSentinel
2. Build and Launch the Orchestrated Multi-Container Stack
Bash
docker-compose up --build
This single command spins up:

The FastAPI streaming socket daemon backend on port 8000

The high-density React telemetry UI dashboard engine on port 3001

An isolated local MongoDB persistence layer instance

3. Access the Live Management Control HUD
Open your browser and navigate to:

http://localhost:3001
Click the 🧪 RUN DIAGNOSTIC TEST FRAME in the upper menu layer to immediately inject mock telemetry vectors and monitor interactive system alerts.

🔒 Security & Multi-Threading Integrity Guardrails
Non-Blocking Ingestion: The ingestion engine leverages thread-safe shared-memory collections.deque structures locked at a rigid 10,000 capacity ceiling to eliminate application lag and kernel socket drop exceptions during high-frequency scans.

Cyclic Pointer Defenses: The customized DNS label reader actively enforces an anti-loop boundary rule limit (max_jumps = 5) to cleanly strip malicious compressed exploit strings before they can lock system worker threads.


---

### 📤 How to update your README on GitHub

Run this last set of commands in your project terminal to save your documentation:

```bash
# 1. Stage the new README file
git add README.md

# 2. Commit the change
git commit -m "docs: finalize professional portfolio README with system quickstart blueprints"

# 3. Push to your live repo
git push origin main
