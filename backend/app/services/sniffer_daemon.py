import socket
import sys
import logging
import asyncio
import time
import struct
import random
from typing import Callable

# Import our modular layer parsers
from app.parsers.ethernet import parse_ethernet_frame
from app.parsers.ipv4 import parse_ipv4_packet
from app.parsers.tcp import parse_tcp_segment
# Import your existing Layer 7 protocols
from app.parsers.protocols.dns import parse_dns_packet
from app.parsers.protocols.http import deep_parse_http

logger = logging.getLogger("NetSentinelSniffer")

class SnifferDaemon:
    def __init__(self, interface: str = "eth0", simulate: bool = True):
        self.interface = interface
        self.sock = None
        self.running = False
        self.simulate = simulate  # Toggles automated background mock fallback generation

    def init_raw_socket(self):
        """Initializes a low-level raw network socket on Linux/WSL."""
        if self.simulate:
            logger.info("[+] Sniffer running in EVALUATION/SIMULATION mode. Bypassing hardware hooks.")
            return

        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            self.sock.bind((self.interface, 0))
            self.sock.setblocking(False)
            logger.info(f"[+] Raw socket successfully bound to interface: {self.interface}")
        except PermissionError:
            logger.critical("[-] Permission Denied! Run with sudo privileges.")
            sys.exit(1)
        except Exception as e:
            logger.critical(f"[-] Failed to bind raw socket interface: {e}. Falling back to simulation.")
            self.simulate = True

    async def _generate_mock_traffic(self, broadcast_callback: Callable[[dict], None]):
        """Generates mock realistic network metrics packets for evaluation telemetry."""
        mock_domains = ["google.com", "github.com", "security-threat-intel.io", "api.netsentinel.internal"]
        mock_ips = ["192.168.1.50", "10.0.0.12", "8.8.8.8", "142.250.190.46"]
        
        while self.running:
            await asyncio.sleep(random.uniform(0.5, 1.5)) # Simulates burst spacing
            
            proto_choice = random.choice(["HTTP", "DNS", "RAW"])
            src_ip = random.choice(mock_ips)
            dst_ip = random.choice(mock_ips) if src_ip != mock_ips[0] else "34.117.230.8"
            
            timestamp_str = f"{time.strftime('%Y-%m-%dT%H:%M:%S')}.{int(time.time()*1000)%1000:03d}Z"
            
            if proto_choice == "HTTP":
                app_layer = {
                    "protocol_parsed": "HTTP",
                    "http_method": random.choice(["GET", "POST"]),
                    "http_path": random.choice(["/api/v1/login", "/index.html", "/assets/dash.js"]),
                    "http_host": "netsentinel-dashboard.io"
                }
                trans_layer = {"protocol": "TCP", "source_port": random.randint(49152, 65535), "destination_port": 80}
            elif proto_choice == "DNS":
                app_layer = {
                    "protocol_parsed": "DNS",
                    "transaction_id": hex(random.randint(4000, 60000)).upper(),
                    "dns_type": "QUERY",
                    "queries": [{"domain": random.choice(mock_domains), "type": "A"}]
                }
                trans_layer = {"protocol": "UDP", "source_port": random.randint(49152, 65535), "destination_port": 53}
            else:
                app_layer = {"protocol_parsed": "RAW"}
                trans_layer = {"protocol": random.choice(["TCP", "UDP"]), "source_port": 443, "destination_port": 51220}

            structured_packet = {
                "timestamp": timestamp_str,
                "network_layer": {
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": trans_layer["protocol"],
                    "version": 4
                },
                "transport_layer": trans_layer,
                "frame_metadata": {
                    "frame_len": random.randint(64, 1518),
                    "interface": "mock-adapter"
                },
                "application_layer": app_layer
            }
            
            await broadcast_callback(structured_packet)

    async def start_capture_loop(self, broadcast_callback: Callable[[dict], None]):
        """Asynchronously monitors network layer streams or generates mock loops."""
        self.init_raw_socket()
        self.running = True

        if self.simulate:
            # Run the clean evaluation loop safely
            await self._generate_mock_traffic(broadcast_callback)
            return

        loop = asyncio.get_event_loop()
        logger.info("[+] Live pipeline packet processing thread initiated.")

        while self.running:
            try:
                raw_packet_bytes = await loop.sock_recv(self.sock, 65535)
                frame_len = len(raw_packet_bytes)

                if frame_len == 0:
                    continue

                # 1. Parse Layer 2 (Ethernet Frame)
                l2_meta, l3_payload = parse_ethernet_frame(raw_packet_bytes)
                
                # 2. Parse Layer 3 (IPv4 Packet)
                l3_meta, l4_payload = parse_ipv4_packet(l3_payload)
                
                # 3. Handle Transport & Deep L7 Layers
                l4_meta = {}
                app_layer_data = {"protocol_parsed": "RAW"}
                transport_protocol = l3_meta.get("protocol")
                
                if transport_protocol == "TCP":
                    l4_meta, l7_payload = parse_tcp_segment(l4_payload)
                    src_port = l4_meta.get("source_port")
                    dst_port = l4_meta.get("destination_port")
                    
                    if 80 in (dst_port, src_port):
                        http_res = deep_parse_http(l7_payload)
                        app_layer_data = http_res if http_res else {"protocol_parsed": "HTTP"}
                    elif 53 in (dst_port, src_port):
                        app_layer_data = parse_dns_packet(l7_payload)

                elif transport_protocol == "UDP" and len(l4_payload) >= 8:
                    src_port, dst_port = struct.unpack('! H H', l4_payload[:4])
                    l4_meta = {"protocol": "UDP", "source_port": src_port, "destination_port": dst_port}
                    l7_payload = l4_payload[8:]
                    
                    if 53 in (dst_port, src_port):
                        app_layer_data = parse_dns_packet(l7_payload)

                timestamp_str = f"{time.strftime('%Y-%m-%dT%H:%M:%S')}.{int(time.time()*1000)%1000:03d}Z"
                structured_packet = {
                    "timestamp": timestamp_str,
                    "network_layer": l3_meta,
                    "transport_layer": l4_meta,
                    "frame_metadata": {"frame_len": frame_len, "interface": self.interface},
                    "application_layer": app_layer_data
                }

                await broadcast_callback(structured_packet)

            except Exception as loop_err:
                logger.error(f"[-] Core processing pipeline parsing fault: {loop_err}")
                await asyncio.sleep(0.1)

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
