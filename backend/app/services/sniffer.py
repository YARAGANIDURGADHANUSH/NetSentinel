import socket
import struct
import sys
import argparse
import json
import os
from datetime import datetime

# --- SYSTEM PATH ALIGNMENT CRADLE ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_APP_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PARENT_APP_DIR not in sys.path:
    sys.path.append(PARENT_APP_DIR)

from utils.formatters import parse_ip_address, format_payload
from parsers.protocols.dns import deep_parse_dns
from parsers.protocols.http import deep_parse_http

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Sniffer Engine")
    parser.add_argument('--exclude-multicast', action='store_true', help="Filter out IGMP and multicast traffic")
    parser.add_argument('--filter', type=str, choices=['tcp', 'udp', 'igmp', 'icmp'], help="Filter strictly by protocol")
    parser.add_argument('--output', type=str, default='packet_log.jsonl', help="Path to save the log file")
    args = parser.parse_args()

    print("[*] Activating NetSentinel Multi-Protocol Sniffer Engine...")
    INTERFACE = "eth2"
    print(f"[*] Binding strictly to interface: {INTERFACE}")

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.bind((INTERFACE, 0))
    except PermissionError:
        print("[!] Error: Root privileges required. Run with 'sudo'.")
        sys.exit(1)

    try:
        while True:
            raw_data, addr = s.recvfrom(65565)
            if len(raw_data) < 34: continue
                
            eth_type = struct.unpack('!H', raw_data[12:14])[0]
            if eth_type != 0x0800: continue
            
            # Layer 3 IPv4 Base Parsing
            ip_header = raw_data[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            ihl = (iph[0] & 0x0F) * 4
            proto = iph[6]
            src_ip = parse_ip_address(iph[8])
            dst_ip = parse_ip_address(iph[9])
            
            src_port, dst_port, flags_list, payload = 0, 0, [], b""
            l4_offset = 14 + ihl
            
            # Layer 4 Unpacking Core
            if proto == 6:  # TCP
                tcp_header = raw_data[l4_offset : l4_offset + 20]
                if len(tcp_header) >= 20:
                    tcph = struct.unpack('!HHIIBBHHH', tcp_header)
                    src_port, dst_port = tcph[0], tcph[1]
                    data_offset = (tcph[4] >> 4) * 4
                    flags = tcph[5]
                    if flags & 0x10: flags_list.append("ACK")
                    if flags & 0x08: flags_list.append("PSH")
                    if flags & 0x02: flags_list.append("SYN")
                    if flags & 0x01: flags_list.append("FIN")
                    payload = raw_data[l4_offset + data_offset:]
                    
            elif proto == 17:  # UDP
                udp_header = raw_data[l4_offset : l4_offset + 8]
                if len(udp_header) == 8:
                    src_port, dst_port = struct.unpack('!HH', udp_header[:4])
                    payload = raw_data[l4_offset + 8:]

            # Core Execution Runtime Filters
            if args.exclude_multicast:
                first_octet = int(dst_ip.split('.')[0]) if '.' in dst_ip else 0
                if 224 <= first_octet <= 239 or proto == 2: continue
            if args.filter:
                if args.filter == 'tcp' and proto != 6: continue
                elif args.filter == 'udp' and proto != 17: continue

            # --- LAYER 7 DEEP PARSING PIPELINE ---
            dns_data = None
            http_data = None
            detected_l7_proto = "RAW"

            if proto == 17 and (src_port == 53 or dst_port == 53) and payload:
                dns_data = deep_parse_dns(payload)
                if dns_data: detected_l7_proto = "DNS"
            elif proto == 6 and payload:
                # Intercept explicit plain text ports or evaluate structural layouts
                http_data = deep_parse_http(payload)
                if http_data: detected_l7_proto = "HTTP"

            # Terminal Live Stream Output Formatting
            proto_label = "TCP" if proto == 6 else ("UDP" if proto == 17 else str(proto))
            flags_str = f" | Flags: [{', '.join(flags_list)}]" if flags_list else ""
            
            print(f"[PACKET] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Proto: {proto_label}{flags_str} | Size: {len(raw_data)} bytes")
            
            if detected_l7_proto == "DNS" and dns_data:
                query_str = f" Queries: {dns_data['queries']}" if dns_data['queries'] else ""
                print(f"  └─ [L7 DEEP DNS] Type: {dns_data['type']} | ID: {dns_data['transaction_id']} | Qs: {dns_data['questions_count']}{query_str}")
            elif detected_l7_proto == "HTTP" and http_data:
                if http_data["direction"] == "REQUEST":
                    print(f"  └─ [L7 DEEP HTTP REQ] Method: {http_data['method']} | Path: {http_data['path']} | Host: {http_data['headers'].get('host', 'unknown')}")
                elif http_data["direction"] == "RESPONSE":
                    print(f"  └─ [L7 DEEP HTTP RES] Status: {http_data['status_code']} | Server: {http_data['headers'].get('server', 'unknown')}")

            # Persistent JSON Lines Export Blueprint
            packet_document = {
                "timestamp": datetime.now().isoformat(),
                "network_layer": {"version": 4, "source_ip": src_ip, "destination_ip": dst_ip},
                "transport_layer": {"protocol": proto_label, "source_port": src_port, "destination_port": dst_port, "tcp_flags": flags_list if proto == 6 else None},
                "frame_metadata": {"total_length_bytes": len(raw_data)},
                "application_layer": {
                    "protocol_parsed": detected_l7_proto,
                    "dns_telemetry": dns_data,
                    "http_telemetry": http_data,
                    "raw_payload_preview": format_payload(payload[:80]) if payload else None
                }
            }
            
            with open(args.output, 'a', encoding='utf-8') as log_file:
                log_file.write(json.dumps(packet_document) + '\n')

    except KeyboardInterrupt:
        print("\n\n[*] Ctrl+C detected. Gracefully shutting down NetSentinel Sniffer Engine...")
        sys.exit(0)

if __name__ == "__main__":
    main()
