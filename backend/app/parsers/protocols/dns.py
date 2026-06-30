import struct

def parse_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    """
    Parses a domain name from the variable-length DNS question layout
    using length-prefixed labels (RFC 1035).
    """
    labels = []
    while True:
        if offset >= len(payload):
            break
        length = payload[offset]
        
        # DNS Name compression pointer check (0xC0)
        if (length & 0xC0) == 0xC0:
            # For simplicity in this lean pipeline, we skip full pointer recursion jumps
            offset += 2
            labels.append("[COMPRESSED]")
            break
            
        offset += 1
        if length == 0:
            break
            
        labels.append(payload[offset:offset+length].decode('utf-8', errors='ignore'))
        offset += length
        
    return ".".join(labels), offset

def parse_dns_packet(payload: bytes) -> dict:
    """
    Parses Layer 7 DNS payloads.
    Extracts Transaction ID, Flags, and the requested Query Domain strings.
    """
    if len(payload) < 12:
        return {"protocol_parsed": "DNS", "error": "Payload too short"}

    try:
        # Unpack the 12-byte fixed DNS header
        tx_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack('! H H H H H H', payload[:12])
        
        # Determine if it's a Query or a Response via the QR bit (highest bit of flags)
        dns_type = "RESPONSE" if (flags & 0x8000) else "QUERY"
        
        metadata = {
            "protocol_parsed": "DNS",
            "transaction_id": hex(tx_id).upper(),
            "dns_type": dns_type,
            "queries": []
        }
        
        # Parse the Question section if present
        offset = 12
        if qd_count > 0 and offset < len(payload):
            domain_name, next_offset = parse_dns_name(payload, offset)
            
            # Ensure we have bytes remaining for QTYPE and QCLASS (4 bytes total)
            if next_offset + 4 <= len(payload):
                qtype, qclass = struct.unpack('! H H', payload[next_offset:next_offset+4])
                
                # Map common DNS record types
                type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT"}
                record_type = type_map.get(qtype, f"TYPE_{qtype}")
                
                metadata["queries"].append({
                    "domain": domain_name,
                    "type": record_type
                })
                
        return metadata

    except Exception as err:
        return {"protocol_parsed": "DNS", "error": f"Parsing exception: {str(err)}"}
