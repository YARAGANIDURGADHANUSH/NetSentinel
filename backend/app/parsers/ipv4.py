import struct

def parse_ipv4_packet(raw_data: bytes) -> tuple:
    """
    Parses Layer 3 IPv4 header.
    Returns a dictionary of network metadata and the remaining payload bytes.
    """
    if len(raw_data) < 20:
        return {}, raw_data
        
    version_and_ihl = raw_data[0]
    version = version_and_ihl >> 4
    ihl = (version_and_ihl & 0xF) * 4
    
    if len(raw_data) < ihl:
        return {}, raw_data
        
    ttl, proto, _, src_bytes, dst_bytes = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    
    # Unpack IP byte segments to dotted-quad strings
    src_ip = '.'.join(str(b) for b in src_bytes)
    dst_ip = '.'.join(str(b) for b in dst_bytes)
    
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_name = protocol_map.get(proto, f"UNKNOWN_L4_({proto})")
    
    metadata = {
        "version": version,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol_name,
        "ttl": ttl
    }
    
    return metadata, raw_data[ihl:]
