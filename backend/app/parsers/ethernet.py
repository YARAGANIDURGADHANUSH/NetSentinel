import struct

def parse_ethernet_frame(raw_data: bytes) -> tuple:
    """
    Parses Layer 2 Ethernet header.
    Returns a dictionary of parsed metadata and the remaining payload bytes.
    """
    if len(raw_data) < 14:
        return {}, raw_data
        
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    
    # Format raw MAC bytes into human-readable colon separation
    formatted_dest = ':'.join(f'{b:02x}' for b in dest_mac)
    formatted_src = ':'.join(f'{b:02x}' for b in src_mac)
    
    metadata = {
        "destination_mac": formatted_dest,
        "source_mac": formatted_src,
        "ether_type": hex(proto)
    }
    
    return metadata, raw_data[14:]
