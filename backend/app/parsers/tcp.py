import struct

def parse_tcp_segment(raw_data: bytes) -> tuple:
    """
    Parses Layer 4 TCP header flags and segment bounds.
    Returns a dictionary of transport metadata and the remaining payload bytes.
    """
    if len(raw_data) < 20:
        return {}, raw_data
        
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', raw_data[:14])
    
    # Extract the data offset to find where the header ends
    data_offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x3F
    
    # Map bit positions to specific TCP flags
    flag_list = []
    if flags & 0x20: flag_list.append("URG")
    if flags & 0x10: flag_list.append("ACK")
    if flags & 0x08: flag_list.append("PSH")
    if flags & 0x04: flag_list.append("RST")
    if flags & 0x02: flag_list.append("SYN")
    if flags & 0x01: flag_list.append("FIN")
    
    metadata = {
        "protocol": "TCP",
        "source_port": src_port,
        "destination_port": dst_port,
        "sequence_number": seq,
        "acknowledgment_number": ack,
        "tcp_flags": flag_list
    }
    
    return metadata, raw_data[data_offset:]
