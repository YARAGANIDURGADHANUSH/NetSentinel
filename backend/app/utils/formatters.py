def parse_ip_address(bytes_data):
    """Converts a 4-byte packed string to standard dotted-quad string notation."""
    return '.'.join(map(str, bytes_data))

def format_payload(data):
    """Converts raw binary payload to readable ASCII text, substituting dots for non-printable bytes."""
    if not data:
        return ""
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
