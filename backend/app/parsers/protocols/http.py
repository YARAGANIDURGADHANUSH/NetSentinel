def deep_parse_http(payload):
    """
    Analyzes raw TCP application payloads to extract structured HTTP request 
    and response states compliant with standard RFC specifications.
    """
    if not payload:
        return None

    try:
        # Decode the initial payload boundary to scan header lines
        decoded = payload[:2048].decode('utf-8', errors='ignore')
        lines = decoded.split('\r\n')
        if not lines or not lines[0]:
            return None

        start_line = lines[0]
        tokens = start_line.split(' ')
        if len(tokens) < 2:
            return None

        # Recognized standard HTTP Request Methods
        HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
        
        # --- CASE A: HTTP REQUEST DETECTED ---
        if tokens[0] in HTTP_METHODS:
            http_metadata = {
                "direction": "REQUEST",
                "method": tokens[0],
                "path": tokens[1],
                "version": tokens[2] if len(tokens) > 2 else "HTTP/1.1",
                "headers": {}
            }
            
            # Extract essential tracking headers safely
            for line in lines[1:]:
                if not line:  # Headers terminate at an empty line boundary
                    break
                if ":" in line:
                    key, val = line.split(":", 1)
                    k_lower = key.strip().lower()
                    if k_lower in ["host", "user-agent", "accept", "content-length"]:
                        http_metadata["headers"][k_lower] = val.strip()
            return http_metadata

        # --- CASE B: HTTP RESPONSE DETECTED ---
        elif tokens[0].startswith("HTTP/"):
            http_metadata = {
                "direction": "RESPONSE",
                "version": tokens[0],
                "status_code": int(tokens[1]) if tokens[1].isdigit() else tokens[1],
                "status_text": " ".join(tokens[2:]) if len(tokens) > 2 else "",
                "headers": {}
            }
            
            # Extract essential telemetry headers safely
            for line in lines[1:]:
                if not line:
                    break
                if ":" in line:
                    key, val = line.split(":", 1)
                    k_lower = key.strip().lower()
                    if k_lower in ["server", "content-type", "content-length", "connection"]:
                        http_metadata["headers"][k_lower] = val.strip()
            return http_metadata

    except Exception:
        # Gracefully drop parsing anomalies to ensure network engine continuity
        pass

    return None
