-- ============================================================================
-- Migration 075: Remove file_path from Squid Proxy parser
-- ============================================================================
-- The file_path field was duplicating the url field. Since url is the
-- canonical UDM field for request URLs, drop the redundant file_path.
-- ============================================================================

UPDATE log_sources
SET parser_vrl = $$
# Squid Proxy Access Log Parser
# Extended format: timestamp duration client_ip result/status bytes method url user hierarchy content_type "referrer"
# The referrer field is optional and quoted

# Get raw log content
raw_log = string!(.message)

# Initialize UDM and metadata
.udm = {}
.metadata = {}

# Trim leading/trailing whitespace, then compact multiple spaces to single space
raw_log = strip_whitespace(raw_log)
raw_log = replace(raw_log, r'\s+', " ")

# Split the log line by single space
parts = split(raw_log, " ")

# Squid logs have at least 10 fields
if length(parts) >= 10 {
    # Field 0: Unix timestamp with milliseconds (e.g., "1766696574.540")
    ts_str = to_string(parts[0])
    ts_float = to_float(ts_str) ?? 0.0
    ts_secs = to_int(floor(ts_float))
    .udm.timestamp = from_unix_timestamp(ts_secs, "seconds") ?? now()

    # Field 1: Duration in milliseconds
    .udm.duration = to_int(parts[1]) ?? 0

    # Field 2: Client IP address (source IP)
    .udm.src_ip = to_string(parts[2])

    # Field 3: Result code/HTTP status (e.g., "TCP_MISS/200", "TCP_DENIED/403")
    result_status = to_string(parts[3])

    # Split result code and HTTP status
    result_parts = split(result_status, "/")
    if length(result_parts) >= 2 {
        squid_result = to_string(result_parts[0])
        http_status = to_int(result_parts[1]) ?? 0

        # Determine action based on Squid result code (universal UDM field)
        .udm.action = if contains(squid_result, "HIT") {
            "cache_hit"
        } else if contains(squid_result, "MISS") {
            "cache_miss"
        } else if contains(squid_result, "DENIED") {
            "denied"
        } else if contains(squid_result, "REFRESH") {
            "cache_refresh"
        } else if contains(squid_result, "TUNNEL") {
            "tunnel"
        } else {
            "proxy_request"
        }

        # Store HTTP status code in UDM
        .udm.status_code = http_status

        # Store original Squid result code in metadata for debugging
        .metadata.squid_result_code = squid_result
    } else {
        .udm.action = "proxy_request"
        .udm.status_code = 0
        .metadata.squid_result_code = result_status
    }

    # Field 4: Response size in bytes
    .udm.bytes_out = to_int(parts[4]) ?? 0

    # Field 5: HTTP method
    http_method = to_string(parts[5])
    .udm.http_method = http_method

    # Update action for CONNECT method
    if http_method == "CONNECT" {
        .udm.action = "tunnel_connect"
    }

    # Field 6: Request URL
    request_url = to_string(parts[6])
    .udm.url = request_url

    # Parse URL to extract destination host and port
    url_match = parse_regex(request_url, r'^(?:(?P<scheme>https?|ftp)://)?(?P<host>[^:/]+)(?::(?P<port>\d+))?(?P<path>/.*)?$') ?? {}
    if exists(url_match.host) {
        host_str = to_string(url_match.host)
        .udm.dest_host = host_str
        .udm.url_domain = host_str
        # If host is an IP address, also set dest_ip for prevalence lookup
        if match(host_str, r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') {
            .udm.dest_ip = host_str
        }
    }
    if exists(url_match.port) {
        .udm.dest_port = to_int(url_match.port) ?? null
    }
    if exists(url_match.scheme) {
        scheme = to_string(url_match.scheme)
        .udm.protocol = if scheme == "https" {
            "HTTPS"
        } else if scheme == "http" {
            "HTTP"
        } else if scheme == "ftp" {
            "FTP"
        } else {
            upcase(scheme)
        }
    } else {
        .udm.protocol = "HTTP"
    }
    if exists(url_match.path) {
        .udm.uri_path = to_string(url_match.path)
    }

    # For CONNECT method (HTTPS tunneling), extract host:port
    if http_method == "CONNECT" {
        connect_match = parse_regex(request_url, r'^(?P<host>[^:]+):(?P<port>\d+)$') ?? {}
        if exists(connect_match.host) {
            connect_host = to_string(connect_match.host)
            .udm.dest_host = connect_host
            # If host is an IP address, also set dest_ip for prevalence lookup
            if match(connect_host, r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') {
                .udm.dest_ip = connect_host
            }
        }
        if exists(connect_match.port) {
            .udm.dest_port = to_int(connect_match.port) ?? null
        }
        .udm.protocol = "HTTPS"
    }

    # Field 7: Username
    username = to_string(parts[7])
    if username != "-" {
        .udm.user = username
    }

    # Field 8: Hierarchy code/peer host (keep in metadata - not standard UDM)
    hierarchy = to_string(parts[8])
    hierarchy_parts = split(hierarchy, "/")
    if length(hierarchy_parts) >= 2 {
        hierarchy_code = to_string(hierarchy_parts[0])
        peer_host = to_string(hierarchy_parts[1])

        .metadata.hierarchy_code = hierarchy_code
        if peer_host != "-" {
            .metadata.peer_host = peer_host
        }
    }

    # Field 9: Content type
    content_type = to_string(parts[9])
    if content_type != "-" {
        .udm.http_content_type = content_type
    }

    # Field 10 (optional): Referrer in quotes - extract with regex since it's quoted
    referrer_match = parse_regex(raw_log, r'"(?P<referrer>[^"]*)"$') ?? {}
    if exists(referrer_match.referrer) {
        referrer_val = to_string(referrer_match.referrer)
        if referrer_val != "-" && referrer_val != "" {
            .udm.http_referrer = referrer_val
        }
    }

} else {
    # Fallback for lines with fewer fields
    .metadata.parse_error = "Insufficient fields in log line"
    .metadata.raw_log = raw_log
    .udm.timestamp = now()
    .udm.action = "proxy_request"
    .udm.status_code = 0
}

# Ensure timestamp is always set
if !exists(.udm.timestamp) {
    .udm.timestamp = now()
}

# Set default protocol if not determined
if !exists(.udm.protocol) {
    .udm.protocol = "HTTP"
}

# Output the event
.
$$,
    updated_at = NOW()
WHERE name = 'Squid Proxy';
