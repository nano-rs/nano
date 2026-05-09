-- Fix Apache parser to use correct field name for referrer
-- Vector's parse_apache_log uses "referrer" (double r) not "referer"

UPDATE parser_library
SET parser_vrl = $VRL$
# Apache Combined Log Format Parser
# Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

# Get the raw log line - could be in .raw_content, .metadata.message, or .message
raw_log = ""
if exists(.raw_content) && is_string(.raw_content) {
    raw_log = to_string!(.raw_content)
} else if exists(.metadata.message) && is_string(.metadata.message) {
    raw_log = to_string!(.metadata.message)
} else if exists(.message) && is_string(.message) {
    raw_log = to_string!(.message)
} else {
    raw_log = to_string(.message) ?? ""
}

# Store raw content
.raw_content = raw_log
.sourcetype = "apache_access"

# Parse using Apache log parser (combined format)
parsed, err = parse_apache_log(raw_log, "combined")

if err == null {
    # Initialize UDM fields
    .udm = {}
    
    # Map to UDM fields
    .udm.src_ip = parsed.host
    .udm.user = if parsed.user != "-" { parsed.user } else { null }
    .udm.action = parsed.method
    .udm.bytes_out = to_int(parsed.size)
    .udm.protocol = "HTTP"
    .udm.user_agent = parsed.agent
    .udm.timestamp = to_string(parsed.timestamp)
    
    # Store raw HTTP status code
    .udm.status = to_string(parsed.status)
    
    # Extract file path from request
    .udm.file_path = parsed.path
    
    # Build referer value (note: Vector uses "referrer" with double r)
    referer_val = if parsed.referrer != "-" { parsed.referrer } else { null }
    
    # Store HTTP-specific fields in metadata
    .metadata = {}
    .metadata.source_type = "apache_access"
    .metadata.http_method = parsed.method
    .metadata.http_status_code = to_int(parsed.status)
    .metadata.request_path = parsed.path
    .metadata.http_version = parsed.protocol
    .metadata.referer = referer_val
    .metadata.user_agent = parsed.agent
    .metadata.response_bytes = to_int(parsed.size)
} else {
    # Fallback - store raw with error
    .udm = {}
    .udm.timestamp = to_string(now())
    .metadata = {}
    .metadata.source_type = "apache_access"
    .metadata.parse_error = to_string(err)
    .metadata.raw_input = raw_log
}

.source_type = "apache_access"
$VRL$,
    updated_at = NOW()
WHERE name = 'apache_access' OR name = 'Apache';

-- Also update the parsers table if it exists there
UPDATE parsers
SET parser_vrl = $VRL$
# Apache Combined Log Format Parser
# Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

# Get the raw log line - could be in .raw_content, .metadata.message, or .message
raw_log = ""
if exists(.raw_content) && is_string(.raw_content) {
    raw_log = to_string!(.raw_content)
} else if exists(.metadata.message) && is_string(.metadata.message) {
    raw_log = to_string!(.metadata.message)
} else if exists(.message) && is_string(.message) {
    raw_log = to_string!(.message)
} else {
    raw_log = to_string(.message) ?? ""
}

# Store raw content
.raw_content = raw_log
.sourcetype = "apache_access"

# Parse using Apache log parser (combined format)
parsed, err = parse_apache_log(raw_log, "combined")

if err == null {
    # Initialize UDM fields
    .udm = {}
    
    # Map to UDM fields
    .udm.src_ip = parsed.host
    .udm.user = if parsed.user != "-" { parsed.user } else { null }
    .udm.action = parsed.method
    .udm.bytes_out = to_int(parsed.size)
    .udm.protocol = "HTTP"
    .udm.user_agent = parsed.agent
    .udm.timestamp = to_string(parsed.timestamp)
    
    # Store raw HTTP status code
    .udm.status = to_string(parsed.status)
    
    # Extract file path from request
    .udm.file_path = parsed.path
    
    # Build referer value (note: Vector uses "referrer" with double r)
    referer_val = if parsed.referrer != "-" { parsed.referrer } else { null }
    
    # Store HTTP-specific fields in metadata
    .metadata = {}
    .metadata.source_type = "apache_access"
    .metadata.http_method = parsed.method
    .metadata.http_status_code = to_int(parsed.status)
    .metadata.request_path = parsed.path
    .metadata.http_version = parsed.protocol
    .metadata.referer = referer_val
    .metadata.user_agent = parsed.agent
    .metadata.response_bytes = to_int(parsed.size)
} else {
    # Fallback - store raw with error
    .udm = {}
    .udm.timestamp = to_string(now())
    .metadata = {}
    .metadata.source_type = "apache_access"
    .metadata.parse_error = to_string(err)
    .metadata.raw_input = raw_log
}

.source_type = "apache_access"
$VRL$,
    updated_at = NOW()
WHERE name = 'apache_access' OR name = 'Apache';
