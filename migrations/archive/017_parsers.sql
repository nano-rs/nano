-- Parser Management Schema
-- Stores VRL parsing configurations that can be managed via UI

CREATE TABLE IF NOT EXISTS parsers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    
    -- Source configuration
    source_type VARCHAR(100) NOT NULL,          -- e.g., 'file', 'syslog', 'http'
    source_config JSONB NOT NULL DEFAULT '{}',  -- Source-specific config (paths, ports, etc.)
    
    -- Parser configuration (VRL code)
    parser_vrl TEXT NOT NULL,                   -- The VRL remap code for parsing
    
    -- Output configuration  
    output_fields JSONB,                        -- Expected output field mappings
    
    -- Linked feed (optional)
    feed_id UUID REFERENCES feeds(id) ON DELETE SET NULL,
    
    -- Status
    enabled BOOLEAN NOT NULL DEFAULT false,
    validated BOOLEAN NOT NULL DEFAULT false,
    validation_error TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_parsers_enabled ON parsers (enabled);
CREATE INDEX IF NOT EXISTS idx_parsers_source_type ON parsers (source_type);
CREATE INDEX IF NOT EXISTS idx_parsers_feed_id ON parsers (feed_id);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_parsers_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS parsers_updated_at ON parsers;
CREATE TRIGGER parsers_updated_at
    BEFORE UPDATE ON parsers
    FOR EACH ROW
    EXECUTE FUNCTION update_parsers_updated_at();

-- Insert the Apache parser as an example
INSERT INTO parsers (name, description, source_type, source_config, parser_vrl, enabled, validated) VALUES
(
    'apache_access',
    'Apache Combined Log Format parser',
    'file',
    '{"include": ["/tmp/apache_access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log"], "read_from": "end"}',
    $VRL$
# Apache Combined Log Format:
# %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

.raw_content = to_string(.message) ?? to_string(.)

parsed, err = parse_regex(.raw_content, r'^(?P<client_ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"')

if err == null {
    .metadata = {
        "source_type": "apache_access",
        "method": parsed.method,
        "path": parsed.path,
        "protocol": parsed.protocol,
        "status_code": to_int(parsed.status) ?? 0,
        "response_size": to_int(parsed.size) ?? 0,
        "referrer": parsed.referrer,
        "user_agent": parsed.user_agent
    }
    
    .udm = {}
    .udm.src_ip = parsed.client_ip
    .udm.user = if parsed.user != "-" { parsed.user } else { null }
    .udm.action = downcase(parsed.method) ?? "unknown"
    .udm.status = parsed.status
    .udm.file_path = parsed.path
    .udm.protocol = if contains(parsed.protocol, "HTTPS") { "https" } else { "http" }
    
    ts, ts_err = parse_timestamp(parsed.timestamp, "%d/%b/%Y:%H:%M:%S %z")
    if ts_err == null {
        .udm.timestamp = to_string(ts)
    } else {
        .udm.timestamp = to_string(now())
    }
    
    .udm.dest_port = if .udm.protocol == "https" { 443 } else { 80 }
    .udm.bytes_out = to_int(parsed.size) ?? null
    .source_type = "apache_access"
} else {
    .metadata = { "source_type": "apache_access", "parse_error": to_string(err) }
    .source_type = "apache_access"
    .udm = { "timestamp": to_string(now()) }
}
$VRL$,
    false,
    true
) ON CONFLICT (name) DO NOTHING;

-- Insert a generic syslog parser
INSERT INTO parsers (name, description, source_type, source_config, parser_vrl, enabled, validated) VALUES
(
    'syslog_rfc3164',
    'Standard RFC 3164 Syslog parser',
    'syslog',
    '{"mode": "udp", "address": "0.0.0.0:514"}',
    $VRL$
# RFC 3164 Syslog Format:
# <priority>timestamp hostname tag: message

.raw_content = to_string(.message) ?? to_string(.)

# Try to parse as syslog
parsed, err = parse_syslog(.raw_content, "rfc3164")

if err == null {
    .metadata = {
        "source_type": "syslog",
        "facility": parsed.facility,
        "severity": parsed.severity,
        "appname": parsed.appname
    }
    
    .udm = {}
    .udm.src_host = parsed.hostname
    .udm.process_name = parsed.appname
    .udm.process_id = parsed.procid
    .udm.timestamp = to_string(parsed.timestamp) ?? to_string(now())
    
    # Map syslog severity to status
    .udm.status = if parsed.severity <= 3 { "error" } 
                  else if parsed.severity <= 4 { "warning" }
                  else { "info" }
    
    .source_type = "syslog"
} else {
    # Fallback - treat as raw text
    .metadata = { "source_type": "syslog", "parse_error": to_string(err) }
    .source_type = "syslog"
    .udm = { "timestamp": to_string(now()) }
}
$VRL$,
    false,
    true
) ON CONFLICT (name) DO NOTHING;

-- Insert a JSON log parser
INSERT INTO parsers (name, description, source_type, source_config, parser_vrl, enabled, validated) VALUES
(
    'json_generic',
    'Generic JSON log parser - passes through JSON fields',
    'http',
    '{"address": "0.0.0.0:8080"}',
    $VRL$
# Generic JSON parser
# Expects logs to already be JSON formatted

.raw_content = to_string(.)

# If already an object, use it directly
if is_object(.) {
    .metadata = {
        "source_type": "json"
    }
    
    .udm = {}
    
    # Try to extract common timestamp fields
    .udm.timestamp = to_string(.timestamp) ?? 
                     to_string(.time) ?? 
                     to_string(.@timestamp) ?? 
                     to_string(.datetime) ??
                     to_string(now())
    
    # Try to extract common fields
    .udm.src_ip = .src_ip ?? .source_ip ?? .client_ip ?? .ip
    .udm.dest_ip = .dest_ip ?? .destination_ip ?? .server_ip
    .udm.user = .user ?? .username ?? .user_name
    .udm.action = .action ?? .event ?? .event_type
    .udm.status = .status ?? .level ?? .severity
    .udm.process_name = .process ?? .service ?? .application
    
    .source_type = "json"
} else {
    # Try to parse as JSON
    parsed, err = parse_json(to_string(.message) ?? to_string(.))
    
    if err == null {
        .metadata = { "source_type": "json" }
        .udm = {
            "timestamp": to_string(parsed.timestamp) ?? to_string(now())
        }
        .source_type = "json"
    } else {
        .metadata = { "source_type": "json", "parse_error": to_string(err) }
        .source_type = "json"
        .udm = { "timestamp": to_string(now()) }
    }
}
$VRL$,
    false,
    true
) ON CONFLICT (name) DO NOTHING;
