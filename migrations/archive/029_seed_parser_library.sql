-- Seed Pre-Built Parser Library
-- Seeds the parser_library table with pre-built parsers for common security log sources
-- Requirements: 10.1, 10.6

-- ============================================================================
-- ENDPOINT CATEGORY PARSERS
-- ============================================================================

-- Windows Event Log Parser (Security Events: 4624, 4625, 4688, etc.)
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'windows_event',
    'Windows Event Log',
    'Parses Windows Security Event Logs including logon events (4624, 4625), process creation (4688), and other security-relevant events.',
    'endpoint',
    'Microsoft',
    'windows_event',
    $VRL$
# Windows Event Log Parser
# Handles Security, System, and Application event logs

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

# Extract common Windows Event fields
.metadata.event_id = to_int(.EventID) ?? to_int(.event_id) ?? null
.metadata.channel = .Channel ?? .channel ?? "Security"
.metadata.computer = .Computer ?? .computer ?? .MachineName ?? null
.metadata.provider_name = .ProviderName ?? .provider_name ?? null
.metadata.level = .Level ?? .level ?? null
.metadata.task = .Task ?? .task ?? null
.metadata.opcode = .Opcode ?? .opcode ?? null
.metadata.keywords = .Keywords ?? .keywords ?? null
.metadata.record_id = .RecordId ?? .record_id ?? null

# Map to UDM fields
.timestamp = parse_timestamp(.TimeCreated.SystemTime, "%+") ?? 
             parse_timestamp(.time_created, "%+") ?? 
             parse_timestamp(.timestamp, "%+") ?? 
             now()

.src_host = .Computer ?? .computer ?? .MachineName ?? null
.user = .TargetUserName ?? .SubjectUserName ?? .UserName ?? .user ?? null
.src_ip = .IpAddress ?? .SourceAddress ?? .src_ip ?? null
.dest_ip = .DestAddress ?? .DestinationAddress ?? .dest_ip ?? null
.src_port = to_int(.SourcePort) ?? null
.dest_port = to_int(.DestPort) ?? to_int(.DestinationPort) ?? null
.protocol = .Protocol ?? null

# Determine action based on event ID
event_id = to_int(.EventID) ?? to_int(.event_id) ?? 0
.action = if event_id == 4624 { "logon_success" }
          else if event_id == 4625 { "logon_failure" }
          else if event_id == 4634 { "logoff" }
          else if event_id == 4648 { "explicit_credential_logon" }
          else if event_id == 4688 { "process_created" }
          else if event_id == 4689 { "process_terminated" }
          else if event_id == 4720 { "user_created" }
          else if event_id == 4722 { "user_enabled" }
          else if event_id == 4725 { "user_disabled" }
          else if event_id == 4726 { "user_deleted" }
          else if event_id == 4728 { "member_added_to_security_group" }
          else if event_id == 4732 { "member_added_to_local_group" }
          else if event_id == 4756 { "member_added_to_universal_group" }
          else if event_id == 4768 { "kerberos_tgt_requested" }
          else if event_id == 4769 { "kerberos_service_ticket_requested" }
          else if event_id == 4776 { "credential_validation" }
          else { to_string(event_id) ?? "unknown" }

# Determine status
.status = if contains(string!(.Keywords) ?? "", "Audit Success") { "success" }
          else if contains(string!(.Keywords) ?? "", "Audit Failure") { "failure" }
          else if event_id == 4624 { "success" }
          else if event_id == 4625 { "failure" }
          else { null }

# Extract process information for process events
if event_id == 4688 || event_id == 4689 {
    .metadata.process_name = .NewProcessName ?? .ProcessName ?? null
    .metadata.process_id = to_int(.NewProcessId) ?? to_int(.ProcessId) ?? null
    .metadata.parent_process_name = .ParentProcessName ?? null
    .metadata.parent_process_id = to_int(.ProcessId) ?? null
    .metadata.command_line = .CommandLine ?? null
}

# Extract logon-specific fields
if event_id == 4624 || event_id == 4625 {
    .metadata.logon_type = to_int(.LogonType) ?? null
    .metadata.logon_type_name = if .metadata.logon_type == 2 { "Interactive" }
                                else if .metadata.logon_type == 3 { "Network" }
                                else if .metadata.logon_type == 4 { "Batch" }
                                else if .metadata.logon_type == 5 { "Service" }
                                else if .metadata.logon_type == 7 { "Unlock" }
                                else if .metadata.logon_type == 8 { "NetworkCleartext" }
                                else if .metadata.logon_type == 9 { "NewCredentials" }
                                else if .metadata.logon_type == 10 { "RemoteInteractive" }
                                else if .metadata.logon_type == 11 { "CachedInteractive" }
                                else { null }
    .metadata.target_logon_id = .TargetLogonId ?? null
    .metadata.subject_logon_id = .SubjectLogonId ?? null
    .metadata.workstation_name = .WorkstationName ?? null
    .metadata.failure_reason = .FailureReason ?? .Status ?? null
    .metadata.sub_status = .SubStatus ?? null
}

# Set source type
.source_type = "windows_event"
$VRL$,
    '[
        {"EventID": 4624, "TimeCreated": {"SystemTime": "2024-01-15T10:30:00Z"}, "Computer": "WORKSTATION01", "TargetUserName": "john.doe", "IpAddress": "192.168.1.100", "LogonType": 10, "Keywords": "Audit Success"},
        {"EventID": 4625, "TimeCreated": {"SystemTime": "2024-01-15T10:31:00Z"}, "Computer": "WORKSTATION01", "TargetUserName": "admin", "IpAddress": "10.0.0.50", "LogonType": 3, "Keywords": "Audit Failure", "FailureReason": "Unknown user name or bad password"},
        {"EventID": 4688, "TimeCreated": {"SystemTime": "2024-01-15T10:32:00Z"}, "Computer": "SERVER01", "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami", "SubjectUserName": "SYSTEM"}
    ]'::jsonb,
    '{
        "timestamp": "TimeCreated.SystemTime",
        "user": "TargetUserName or SubjectUserName",
        "src_host": "Computer",
        "src_ip": "IpAddress",
        "action": "Derived from EventID",
        "status": "Derived from Keywords"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Sysmon Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'sysmon',
    'Sysmon',
    'Parses Microsoft Sysmon logs for detailed endpoint telemetry including process creation, network connections, file creation, and registry modifications.',
    'endpoint',
    'Microsoft',
    'sysmon',
    $VRL$
# Sysmon Parser
# Handles Sysmon events for detailed endpoint monitoring

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

# Extract Sysmon event ID
event_id = to_int(.EventID) ?? to_int(.event_id) ?? 0
.metadata.event_id = event_id

# Map event ID to event type name
.metadata.event_type = if event_id == 1 { "ProcessCreate" }
                       else if event_id == 2 { "FileCreateTime" }
                       else if event_id == 3 { "NetworkConnect" }
                       else if event_id == 4 { "SysmonServiceStateChanged" }
                       else if event_id == 5 { "ProcessTerminate" }
                       else if event_id == 6 { "DriverLoad" }
                       else if event_id == 7 { "ImageLoad" }
                       else if event_id == 8 { "CreateRemoteThread" }
                       else if event_id == 9 { "RawAccessRead" }
                       else if event_id == 10 { "ProcessAccess" }
                       else if event_id == 11 { "FileCreate" }
                       else if event_id == 12 { "RegistryEvent" }
                       else if event_id == 13 { "RegistryValueSet" }
                       else if event_id == 14 { "RegistryRename" }
                       else if event_id == 15 { "FileCreateStreamHash" }
                       else if event_id == 17 { "PipeEvent" }
                       else if event_id == 18 { "PipeEvent" }
                       else if event_id == 19 { "WmiEvent" }
                       else if event_id == 20 { "WmiEvent" }
                       else if event_id == 21 { "WmiEvent" }
                       else if event_id == 22 { "DNSEvent" }
                       else if event_id == 23 { "FileDelete" }
                       else if event_id == 24 { "ClipboardChange" }
                       else if event_id == 25 { "ProcessTampering" }
                       else if event_id == 26 { "FileDeleteDetected" }
                       else { "Unknown" }

# Map to UDM fields
.timestamp = parse_timestamp(.UtcTime, "%Y-%m-%d %H:%M:%S%.f") ?? 
             parse_timestamp(.TimeCreated.SystemTime, "%+") ?? 
             now()

.src_host = .Computer ?? .computer ?? null
.user = .User ?? .user ?? null

# Process creation (Event ID 1)
if event_id == 1 {
    .action = "process_created"
    .metadata.process_guid = .ProcessGuid ?? null
    .metadata.process_id = to_int(.ProcessId) ?? null
    .metadata.image = .Image ?? null
    .metadata.file_version = .FileVersion ?? null
    .metadata.description = .Description ?? null
    .metadata.product = .Product ?? null
    .metadata.company = .Company ?? null
    .metadata.original_file_name = .OriginalFileName ?? null
    .metadata.command_line = .CommandLine ?? null
    .metadata.current_directory = .CurrentDirectory ?? null
    .metadata.integrity_level = .IntegrityLevel ?? null
    .metadata.hashes = .Hashes ?? null
    .metadata.parent_process_guid = .ParentProcessGuid ?? null
    .metadata.parent_process_id = to_int(.ParentProcessId) ?? null
    .metadata.parent_image = .ParentImage ?? null
    .metadata.parent_command_line = .ParentCommandLine ?? null
    .metadata.parent_user = .ParentUser ?? null
}

# Network connection (Event ID 3)
if event_id == 3 {
    .action = "network_connection"
    .src_ip = .SourceIp ?? null
    .dest_ip = .DestinationIp ?? null
    .src_port = to_int(.SourcePort) ?? null
    .dest_port = to_int(.DestinationPort) ?? null
    .protocol = downcase(.Protocol ?? "") ?? null
    .dest_host = .DestinationHostname ?? null
    .metadata.initiated = .Initiated ?? null
    .metadata.source_is_ipv6 = .SourceIsIpv6 ?? null
    .metadata.destination_is_ipv6 = .DestinationIsIpv6 ?? null
    .metadata.image = .Image ?? null
}

# File creation (Event ID 11)
if event_id == 11 {
    .action = "file_created"
    .metadata.target_filename = .TargetFilename ?? null
    .metadata.creation_utc_time = .CreationUtcTime ?? null
    .metadata.image = .Image ?? null
}

# Registry events (Event ID 12, 13, 14)
if event_id == 12 || event_id == 13 || event_id == 14 {
    .action = if event_id == 12 { "registry_object_added_deleted" }
              else if event_id == 13 { "registry_value_set" }
              else { "registry_renamed" }
    .metadata.event_type_detail = .EventType ?? null
    .metadata.target_object = .TargetObject ?? null
    .metadata.details = .Details ?? null
    .metadata.image = .Image ?? null
}

# DNS query (Event ID 22)
if event_id == 22 {
    .action = "dns_query"
    .metadata.query_name = .QueryName ?? null
    .metadata.query_status = .QueryStatus ?? null
    .metadata.query_results = .QueryResults ?? null
    .metadata.image = .Image ?? null
}

# Default action for other events
if .action == null {
    .action = .metadata.event_type ?? "sysmon_event"
}

.status = "success"
.source_type = "sysmon"
$VRL$,
    '[
        {"EventID": 1, "UtcTime": "2024-01-15 10:30:00.123", "Computer": "WORKSTATION01", "User": "DOMAIN\\john.doe", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami", "ParentImage": "C:\\Windows\\explorer.exe", "ProcessId": 1234, "ParentProcessId": 5678, "Hashes": "SHA256=ABC123"},
        {"EventID": 3, "UtcTime": "2024-01-15 10:31:00.456", "Computer": "WORKSTATION01", "User": "DOMAIN\\john.doe", "Image": "C:\\Program Files\\Chrome\\chrome.exe", "SourceIp": "192.168.1.100", "SourcePort": 54321, "DestinationIp": "142.250.80.46", "DestinationPort": 443, "Protocol": "tcp", "DestinationHostname": "www.google.com"},
        {"EventID": 22, "UtcTime": "2024-01-15 10:32:00.789", "Computer": "WORKSTATION01", "User": "DOMAIN\\john.doe", "Image": "C:\\Program Files\\Chrome\\chrome.exe", "QueryName": "www.google.com", "QueryStatus": "0", "QueryResults": "142.250.80.46"}
    ]'::jsonb,
    '{
        "timestamp": "UtcTime",
        "user": "User",
        "src_host": "Computer",
        "src_ip": "SourceIp (Event 3)",
        "dest_ip": "DestinationIp (Event 3)",
        "action": "Derived from EventID"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Detection patterns for endpoint parsers
INSERT INTO detection_patterns (source_type, patterns, priority, enabled)
VALUES 
    ('windows_event', '[
        {"field": "message", "regex": "EventID|event_id|EventRecordID", "weight": 0.6},
        {"field": "message", "regex": "Computer|MachineName", "weight": 0.3},
        {"field": "message", "regex": "Security|System|Application", "weight": 0.2},
        {"field": "message", "regex": "Audit Success|Audit Failure", "weight": 0.5}
    ]'::jsonb, 100, true),
    ('sysmon', '[
        {"field": "message", "regex": "Sysmon|ProcessGuid|ParentProcessGuid", "weight": 0.8},
        {"field": "message", "regex": "UtcTime.*\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}", "weight": 0.4},
        {"field": "message", "regex": "Image.*\\.exe|CommandLine", "weight": 0.3},
        {"field": "message", "regex": "Hashes.*SHA256|MD5|SHA1", "weight": 0.5}
    ]'::jsonb, 110, true)
ON CONFLICT DO NOTHING;


-- ============================================================================
-- NETWORK CATEGORY PARSERS
-- ============================================================================

-- Palo Alto Firewall Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'palo_alto',
    'Palo Alto Firewall',
    'Parses Palo Alto Networks PAN-OS firewall logs including traffic, threat, and system logs.',
    'network',
    'Palo Alto Networks',
    'palo_alto',
    $VRL$
# Palo Alto Firewall Parser
# Handles PAN-OS traffic, threat, and system logs (CSV format)

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

# Check if this is CSV format (comma-separated)
message = string!(.message) ?? ""

# Parse CSV fields - PAN-OS Traffic Log format
# Format: FUTURE_USE,receive_time,serial,type,subtype,FUTURE_USE,generated_time,src,dst,natsrc,natdst,rule,srcuser,dstuser,app,vsys,from,to,inbound_if,outbound_if,logset,FUTURE_USE,sessionid,repeatcnt,sport,dport,natsport,natdport,flags,proto,action,...
fields = split(message, ",") ?? []

if length(fields) > 30 {
    # Traffic log format
    .metadata.receive_time = get(fields, 1) ?? null
    .metadata.serial = get(fields, 2) ?? null
    .metadata.log_type = get(fields, 3) ?? null
    .metadata.subtype = get(fields, 4) ?? null
    .metadata.generated_time = get(fields, 6) ?? null
    
    .src_ip = get(fields, 7) ?? null
    .dest_ip = get(fields, 8) ?? null
    .metadata.nat_src_ip = get(fields, 9) ?? null
    .metadata.nat_dst_ip = get(fields, 10) ?? null
    .metadata.rule = get(fields, 11) ?? null
    .user = get(fields, 12) ?? null
    .metadata.dst_user = get(fields, 13) ?? null
    .metadata.application = get(fields, 14) ?? null
    .metadata.vsys = get(fields, 15) ?? null
    .metadata.from_zone = get(fields, 16) ?? null
    .metadata.to_zone = get(fields, 17) ?? null
    .metadata.inbound_if = get(fields, 18) ?? null
    .metadata.outbound_if = get(fields, 19) ?? null
    .metadata.session_id = get(fields, 22) ?? null
    .src_port = to_int(get(fields, 24) ?? "") ?? null
    .dest_port = to_int(get(fields, 25) ?? "") ?? null
    .protocol = get(fields, 29) ?? null
    .action = downcase(get(fields, 30) ?? "") ?? null
    
    # Parse timestamp
    .timestamp = parse_timestamp(get(fields, 6) ?? "", "%Y/%m/%d %H:%M:%S") ?? 
                 parse_timestamp(get(fields, 1) ?? "", "%Y/%m/%d %H:%M:%S") ?? 
                 now()
} else {
    # Try JSON format
    .metadata.log_type = .type ?? .log_type ?? null
    .metadata.subtype = .subtype ?? null
    .src_ip = .src ?? .source_ip ?? null
    .dest_ip = .dst ?? .destination_ip ?? null
    .src_port = to_int(.sport) ?? to_int(.source_port) ?? null
    .dest_port = to_int(.dport) ?? to_int(.destination_port) ?? null
    .user = .srcuser ?? .user ?? null
    .action = downcase(.action ?? "") ?? null
    .protocol = .proto ?? .protocol ?? null
    .metadata.application = .app ?? .application ?? null
    .metadata.rule = .rule ?? null
    .timestamp = parse_timestamp(.receive_time, "%Y/%m/%d %H:%M:%S") ?? 
                 parse_timestamp(.generated_time, "%Y/%m/%d %H:%M:%S") ?? 
                 now()
}

# Normalize action
.action = if .action == "allow" { "allowed" }
          else if .action == "deny" { "denied" }
          else if .action == "drop" { "dropped" }
          else if .action == "reset-client" { "reset" }
          else if .action == "reset-server" { "reset" }
          else if .action == "reset-both" { "reset" }
          else { .action }

.status = if .action == "allowed" { "success" }
          else if .action == "denied" || .action == "dropped" { "failure" }
          else { null }

.source_type = "palo_alto"
$VRL$,
    '[
        "1,2024/01/15 10:30:00,001234567890,TRAFFIC,end,2049,2024/01/15 10:30:00,192.168.1.100,10.0.0.50,192.168.1.100,10.0.0.50,Allow-All,domain\\user,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2024/01/15 10:30:00,12345,1,54321,443,54321,443,0x400000,tcp,allow,1234,567,890,0,0,0,0,0,0,0,0,0,0",
        {"type": "TRAFFIC", "subtype": "end", "src": "192.168.1.100", "dst": "10.0.0.50", "sport": 54321, "dport": 443, "proto": "tcp", "action": "allow", "app": "ssl", "rule": "Allow-HTTPS", "srcuser": "john.doe", "receive_time": "2024/01/15 10:31:00"}
    ]'::jsonb,
    '{
        "timestamp": "receive_time or generated_time",
        "src_ip": "src (field 7 in CSV)",
        "dest_ip": "dst (field 8 in CSV)",
        "src_port": "sport (field 24 in CSV)",
        "dest_port": "dport (field 25 in CSV)",
        "user": "srcuser (field 12 in CSV)",
        "action": "action (field 30 in CSV)",
        "protocol": "proto (field 29 in CSV)"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Cisco ASA Firewall Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'cisco_asa',
    'Cisco ASA Firewall',
    'Parses Cisco ASA firewall logs including connection events, access control, and VPN logs.',
    'network',
    'Cisco',
    'cisco_asa',
    $VRL$
# Cisco ASA Firewall Parser
# Handles ASA syslog messages

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

message = string!(.message) ?? ""

# Extract ASA message ID (e.g., %ASA-6-302013)
asa_match = parse_regex(message, r'%ASA-(?P<severity>\d)-(?P<msg_id>\d+):?\s*(?P<content>.*)') ?? {}

if asa_match != {} {
    .metadata.severity = to_int(asa_match.severity) ?? null
    .metadata.message_id = asa_match.msg_id ?? null
    content = asa_match.content ?? message
    
    msg_id = asa_match.msg_id ?? ""
    
    # Connection built/teardown messages (302013, 302014, 302015, 302016)
    if msg_id == "302013" || msg_id == "302014" || msg_id == "302015" || msg_id == "302016" {
        conn_match = parse_regex(content, r'(?P<action>Built|Teardown)\s+(?P<direction>inbound|outbound)\s+(?P<protocol>\w+)\s+connection\s+(?P<conn_id>\d+)\s+for\s+(?P<src_zone>\w+):(?P<src_ip>[\d\.]+)/(?P<src_port>\d+).*to\s+(?P<dst_zone>\w+):(?P<dst_ip>[\d\.]+)/(?P<dst_port>\d+)') ?? {}
        
        if conn_match != {} {
            .action = if conn_match.action == "Built" { "connection_established" } else { "connection_closed" }
            .src_ip = conn_match.src_ip ?? null
            .dest_ip = conn_match.dst_ip ?? null
            .src_port = to_int(conn_match.src_port) ?? null
            .dest_port = to_int(conn_match.dst_port) ?? null
            .protocol = downcase(conn_match.protocol ?? "") ?? null
            .metadata.connection_id = conn_match.conn_id ?? null
            .metadata.src_zone = conn_match.src_zone ?? null
            .metadata.dst_zone = conn_match.dst_zone ?? null
            .metadata.direction = conn_match.direction ?? null
        }
    }
    
    # Denied connection messages (106001, 106006, 106007, 106014, 106015)
    if msg_id == "106001" || msg_id == "106006" || msg_id == "106007" || msg_id == "106014" || msg_id == "106015" {
        deny_match = parse_regex(content, r'(?P<direction>Inbound|Outbound)?\s*(?P<protocol>\w+)\s+(?:connection\s+)?denied.*from\s+(?P<src_ip>[\d\.]+)(?:/(?P<src_port>\d+))?\s+to\s+(?P<dst_ip>[\d\.]+)(?:/(?P<dst_port>\d+))?') ?? {}
        
        if deny_match != {} {
            .action = "denied"
            .status = "failure"
            .src_ip = deny_match.src_ip ?? null
            .dest_ip = deny_match.dst_ip ?? null
            .src_port = to_int(deny_match.src_port) ?? null
            .dest_port = to_int(deny_match.dst_port) ?? null
            .protocol = downcase(deny_match.protocol ?? "") ?? null
        }
    }
    
    # Authentication messages (113004, 113005, 113012, 113015)
    if msg_id == "113004" || msg_id == "113005" || msg_id == "113012" || msg_id == "113015" {
        auth_match = parse_regex(content, r'(?P<result>AAA\s+user\s+authentication\s+\w+|Authentication\s+\w+).*user\s*[=:]?\s*(?P<user>\S+).*(?:from|server)\s+(?P<ip>[\d\.]+)') ?? {}
        
        if auth_match != {} {
            .action = "authentication"
            .user = auth_match.user ?? null
            .src_ip = auth_match.ip ?? null
            .status = if contains(downcase(auth_match.result ?? ""), "success") || contains(downcase(auth_match.result ?? ""), "successful") { "success" } else { "failure" }
        }
    }
    
    # VPN messages (722022, 722023, 722028, 722037)
    if starts_with(msg_id, "722") {
        vpn_match = parse_regex(content, r'(?P<action>Group|WebVPN|SVC).*user\s+(?P<user>\S+).*IP\s+(?P<ip>[\d\.]+)') ?? {}
        
        if vpn_match != {} {
            .action = "vpn_session"
            .user = vpn_match.user ?? null
            .src_ip = vpn_match.ip ?? null
        }
    }
}

# Extract timestamp from syslog header if present
ts_match = parse_regex(message, r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})') ?? {}
if ts_match != {} {
    year = format_timestamp(now(), "%Y")
    ts_str = year + " " + (ts_match.month ?? "") + " " + (ts_match.day ?? "") + " " + (ts_match.time ?? "")
    .timestamp = parse_timestamp(ts_str, "%Y %b %d %H:%M:%S") ?? now()
} else {
    .timestamp = parse_timestamp(.timestamp, "%+") ?? now()
}

# Extract hostname
host_match = parse_regex(message, r'^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(?P<host>\S+)') ?? {}
.src_host = host_match.host ?? .host ?? null

# Default action if not set
if .action == null {
    .action = "asa_event"
}

.source_type = "cisco_asa"
$VRL$,
    '[
        "Jan 15 10:30:00 firewall %ASA-6-302013: Built inbound TCP connection 12345 for outside:192.168.1.100/54321 to inside:10.0.0.50/443",
        "Jan 15 10:31:00 firewall %ASA-4-106001: Inbound TCP connection denied from 10.0.0.100/12345 to 192.168.1.50/22 flags SYN on interface outside",
        "Jan 15 10:32:00 firewall %ASA-6-113004: AAA user authentication Successful : server = 10.0.0.10 : user = john.doe"
    ]'::jsonb,
    '{
        "timestamp": "Syslog timestamp header",
        "src_ip": "Extracted from message content",
        "dest_ip": "Extracted from message content",
        "src_port": "Extracted from message content",
        "dest_port": "Extracted from message content",
        "user": "Extracted from authentication messages",
        "action": "Derived from message ID",
        "protocol": "Extracted from connection messages"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Syslog Parser (RFC 3164/5424)
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'syslog',
    'Syslog (RFC 3164/5424)',
    'Parses standard syslog messages in both RFC 3164 (BSD) and RFC 5424 formats.',
    'network',
    'Various',
    'syslog',
    $VRL$
# Syslog Parser
# Handles RFC 3164 (BSD) and RFC 5424 syslog formats

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

message = string!(.message) ?? ""

# Try RFC 5424 format first
# Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
rfc5424_match = parse_regex(message, r'^<(?P<pri>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<proc_id>\S+)\s+(?P<msg_id>\S+)\s+(?P<sd>(?:\[.*?\])*|-)\s*(?P<msg>.*)$') ?? {}

if rfc5424_match != {} {
    .metadata.format = "RFC5424"
    .metadata.version = rfc5424_match.version ?? null
    
    # Parse priority
    pri = to_int(rfc5424_match.pri) ?? 0
    .metadata.facility = floor(pri / 8)
    .metadata.severity = pri - (.metadata.facility * 8)
    
    # Map severity to level name
    .metadata.severity_name = if .metadata.severity == 0 { "emergency" }
                              else if .metadata.severity == 1 { "alert" }
                              else if .metadata.severity == 2 { "critical" }
                              else if .metadata.severity == 3 { "error" }
                              else if .metadata.severity == 4 { "warning" }
                              else if .metadata.severity == 5 { "notice" }
                              else if .metadata.severity == 6 { "info" }
                              else if .metadata.severity == 7 { "debug" }
                              else { "unknown" }
    
    .timestamp = parse_timestamp(rfc5424_match.timestamp, "%+") ?? 
                 parse_timestamp(rfc5424_match.timestamp, "%Y-%m-%dT%H:%M:%S%.fZ") ?? 
                 now()
    .src_host = if rfc5424_match.hostname != "-" { rfc5424_match.hostname } else { null }
    .metadata.app_name = if rfc5424_match.app_name != "-" { rfc5424_match.app_name } else { null }
    .metadata.proc_id = if rfc5424_match.proc_id != "-" { rfc5424_match.proc_id } else { null }
    .metadata.msg_id = if rfc5424_match.msg_id != "-" { rfc5424_match.msg_id } else { null }
    .metadata.structured_data = if rfc5424_match.sd != "-" { rfc5424_match.sd } else { null }
    .metadata.message = rfc5424_match.msg ?? null
} else {
    # Try RFC 3164 (BSD) format
    # Format: <PRI>TIMESTAMP HOSTNAME TAG: MSG or TIMESTAMP HOSTNAME TAG: MSG
    rfc3164_match = parse_regex(message, r'^(?:<(?P<pri>\d+)>)?(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$') ?? {}
    
    if rfc3164_match != {} {
        .metadata.format = "RFC3164"
        
        # Parse priority if present
        if rfc3164_match.pri != null {
            pri = to_int(rfc3164_match.pri) ?? 0
            .metadata.facility = floor(pri / 8)
            .metadata.severity = pri - (.metadata.facility * 8)
            
            .metadata.severity_name = if .metadata.severity == 0 { "emergency" }
                                      else if .metadata.severity == 1 { "alert" }
                                      else if .metadata.severity == 2 { "critical" }
                                      else if .metadata.severity == 3 { "error" }
                                      else if .metadata.severity == 4 { "warning" }
                                      else if .metadata.severity == 5 { "notice" }
                                      else if .metadata.severity == 6 { "info" }
                                      else if .metadata.severity == 7 { "debug" }
                                      else { "unknown" }
        }
        
        # Parse timestamp (add current year)
        year = format_timestamp(now(), "%Y")
        ts_str = year + " " + (rfc3164_match.timestamp ?? "")
        .timestamp = parse_timestamp(ts_str, "%Y %b %d %H:%M:%S") ?? now()
        
        .src_host = rfc3164_match.hostname ?? null
        .metadata.app_name = rfc3164_match.tag ?? null
        .metadata.proc_id = rfc3164_match.pid ?? null
        .metadata.message = rfc3164_match.msg ?? null
    } else {
        # Fallback - just store the message
        .metadata.format = "unknown"
        .metadata.message = message
        .timestamp = now()
    }
}

# Try to extract common fields from message content
msg_content = .metadata.message ?? message

# Look for IP addresses
ip_match = parse_regex(msg_content, r'(?:from|src|source|client)[:\s]+(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') ?? {}
if ip_match.src_ip != null {
    .src_ip = ip_match.src_ip
}

dst_match = parse_regex(msg_content, r'(?:to|dst|dest|destination|server)[:\s]+(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') ?? {}
if dst_match.dst_ip != null {
    .dest_ip = dst_match.dst_ip
}

# Look for user
user_match = parse_regex(msg_content, r'(?:user|username|login)[=:\s]+["\']?(?P<user>\S+?)["\']?(?:\s|$|,)') ?? {}
if user_match.user != null {
    .user = user_match.user
}

# Determine action from common patterns
.action = if contains(downcase(msg_content), "failed") || contains(downcase(msg_content), "failure") || contains(downcase(msg_content), "denied") { "failure" }
          else if contains(downcase(msg_content), "success") || contains(downcase(msg_content), "accepted") || contains(downcase(msg_content), "allowed") { "success" }
          else if contains(downcase(msg_content), "started") || contains(downcase(msg_content), "start") { "started" }
          else if contains(downcase(msg_content), "stopped") || contains(downcase(msg_content), "stop") { "stopped" }
          else if contains(downcase(msg_content), "error") { "error" }
          else if contains(downcase(msg_content), "warning") || contains(downcase(msg_content), "warn") { "warning" }
          else { "syslog_event" }

.status = if .action == "failure" || .action == "error" { "failure" }
          else if .action == "success" { "success" }
          else { null }

.source_type = "syslog"
$VRL$,
    '[
        "<134>1 2024-01-15T10:30:00.123456Z server01 myapp 1234 ID47 - User john.doe logged in successfully from 192.168.1.100",
        "<38>Jan 15 10:31:00 server02 sshd[5678]: Failed password for invalid user admin from 10.0.0.50 port 54321 ssh2",
        "Jan 15 10:32:00 server03 sudo: john.doe : TTY=pts/0 ; PWD=/home/john.doe ; USER=root ; COMMAND=/bin/bash"
    ]'::jsonb,
    '{
        "timestamp": "Syslog timestamp (RFC 5424 or RFC 3164)",
        "src_host": "hostname field",
        "src_ip": "Extracted from message content",
        "user": "Extracted from message content",
        "action": "Derived from message patterns",
        "metadata.facility": "Syslog facility code",
        "metadata.severity": "Syslog severity level"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();

-- Detection patterns for network parsers
INSERT INTO detection_patterns (source_type, patterns, priority, enabled)
VALUES 
    ('palo_alto', '[
        {"field": "message", "regex": "%ASA|TRAFFIC|THREAT|SYSTEM", "weight": 0.3},
        {"field": "message", "regex": "PAN-OS|Palo Alto", "weight": 0.9},
        {"field": "message", "regex": "vsys\\d|zone|from_zone|to_zone", "weight": 0.5}
    ]'::jsonb, 90, true),
    ('cisco_asa', '[
        {"field": "message", "regex": "%ASA-\\d-\\d+", "weight": 0.9},
        {"field": "message", "regex": "Built.*connection|Teardown.*connection", "weight": 0.6},
        {"field": "message", "regex": "Deny|Denied.*from.*to", "weight": 0.4}
    ]'::jsonb, 95, true),
    ('syslog', '[
        {"field": "message", "regex": "^<\\d+>", "weight": 0.5},
        {"field": "message", "regex": "^\\w{3}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}", "weight": 0.4},
        {"field": "message", "regex": "sshd|sudo|cron|systemd", "weight": 0.3}
    ]'::jsonb, 50, true)
ON CONFLICT DO NOTHING;


-- ============================================================================
-- CLOUD CATEGORY PARSERS
-- ============================================================================

-- AWS CloudTrail Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'aws_cloudtrail',
    'AWS CloudTrail',
    'Parses AWS CloudTrail API audit logs for tracking AWS account activity and API calls.',
    'cloud',
    'Amazon Web Services',
    'aws_cloudtrail',
    $VRL$
# AWS CloudTrail Parser
# Handles CloudTrail API audit logs

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

# Handle CloudTrail's nested Records array if present
record = if .Records != null { get!(.Records, 0) } else { . }

# Extract core CloudTrail fields
.metadata.event_version = record.eventVersion ?? null
.metadata.event_id = record.eventID ?? null
.metadata.event_type = record.eventType ?? null
.metadata.event_category = record.eventCategory ?? null
.metadata.event_source = record.eventSource ?? null
.metadata.event_name = record.eventName ?? null
.metadata.aws_region = record.awsRegion ?? null
.metadata.recipient_account_id = record.recipientAccountId ?? null
.metadata.request_id = record.requestID ?? null
.metadata.read_only = record.readOnly ?? null
.metadata.management_event = record.managementEvent ?? null

# User identity
user_identity = record.userIdentity ?? {}
.metadata.user_type = user_identity.type ?? null
.metadata.principal_id = user_identity.principalId ?? null
.metadata.arn = user_identity.arn ?? null
.metadata.account_id = user_identity.accountId ?? null
.metadata.access_key_id = user_identity.accessKeyId ?? null
.metadata.session_context = user_identity.sessionContext ?? null

# Extract username from various identity types
.user = user_identity.userName ?? 
        user_identity.principalId ?? 
        (if user_identity.type == "AssumedRole" { 
            split(user_identity.arn ?? "", "/") |> get!(_, -1) 
        } else { null }) ??
        user_identity.arn ?? null

# Map to UDM fields
.timestamp = parse_timestamp(record.eventTime, "%+") ?? 
             parse_timestamp(record.eventTime, "%Y-%m-%dT%H:%M:%SZ") ?? 
             now()

.src_ip = record.sourceIPAddress ?? null
.src_host = record.userAgent ?? null
.dest_host = record.eventSource ?? null

# Action is the API call name
.action = record.eventName ?? null

# Determine status from error fields
.status = if record.errorCode != null || record.errorMessage != null { "failure" } else { "success" }
.metadata.error_code = record.errorCode ?? null
.metadata.error_message = record.errorMessage ?? null

# Request and response parameters
.metadata.request_parameters = record.requestParameters ?? null
.metadata.response_elements = record.responseElements ?? null

# Resources affected
.metadata.resources = record.resources ?? null

# VPC endpoint info if present
.metadata.vpc_endpoint_id = record.vpcEndpointId ?? null

# Additional context
.metadata.shared_event_id = record.sharedEventID ?? null
.metadata.additional_event_data = record.additionalEventData ?? null

.source_type = "aws_cloudtrail"
$VRL$,
    '[
        {"eventVersion": "1.08", "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE", "arn": "arn:aws:iam::123456789012:user/john.doe", "accountId": "123456789012", "userName": "john.doe"}, "eventTime": "2024-01-15T10:30:00Z", "eventSource": "ec2.amazonaws.com", "eventName": "DescribeInstances", "awsRegion": "us-east-1", "sourceIPAddress": "192.168.1.100", "userAgent": "aws-cli/2.0.0", "requestParameters": {"instancesSet": {}}, "responseElements": null, "requestID": "abc123", "eventID": "def456", "readOnly": true, "eventType": "AwsApiCall", "managementEvent": true, "recipientAccountId": "123456789012"},
        {"eventVersion": "1.08", "userIdentity": {"type": "AssumedRole", "principalId": "AROAEXAMPLE:admin-session", "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/admin-session", "accountId": "123456789012"}, "eventTime": "2024-01-15T10:31:00Z", "eventSource": "s3.amazonaws.com", "eventName": "DeleteBucket", "awsRegion": "us-east-1", "sourceIPAddress": "10.0.0.50", "userAgent": "console.amazonaws.com", "errorCode": "AccessDenied", "errorMessage": "Access Denied", "requestParameters": {"bucketName": "my-bucket"}, "requestID": "xyz789", "eventID": "ghi012", "readOnly": false, "eventType": "AwsApiCall", "managementEvent": true, "recipientAccountId": "123456789012"}
    ]'::jsonb,
    '{
        "timestamp": "eventTime",
        "user": "userIdentity.userName or derived from ARN",
        "src_ip": "sourceIPAddress",
        "src_host": "userAgent",
        "dest_host": "eventSource",
        "action": "eventName",
        "status": "Derived from errorCode presence"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- AWS GuardDuty Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'aws_guardduty',
    'AWS GuardDuty',
    'Parses AWS GuardDuty threat detection findings for security monitoring.',
    'cloud',
    'Amazon Web Services',
    'aws_guardduty',
    $VRL$
# AWS GuardDuty Parser
# Handles GuardDuty threat findings

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

# Extract core GuardDuty fields
.metadata.schema_version = .schemaVersion ?? null
.metadata.account_id = .accountId ?? null
.metadata.region = .region ?? null
.metadata.partition = .partition ?? null
.metadata.id = .id ?? null
.metadata.arn = .arn ?? null
.metadata.type = .type ?? null
.metadata.severity = .severity ?? null
.metadata.confidence = .confidence ?? null
.metadata.title = .title ?? null
.metadata.description = .description ?? null

# Parse finding type for action
finding_type = .type ?? ""
type_parts = split(finding_type, ":")
.metadata.threat_purpose = get(type_parts, 0) ?? null
.metadata.resource_type = get(type_parts, 1) ?? null
.metadata.threat_name = get(type_parts, 2) ?? null

# Map severity to level name
severity = to_float(.severity) ?? 0.0
.metadata.severity_level = if severity >= 7.0 { "high" }
                           else if severity >= 4.0 { "medium" }
                           else { "low" }

# Extract resource information
resource = .resource ?? {}
.metadata.resource_type_detail = resource.resourceType ?? null

# Handle different resource types
if resource.instanceDetails != null {
    instance = resource.instanceDetails
    .dest_ip = instance.networkInterfaces[0].privateIpAddress ?? null
    .metadata.instance_id = instance.instanceId ?? null
    .metadata.instance_type = instance.instanceType ?? null
    .metadata.availability_zone = instance.availabilityZone ?? null
    .metadata.image_id = instance.imageId ?? null
    .metadata.platform = instance.platform ?? null
    .metadata.tags = instance.tags ?? null
}

if resource.accessKeyDetails != null {
    access_key = resource.accessKeyDetails
    .user = access_key.userName ?? null
    .metadata.access_key_id = access_key.accessKeyId ?? null
    .metadata.principal_id = access_key.principalId ?? null
    .metadata.user_type = access_key.userType ?? null
}

if resource.s3BucketDetails != null {
    s3 = resource.s3BucketDetails[0] ?? {}
    .metadata.bucket_name = s3.name ?? null
    .metadata.bucket_arn = s3.arn ?? null
    .metadata.bucket_type = s3.type ?? null
}

# Extract service/action information
service = .service ?? {}
.metadata.detector_id = service.detectorId ?? null
.metadata.event_first_seen = service.eventFirstSeen ?? null
.metadata.event_last_seen = service.eventLastSeen ?? null
.metadata.count = service.count ?? null
.metadata.archived = service.archived ?? null

# Action details
action = service.action ?? {}
.metadata.action_type = action.actionType ?? null

if action.networkConnectionAction != null {
    net_action = action.networkConnectionAction
    .metadata.connection_direction = net_action.connectionDirection ?? null
    .metadata.blocked = net_action.blocked ?? null
    .protocol = downcase(net_action.protocol ?? "") ?? null
    
    local_port = net_action.localPortDetails ?? {}
    remote_port = net_action.remotePortDetails ?? {}
    remote_ip = net_action.remoteIpDetails ?? {}
    
    .src_port = to_int(local_port.port) ?? null
    .dest_port = to_int(remote_port.port) ?? null
    .src_ip = remote_ip.ipAddressV4 ?? null
    .metadata.remote_org = remote_ip.organization ?? null
    .metadata.remote_country = remote_ip.country ?? null
    .metadata.remote_city = remote_ip.city ?? null
}

if action.awsApiCallAction != null {
    api_action = action.awsApiCallAction
    .action = api_action.api ?? null
    .metadata.service_name = api_action.serviceName ?? null
    .metadata.caller_type = api_action.callerType ?? null
    .src_ip = api_action.remoteIpDetails.ipAddressV4 ?? null
}

if action.dnsRequestAction != null {
    dns_action = action.dnsRequestAction
    .metadata.domain = dns_action.domain ?? null
    .metadata.blocked = dns_action.blocked ?? null
}

# Map to UDM fields
.timestamp = parse_timestamp(.updatedAt, "%+") ?? 
             parse_timestamp(.createdAt, "%+") ?? 
             parse_timestamp(service.eventLastSeen, "%+") ?? 
             now()

# Default action from finding type
if .action == null {
    .action = .metadata.type ?? "guardduty_finding"
}

.status = "alert"
.source_type = "aws_guardduty"
$VRL$,
    '[
        {"schemaVersion": "2.0", "accountId": "123456789012", "region": "us-east-1", "partition": "aws", "id": "abc123", "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/xyz/finding/abc123", "type": "UnauthorizedAccess:EC2/SSHBruteForce", "severity": 8.0, "confidence": 90, "title": "SSH brute force attack detected", "description": "Multiple SSH login attempts detected", "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-1234567890abcdef0", "instanceType": "t2.micro", "networkInterfaces": [{"privateIpAddress": "10.0.0.50"}]}}, "service": {"detectorId": "xyz", "action": {"actionType": "NETWORK_CONNECTION", "networkConnectionAction": {"connectionDirection": "INBOUND", "protocol": "TCP", "remotePortDetails": {"port": 22}, "remoteIpDetails": {"ipAddressV4": "192.168.1.100", "country": {"countryName": "Unknown"}}}}, "eventFirstSeen": "2024-01-15T10:00:00Z", "eventLastSeen": "2024-01-15T10:30:00Z", "count": 50}, "createdAt": "2024-01-15T10:00:00Z", "updatedAt": "2024-01-15T10:30:00Z"}
    ]'::jsonb,
    '{
        "timestamp": "updatedAt or eventLastSeen",
        "src_ip": "From action details (remoteIpDetails)",
        "dest_ip": "From instanceDetails (privateIpAddress)",
        "action": "type or api call name",
        "status": "Always alert for findings",
        "metadata.severity": "GuardDuty severity score",
        "metadata.severity_level": "high/medium/low"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Azure Activity Log Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'azure_activity',
    'Azure Activity Log',
    'Parses Azure Activity Log events for tracking Azure subscription-level operations.',
    'cloud',
    'Microsoft',
    'azure_activity',
    $VRL$
# Azure Activity Log Parser
# Handles Azure Activity Log events

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

# Handle records array if present
record = if .records != null { get!(.records, 0) } else { . }

# Extract core Azure Activity Log fields
.metadata.tenant_id = record.tenantId ?? null
.metadata.operation_name = record.operationName ?? null
.metadata.operation_id = record.operationId ?? null
.metadata.correlation_id = record.correlationId ?? null
.metadata.category = record.category ?? null
.metadata.result_type = record.resultType ?? null
.metadata.result_signature = record.resultSignature ?? null
.metadata.result_description = record.resultDescription ?? null
.metadata.duration_ms = record.durationMs ?? null
.metadata.level = record.level ?? null
.metadata.resource_id = record.resourceId ?? null
.metadata.resource_group = record.resourceGroupName ?? null
.metadata.resource_provider = record.resourceProviderName ?? null
.metadata.subscription_id = record.subscriptionId ?? null

# Extract caller identity
.metadata.caller = record.caller ?? null
.metadata.claims = record.claims ?? null

# Parse caller for user info
caller = record.caller ?? ""
if contains(caller, "@") {
    .user = caller
} else if record.claims != null {
    claims = record.claims
    .user = claims.name ?? claims.upn ?? claims.appid ?? caller
    .metadata.app_id = claims.appid ?? null
    .metadata.object_id = claims.oid ?? null
}

# Extract IP from claims or properties
if record.claims != null {
    .src_ip = record.claims.ipaddr ?? null
}
if .src_ip == null && record.properties != null {
    .src_ip = record.properties.clientIpAddress ?? record.properties.callerIpAddress ?? null
}

# Map to UDM fields
.timestamp = parse_timestamp(record.time, "%+") ?? 
             parse_timestamp(record.eventTimestamp, "%+") ?? 
             now()

# Action is the operation name
.action = record.operationName ?? null

# Determine status from result
result = downcase(record.resultType ?? "")
.status = if result == "success" || result == "succeeded" { "success" }
          else if result == "failure" || result == "failed" { "failure" }
          else if result == "start" || result == "started" { "started" }
          else { null }

# Properties contain additional context
.metadata.properties = record.properties ?? null

# HTTP request details if present
if record.httpRequest != null {
    .metadata.http_method = record.httpRequest.method ?? null
    .metadata.http_uri = record.httpRequest.uri ?? null
    .src_ip = record.httpRequest.clientIpAddress ?? .src_ip
}

# Extract resource type from resource ID
resource_id = record.resourceId ?? ""
if resource_id != "" {
    parts = split(resource_id, "/")
    # Resource ID format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
    .metadata.resource_type = get(parts, -2) ?? null
    .metadata.resource_name = get(parts, -1) ?? null
}

.source_type = "azure_activity"
$VRL$,
    '[
        {"time": "2024-01-15T10:30:00.1234567Z", "tenantId": "12345678-1234-1234-1234-123456789012", "operationName": "Microsoft.Compute/virtualMachines/start/action", "operationId": "abc123", "correlationId": "def456", "category": "Administrative", "resultType": "Success", "resultSignature": "Succeeded.", "caller": "john.doe@contoso.com", "claims": {"ipaddr": "192.168.1.100", "name": "John Doe", "upn": "john.doe@contoso.com"}, "resourceId": "/subscriptions/sub123/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/myVM", "resourceGroupName": "myRG", "resourceProviderName": "Microsoft.Compute", "subscriptionId": "sub123", "level": "Information"},
        {"time": "2024-01-15T10:31:00.0000000Z", "tenantId": "12345678-1234-1234-1234-123456789012", "operationName": "Microsoft.Storage/storageAccounts/delete", "operationId": "ghi789", "category": "Administrative", "resultType": "Failure", "resultDescription": "The resource group could not be found.", "caller": "admin@contoso.com", "resourceId": "/subscriptions/sub123/resourceGroups/myRG/providers/Microsoft.Storage/storageAccounts/mystorageaccount", "level": "Error"}
    ]'::jsonb,
    '{
        "timestamp": "time or eventTimestamp",
        "user": "caller or claims.upn",
        "src_ip": "claims.ipaddr or httpRequest.clientIpAddress",
        "action": "operationName",
        "status": "Derived from resultType"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();

-- Detection patterns for cloud parsers
INSERT INTO detection_patterns (source_type, patterns, priority, enabled)
VALUES 
    ('aws_cloudtrail', '[
        {"field": "message", "regex": "eventSource.*amazonaws\\.com|awsRegion|eventName", "weight": 0.7},
        {"field": "message", "regex": "userIdentity|recipientAccountId", "weight": 0.6},
        {"field": "message", "regex": "CloudTrail|eventVersion", "weight": 0.8}
    ]'::jsonb, 85, true),
    ('aws_guardduty', '[
        {"field": "message", "regex": "GuardDuty|detectorId|schemaVersion", "weight": 0.8},
        {"field": "message", "regex": "UnauthorizedAccess|Recon|Trojan|Stealth", "weight": 0.6},
        {"field": "message", "regex": "severity.*\\d+\\.\\d+|confidence", "weight": 0.4}
    ]'::jsonb, 80, true),
    ('azure_activity', '[
        {"field": "message", "regex": "tenantId|subscriptionId|resourceId", "weight": 0.6},
        {"field": "message", "regex": "Microsoft\\.(Compute|Storage|Network|Web)", "weight": 0.7},
        {"field": "message", "regex": "operationName|resultType|correlationId", "weight": 0.5}
    ]'::jsonb, 82, true)
ON CONFLICT DO NOTHING;


-- ============================================================================
-- IDENTITY CATEGORY PARSERS
-- ============================================================================

-- Okta System Log Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'okta',
    'Okta System Log',
    'Parses Okta System Log events for identity and access management monitoring.',
    'identity',
    'Okta',
    'okta',
    $VRL$
# Okta System Log Parser
# Handles Okta System Log events

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

# Extract core Okta fields
.metadata.uuid = .uuid ?? null
.metadata.event_type = .eventType ?? null
.metadata.version = .version ?? null
.metadata.severity = .severity ?? null
.metadata.legacy_event_type = .legacyEventType ?? null
.metadata.display_message = .displayMessage ?? null
.metadata.debug_context = .debugContext ?? null
.metadata.authentication_context = .authenticationContext ?? null
.metadata.security_context = .securityContext ?? null
.metadata.request = .request ?? null
.metadata.transaction = .transaction ?? null

# Actor (who performed the action)
actor = .actor ?? {}
.user = actor.alternateId ?? actor.displayName ?? null
.metadata.actor_id = actor.id ?? null
.metadata.actor_type = actor.type ?? null
.metadata.actor_display_name = actor.displayName ?? null

# Target (what was affected)
targets = .target ?? []
if length(targets) > 0 {
    primary_target = get!(targets, 0)
    .metadata.target_id = primary_target.id ?? null
    .metadata.target_type = primary_target.type ?? null
    .metadata.target_display_name = primary_target.displayName ?? null
    .metadata.target_alternate_id = primary_target.alternateId ?? null
    .metadata.all_targets = targets
}

# Client information
client = .client ?? {}
.src_ip = client.ipAddress ?? null
.metadata.user_agent = client.userAgent.rawUserAgent ?? null
.metadata.user_agent_os = client.userAgent.os ?? null
.metadata.user_agent_browser = client.userAgent.browser ?? null
.metadata.device = client.device ?? null
.metadata.zone = client.zone ?? null
.metadata.geographical_context = client.geographicalContext ?? null

# Extract geo info
if client.geographicalContext != null {
    geo = client.geographicalContext
    .metadata.city = geo.city ?? null
    .metadata.state = geo.state ?? null
    .metadata.country = geo.country ?? null
    .metadata.postal_code = geo.postalCode ?? null
    .metadata.geolocation = geo.geolocation ?? null
}

# Outcome
outcome = .outcome ?? {}
.metadata.outcome_result = outcome.result ?? null
.metadata.outcome_reason = outcome.reason ?? null

# Map to UDM fields
.timestamp = parse_timestamp(.published, "%+") ?? now()

# Action is the event type
.action = .eventType ?? null

# Determine status from outcome
result = downcase(outcome.result ?? "")
.status = if result == "success" { "success" }
          else if result == "failure" || result == "denied" { "failure" }
          else if result == "skipped" { "skipped" }
          else if result == "allow" { "success" }
          else { null }

# Authentication context
auth_context = .authenticationContext ?? {}
.metadata.auth_provider = auth_context.authenticationProvider ?? null
.metadata.credential_provider = auth_context.credentialProvider ?? null
.metadata.credential_type = auth_context.credentialType ?? null
.metadata.issuer = auth_context.issuer ?? null
.metadata.interface = auth_context.interface ?? null
.metadata.authentication_step = auth_context.authenticationStep ?? null
.metadata.external_session_id = auth_context.externalSessionId ?? null

# Security context
sec_context = .securityContext ?? {}
.metadata.as_number = sec_context.asNumber ?? null
.metadata.as_org = sec_context.asOrg ?? null
.metadata.isp = sec_context.isp ?? null
.metadata.domain = sec_context.domain ?? null
.metadata.is_proxy = sec_context.isProxy ?? null

.source_type = "okta"
$VRL$,
    '[
        {"uuid": "abc123-def456", "published": "2024-01-15T10:30:00.000Z", "eventType": "user.session.start", "version": "0", "severity": "INFO", "displayMessage": "User login to Okta", "actor": {"id": "00u123", "type": "User", "alternateId": "john.doe@company.com", "displayName": "John Doe"}, "client": {"userAgent": {"rawUserAgent": "Mozilla/5.0", "os": "Windows 10", "browser": "Chrome"}, "zone": "null", "device": "Computer", "ipAddress": "192.168.1.100", "geographicalContext": {"city": "San Francisco", "state": "California", "country": "United States"}}, "outcome": {"result": "SUCCESS"}, "target": [{"id": "00u123", "type": "User", "alternateId": "john.doe@company.com", "displayName": "John Doe"}], "authenticationContext": {"authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER", "credentialType": "PASSWORD"}},
        {"uuid": "ghi789-jkl012", "published": "2024-01-15T10:31:00.000Z", "eventType": "user.authentication.auth_via_mfa", "version": "0", "severity": "INFO", "displayMessage": "Authentication of user via MFA", "actor": {"id": "00u456", "type": "User", "alternateId": "admin@company.com", "displayName": "Admin User"}, "client": {"ipAddress": "10.0.0.50", "geographicalContext": {"country": "United States"}}, "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"}, "authenticationContext": {"credentialType": "OTP"}}
    ]'::jsonb,
    '{
        "timestamp": "published",
        "user": "actor.alternateId",
        "src_ip": "client.ipAddress",
        "action": "eventType",
        "status": "Derived from outcome.result"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Azure AD Sign-in Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'azure_ad_signin',
    'Azure AD Sign-in',
    'Parses Azure Active Directory sign-in logs for authentication monitoring.',
    'identity',
    'Microsoft',
    'azure_ad_signin',
    $VRL$
# Azure AD Sign-in Log Parser
# Handles Azure AD sign-in events

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

# Handle records array if present
record = if .records != null { get!(.records, 0) } else { . }

# Extract core Azure AD Sign-in fields
.metadata.id = record.id ?? null
.metadata.correlation_id = record.correlationId ?? null
.metadata.tenant_id = record.tenantId ?? null
.metadata.result_type = record.resultType ?? null
.metadata.result_signature = record.resultSignature ?? null
.metadata.result_description = record.resultDescription ?? null
.metadata.risk_detail = record.riskDetail ?? null
.metadata.risk_level_aggregated = record.riskLevelAggregated ?? null
.metadata.risk_level_during_signin = record.riskLevelDuringSignIn ?? null
.metadata.risk_state = record.riskState ?? null
.metadata.risk_event_types = record.riskEventTypes ?? null
.metadata.resource_display_name = record.resourceDisplayName ?? null
.metadata.resource_id = record.resourceId ?? null

# User information
.user = record.userPrincipalName ?? record.userDisplayName ?? null
.metadata.user_id = record.userId ?? null
.metadata.user_display_name = record.userDisplayName ?? null
.metadata.user_principal_name = record.userPrincipalName ?? null

# Application information
.metadata.app_id = record.appId ?? null
.metadata.app_display_name = record.appDisplayName ?? null
.metadata.client_app_used = record.clientAppUsed ?? null

# Location and device
.src_ip = record.ipAddress ?? null
.metadata.is_interactive = record.isInteractive ?? null
.metadata.token_issuer_type = record.tokenIssuerType ?? null
.metadata.token_issuer_name = record.tokenIssuerName ?? null

# Location details
location = record.location ?? {}
.metadata.city = location.city ?? null
.metadata.state = location.state ?? null
.metadata.country_or_region = location.countryOrRegion ?? null
.metadata.geo_coordinates = location.geoCoordinates ?? null

# Device details
device = record.deviceDetail ?? {}
.metadata.device_id = device.deviceId ?? null
.metadata.display_name = device.displayName ?? null
.metadata.operating_system = device.operatingSystem ?? null
.metadata.browser = device.browser ?? null
.metadata.is_compliant = device.isCompliant ?? null
.metadata.is_managed = device.isManaged ?? null
.metadata.trust_type = device.trustType ?? null

# Status details
status = record.status ?? {}
.metadata.error_code = status.errorCode ?? null
.metadata.failure_reason = status.failureReason ?? null
.metadata.additional_details = status.additionalDetails ?? null

# Conditional access
.metadata.conditional_access_status = record.conditionalAccessStatus ?? null
.metadata.applied_conditional_access_policies = record.appliedConditionalAccessPolicies ?? null

# Authentication details
.metadata.authentication_details = record.authenticationDetails ?? null
.metadata.authentication_methods_used = record.authenticationMethodsUsed ?? null
.metadata.authentication_processing_details = record.authenticationProcessingDetails ?? null
.metadata.authentication_requirement = record.authenticationRequirement ?? null
.metadata.authentication_requirement_policies = record.authenticationRequirementPolicies ?? null

# MFA details
.metadata.mfa_detail = record.mfaDetail ?? null

# Map to UDM fields
.timestamp = parse_timestamp(record.createdDateTime, "%+") ?? 
             parse_timestamp(record.time, "%+") ?? 
             now()

# Action based on sign-in type
.action = if record.isInteractive == true { "interactive_signin" }
          else if record.isInteractive == false { "non_interactive_signin" }
          else { "signin" }

# Determine status from result
result_type = to_string(record.resultType) ?? ""
.status = if result_type == "0" { "success" }
          else if result_type != "" { "failure" }
          else { null }

# Add error code to action if failed
if .status == "failure" && status.errorCode != null {
    .metadata.error_code = status.errorCode
    .metadata.failure_reason = status.failureReason ?? null
}

.source_type = "azure_ad_signin"
$VRL$,
    '[
        {"id": "abc123", "createdDateTime": "2024-01-15T10:30:00Z", "userDisplayName": "John Doe", "userPrincipalName": "john.doe@contoso.com", "userId": "user123", "appId": "app123", "appDisplayName": "Microsoft Office", "ipAddress": "192.168.1.100", "clientAppUsed": "Browser", "conditionalAccessStatus": "success", "isInteractive": true, "riskDetail": "none", "riskLevelAggregated": "none", "riskLevelDuringSignIn": "none", "riskState": "none", "resourceDisplayName": "Office 365", "status": {"errorCode": 0}, "deviceDetail": {"operatingSystem": "Windows 10", "browser": "Chrome 120"}, "location": {"city": "San Francisco", "state": "California", "countryOrRegion": "US"}, "resultType": "0"},
        {"id": "def456", "createdDateTime": "2024-01-15T10:31:00Z", "userDisplayName": "Admin User", "userPrincipalName": "admin@contoso.com", "userId": "user456", "appId": "app456", "appDisplayName": "Azure Portal", "ipAddress": "10.0.0.50", "clientAppUsed": "Browser", "isInteractive": true, "status": {"errorCode": 50126, "failureReason": "Invalid username or password"}, "location": {"countryOrRegion": "US"}, "resultType": "50126"}
    ]'::jsonb,
    '{
        "timestamp": "createdDateTime",
        "user": "userPrincipalName",
        "src_ip": "ipAddress",
        "action": "Derived from isInteractive",
        "status": "Derived from resultType (0=success)"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();

-- Detection patterns for identity parsers
INSERT INTO detection_patterns (source_type, patterns, priority, enabled)
VALUES 
    ('okta', '[
        {"field": "message", "regex": "eventType|displayMessage|actor", "weight": 0.5},
        {"field": "message", "regex": "okta|Okta", "weight": 0.8},
        {"field": "message", "regex": "user\\.session|user\\.authentication|app\\.oauth", "weight": 0.7}
    ]'::jsonb, 88, true),
    ('azure_ad_signin', '[
        {"field": "message", "regex": "userPrincipalName|conditionalAccessStatus", "weight": 0.7},
        {"field": "message", "regex": "isInteractive|tokenIssuerType", "weight": 0.5},
        {"field": "message", "regex": "riskLevel|riskState|riskDetail", "weight": 0.6}
    ]'::jsonb, 86, true)
ON CONFLICT DO NOTHING;


-- ============================================================================
-- APPLICATION CATEGORY PARSERS
-- ============================================================================

-- Apache Access Log Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'apache_access',
    'Apache Access Log',
    'Parses Apache HTTP Server access logs in Common Log Format (CLF) and Combined Log Format.',
    'application',
    'Apache',
    'apache_access',
    $VRL$
# Apache Access Log Parser
# Handles Common Log Format (CLF) and Combined Log Format

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

message = string!(.message) ?? ""

# Try Combined Log Format first (most common)
# Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
combined_match = parse_regex(message, r'^(?P<client_ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?') ?? {}

if combined_match != {} {
    .src_ip = combined_match.client_ip ?? null
    .metadata.ident = if combined_match.ident != "-" { combined_match.ident } else { null }
    .user = if combined_match.user != "-" { combined_match.user } else { null }
    
    # Parse Apache timestamp format: 15/Jan/2024:10:30:00 +0000
    .timestamp = parse_timestamp(combined_match.timestamp, "%d/%b/%Y:%H:%M:%S %z") ?? now()
    
    .metadata.method = combined_match.method ?? null
    .metadata.path = combined_match.path ?? null
    .metadata.protocol = combined_match.protocol ?? null
    .metadata.status_code = to_int(combined_match.status) ?? null
    .metadata.bytes = if combined_match.bytes != "-" { to_int(combined_match.bytes) ?? null } else { null }
    .metadata.referer = if combined_match.referer != "-" && combined_match.referer != "" { combined_match.referer } else { null }
    .metadata.user_agent = combined_match.user_agent ?? null
    
    # Map HTTP method to action
    method = upcase(combined_match.method ?? "")
    .action = if method == "GET" { "http_get" }
              else if method == "POST" { "http_post" }
              else if method == "PUT" { "http_put" }
              else if method == "DELETE" { "http_delete" }
              else if method == "PATCH" { "http_patch" }
              else if method == "HEAD" { "http_head" }
              else if method == "OPTIONS" { "http_options" }
              else { "http_request" }
    
    # Determine status from HTTP status code
    status_code = to_int(combined_match.status) ?? 0
    .status = if status_code >= 200 && status_code < 300 { "success" }
              else if status_code >= 300 && status_code < 400 { "redirect" }
              else if status_code >= 400 && status_code < 500 { "client_error" }
              else if status_code >= 500 { "server_error" }
              else { null }
    
    # Security-relevant status codes
    .metadata.is_error = status_code >= 400
    .metadata.is_auth_failure = status_code == 401 || status_code == 403
} else {
    # Try Common Log Format (without referer and user-agent)
    clf_match = parse_regex(message, r'^(?P<client_ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\S+)') ?? {}
    
    if clf_match != {} {
        .src_ip = clf_match.client_ip ?? null
        .user = if clf_match.user != "-" { clf_match.user } else { null }
        .timestamp = parse_timestamp(clf_match.timestamp, "%d/%b/%Y:%H:%M:%S %z") ?? now()
        
        # Parse request line
        request_parts = split(clf_match.request ?? "", " ")
        .metadata.method = get(request_parts, 0) ?? null
        .metadata.path = get(request_parts, 1) ?? null
        .metadata.protocol = get(request_parts, 2) ?? null
        .metadata.status_code = to_int(clf_match.status) ?? null
        .metadata.bytes = if clf_match.bytes != "-" { to_int(clf_match.bytes) ?? null } else { null }
        
        .action = "http_request"
        status_code = to_int(clf_match.status) ?? 0
        .status = if status_code >= 200 && status_code < 400 { "success" } else { "failure" }
    } else {
        # Fallback - store as-is
        .metadata.raw_message = message
        .timestamp = now()
        .action = "apache_access"
    }
}

# Extract query string if present
path = .metadata.path ?? ""
if contains(path, "?") {
    parts = split(path, "?")
    .metadata.path = get(parts, 0) ?? path
    .metadata.query_string = get(parts, 1) ?? null
}

.source_type = "apache_access"
$VRL$,
    '[
        "192.168.1.100 - john.doe [15/Jan/2024:10:30:00 +0000] \"GET /api/users?page=1 HTTP/1.1\" 200 1234 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"",
        "10.0.0.50 - - [15/Jan/2024:10:31:00 +0000] \"POST /api/login HTTP/1.1\" 401 89 \"-\" \"curl/7.68.0\"",
        "172.16.0.1 - admin [15/Jan/2024:10:32:00 +0000] \"DELETE /api/users/123 HTTP/1.1\" 204 0 \"https://admin.example.com/\" \"Mozilla/5.0\""
    ]'::jsonb,
    '{
        "timestamp": "Apache timestamp [dd/Mon/yyyy:HH:mm:ss +zzzz]",
        "src_ip": "Client IP (first field)",
        "user": "Authenticated user (third field)",
        "action": "Derived from HTTP method",
        "status": "Derived from HTTP status code",
        "metadata.method": "HTTP method",
        "metadata.path": "Request path",
        "metadata.status_code": "HTTP status code"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Apache Error Log Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'apache_error',
    'Apache Error Log',
    'Parses Apache HTTP Server error logs for troubleshooting and security monitoring.',
    'application',
    'Apache',
    'apache_error',
    $VRL$
# Apache Error Log Parser
# Handles Apache 2.4+ error log format

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

message = string!(.message) ?? ""

# Apache 2.4+ error log format:
# [timestamp] [module:level] [pid tid] [client ip:port] message
# Example: [Mon Jan 15 10:30:00.123456 2024] [ssl:error] [pid 1234:tid 5678] [client 192.168.1.100:54321] AH02032: Hostname provided via SNI...

error_match = parse_regex(message, r'^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<module>\w+)?:?(?P<level>\w+)\]\s+\[pid\s+(?P<pid>\d+)(?::tid\s+(?P<tid>\d+))?\](?:\s+\[client\s+(?P<client_ip>[^\]:]+)(?::(?P<client_port>\d+))?\])?\s*(?P<message>.*)$') ?? {}

if error_match != {} {
    # Parse timestamp - Apache error log format: Mon Jan 15 10:30:00.123456 2024
    .timestamp = parse_timestamp(error_match.timestamp, "%a %b %d %H:%M:%S%.f %Y") ?? 
                 parse_timestamp(error_match.timestamp, "%a %b %d %H:%M:%S %Y") ?? 
                 now()
    
    .metadata.module = error_match.module ?? null
    .metadata.level = error_match.level ?? null
    .metadata.pid = to_int(error_match.pid) ?? null
    .metadata.tid = to_int(error_match.tid) ?? null
    .src_ip = error_match.client_ip ?? null
    .src_port = to_int(error_match.client_port) ?? null
    .metadata.error_message = error_match.message ?? null
    
    # Map level to severity
    level = downcase(error_match.level ?? "")
    .metadata.severity = if level == "emerg" { 0 }
                         else if level == "alert" { 1 }
                         else if level == "crit" { 2 }
                         else if level == "error" { 3 }
                         else if level == "warn" { 4 }
                         else if level == "notice" { 5 }
                         else if level == "info" { 6 }
                         else if level == "debug" { 7 }
                         else if level == "trace1" || level == "trace2" || level == "trace3" || level == "trace4" || level == "trace5" || level == "trace6" || level == "trace7" || level == "trace8" { 8 }
                         else { null }
    
    # Determine action from level
    .action = if level == "error" || level == "crit" || level == "alert" || level == "emerg" { "error" }
              else if level == "warn" { "warning" }
              else { "apache_error_log" }
    
    .status = if level == "error" || level == "crit" || level == "alert" || level == "emerg" { "failure" }
              else { null }
    
    # Extract Apache error codes (AH#####)
    ah_match = parse_regex(error_match.message ?? "", r'AH(?P<code>\d+)') ?? {}
    if ah_match.code != null {
        .metadata.apache_error_code = "AH" + (ah_match.code ?? "")
    }
} else {
    # Try older Apache 2.2 format: [timestamp] [level] [client ip] message
    old_match = parse_regex(message, r'^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>\w+)\](?:\s+\[client\s+(?P<client_ip>[^\]]+)\])?\s*(?P<message>.*)$') ?? {}
    
    if old_match != {} {
        .timestamp = parse_timestamp(old_match.timestamp, "%a %b %d %H:%M:%S %Y") ?? now()
        .metadata.level = old_match.level ?? null
        .src_ip = old_match.client_ip ?? null
        .metadata.error_message = old_match.message ?? null
        .action = "apache_error_log"
    } else {
        # Fallback
        .metadata.raw_message = message
        .timestamp = now()
        .action = "apache_error"
    }
}

.source_type = "apache_error"
$VRL$,
    '[
        "[Mon Jan 15 10:30:00.123456 2024] [ssl:error] [pid 1234:tid 5678] [client 192.168.1.100:54321] AH02032: Hostname provided via SNI and target server do not match",
        "[Mon Jan 15 10:31:00.000000 2024] [core:error] [pid 1234:tid 5678] [client 10.0.0.50:12345] AH00126: Invalid URI in request GET /../../etc/passwd HTTP/1.1",
        "[Mon Jan 15 10:32:00.000000 2024] [authz_core:error] [pid 1234:tid 5678] [client 172.16.0.1:8080] AH01630: client denied by server configuration: /var/www/html/admin"
    ]'::jsonb,
    '{
        "timestamp": "Apache error timestamp",
        "src_ip": "Client IP from [client ip:port]",
        "action": "Derived from log level",
        "status": "failure for error/crit/alert/emerg",
        "metadata.level": "Apache log level",
        "metadata.module": "Apache module name",
        "metadata.apache_error_code": "AH##### error code"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Nginx Access Log Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'nginx_access',
    'Nginx Access Log',
    'Parses Nginx HTTP Server access logs in default combined format.',
    'application',
    'Nginx',
    'nginx_access',
    $VRL$
# Nginx Access Log Parser
# Handles default combined log format

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

message = string!(.message) ?? ""

# Nginx combined log format (default):
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
# Extended format may include: $request_time $upstream_response_time

combined_match = parse_regex(message, r'^(?P<remote_addr>\S+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<time_local>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<body_bytes>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"(?:\s+(?P<request_time>[\d\.]+))?(?:\s+(?P<upstream_time>[\d\.\-]+))?') ?? {}

if combined_match != {} {
    .src_ip = combined_match.remote_addr ?? null
    .user = if combined_match.remote_user != "-" { combined_match.remote_user } else { null }
    
    # Parse Nginx timestamp format: 15/Jan/2024:10:30:00 +0000
    .timestamp = parse_timestamp(combined_match.time_local, "%d/%b/%Y:%H:%M:%S %z") ?? now()
    
    .metadata.method = combined_match.method ?? null
    .metadata.path = combined_match.path ?? null
    .metadata.protocol = combined_match.protocol ?? null
    .metadata.status_code = to_int(combined_match.status) ?? null
    .metadata.body_bytes = to_int(combined_match.body_bytes) ?? null
    .metadata.referer = if combined_match.referer != "-" && combined_match.referer != "" { combined_match.referer } else { null }
    .metadata.user_agent = combined_match.user_agent ?? null
    .metadata.request_time = to_float(combined_match.request_time) ?? null
    .metadata.upstream_response_time = if combined_match.upstream_time != "-" { to_float(combined_match.upstream_time) ?? null } else { null }
    
    # Map HTTP method to action
    method = upcase(combined_match.method ?? "")
    .action = if method == "GET" { "http_get" }
              else if method == "POST" { "http_post" }
              else if method == "PUT" { "http_put" }
              else if method == "DELETE" { "http_delete" }
              else if method == "PATCH" { "http_patch" }
              else if method == "HEAD" { "http_head" }
              else if method == "OPTIONS" { "http_options" }
              else { "http_request" }
    
    # Determine status from HTTP status code
    status_code = to_int(combined_match.status) ?? 0
    .status = if status_code >= 200 && status_code < 300 { "success" }
              else if status_code >= 300 && status_code < 400 { "redirect" }
              else if status_code >= 400 && status_code < 500 { "client_error" }
              else if status_code >= 500 { "server_error" }
              else { null }
    
    .metadata.is_error = status_code >= 400
    .metadata.is_auth_failure = status_code == 401 || status_code == 403
} else {
    # Try JSON format (common for structured logging)
    if starts_with(message, "{") {
        json_log = parse_json(message) ?? {}
        if json_log != {} {
            .src_ip = json_log.remote_addr ?? json_log.client_ip ?? null
            .user = json_log.remote_user ?? json_log.user ?? null
            .timestamp = parse_timestamp(json_log.time_local ?? json_log.timestamp ?? "", "%d/%b/%Y:%H:%M:%S %z") ?? 
                         parse_timestamp(json_log.time_iso8601 ?? "", "%+") ?? 
                         now()
            .metadata.method = json_log.request_method ?? null
            .metadata.path = json_log.request_uri ?? json_log.uri ?? null
            .metadata.status_code = to_int(json_log.status) ?? null
            .metadata.body_bytes = to_int(json_log.body_bytes_sent) ?? null
            .metadata.referer = json_log.http_referer ?? null
            .metadata.user_agent = json_log.http_user_agent ?? null
            .metadata.request_time = to_float(json_log.request_time) ?? null
            .action = "http_request"
            status_code = to_int(json_log.status) ?? 0
            .status = if status_code >= 200 && status_code < 400 { "success" } else { "failure" }
        }
    } else {
        .metadata.raw_message = message
        .timestamp = now()
        .action = "nginx_access"
    }
}

# Extract query string if present
path = .metadata.path ?? ""
if contains(path, "?") {
    parts = split(path, "?")
    .metadata.path = get(parts, 0) ?? path
    .metadata.query_string = get(parts, 1) ?? null
}

.source_type = "nginx_access"
$VRL$,
    '[
        "192.168.1.100 - john.doe [15/Jan/2024:10:30:00 +0000] \"GET /api/users?page=1 HTTP/1.1\" 200 1234 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\" 0.050 0.048",
        "10.0.0.50 - - [15/Jan/2024:10:31:00 +0000] \"POST /api/login HTTP/1.1\" 401 89 \"-\" \"curl/7.68.0\"",
        "172.16.0.1 - - [15/Jan/2024:10:32:00 +0000] \"GET /static/app.js HTTP/2.0\" 304 0 \"https://example.com/\" \"Mozilla/5.0\""
    ]'::jsonb,
    '{
        "timestamp": "Nginx timestamp [dd/Mon/yyyy:HH:mm:ss +zzzz]",
        "src_ip": "remote_addr (first field)",
        "user": "remote_user (third field)",
        "action": "Derived from HTTP method",
        "status": "Derived from HTTP status code",
        "metadata.request_time": "Request processing time in seconds"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();


-- Nginx Error Log Parser
INSERT INTO parser_library (name, display_name, description, category, vendor, source_type, parser_vrl, sample_logs, field_mappings, version, is_system)
VALUES (
    'nginx_error',
    'Nginx Error Log',
    'Parses Nginx HTTP Server error logs for troubleshooting and security monitoring.',
    'application',
    'Nginx',
    'nginx_error',
    $VRL$
# Nginx Error Log Parser
# Handles Nginx error log format

# Store raw content
.raw_content = encode_json(.)

# Initialize metadata
.metadata = {}

message = string!(.message) ?? ""

# Nginx error log format:
# YYYY/MM/DD HH:MM:SS [level] pid#tid: *cid message, client: ip, server: server, request: "method path protocol", host: "host"
# Example: 2024/01/15 10:30:00 [error] 1234#5678: *9012 open() "/var/www/html/missing.html" failed (2: No such file or directory), client: 192.168.1.100, server: example.com, request: "GET /missing.html HTTP/1.1", host: "example.com"

error_match = parse_regex(message, r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+(?:\*(?P<cid>\d+)\s+)?(?P<error_message>.*)$') ?? {}

if error_match != {} {
    # Parse timestamp: 2024/01/15 10:30:00
    .timestamp = parse_timestamp(error_match.timestamp, "%Y/%m/%d %H:%M:%S") ?? now()
    
    .metadata.level = error_match.level ?? null
    .metadata.pid = to_int(error_match.pid) ?? null
    .metadata.tid = to_int(error_match.tid) ?? null
    .metadata.connection_id = to_int(error_match.cid) ?? null
    
    error_msg = error_match.error_message ?? ""
    .metadata.error_message = error_msg
    
    # Extract client IP
    client_match = parse_regex(error_msg, r'client:\s*(?P<client_ip>[\d\.]+)') ?? {}
    .src_ip = client_match.client_ip ?? null
    
    # Extract server
    server_match = parse_regex(error_msg, r'server:\s*(?P<server>\S+)') ?? {}
    .dest_host = server_match.server ?? null
    
    # Extract request details
    request_match = parse_regex(error_msg, r'request:\s*"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"') ?? {}
    .metadata.method = request_match.method ?? null
    .metadata.path = request_match.path ?? null
    .metadata.protocol = request_match.protocol ?? null
    
    # Extract host
    host_match = parse_regex(error_msg, r'host:\s*"(?P<host>[^"]+)"') ?? {}
    .metadata.host = host_match.host ?? null
    
    # Extract upstream if present
    upstream_match = parse_regex(error_msg, r'upstream:\s*"(?P<upstream>[^"]+)"') ?? {}
    .metadata.upstream = upstream_match.upstream ?? null
    
    # Map level to severity
    level = downcase(error_match.level ?? "")
    .metadata.severity = if level == "emerg" { 0 }
                         else if level == "alert" { 1 }
                         else if level == "crit" { 2 }
                         else if level == "error" { 3 }
                         else if level == "warn" { 4 }
                         else if level == "notice" { 5 }
                         else if level == "info" { 6 }
                         else if level == "debug" { 7 }
                         else { null }
    
    # Determine action from level
    .action = if level == "error" || level == "crit" || level == "alert" || level == "emerg" { "error" }
              else if level == "warn" { "warning" }
              else { "nginx_error_log" }
    
    .status = if level == "error" || level == "crit" || level == "alert" || level == "emerg" { "failure" }
              else { null }
    
    # Detect common error types
    .metadata.error_type = if contains(error_msg, "No such file or directory") { "file_not_found" }
                           else if contains(error_msg, "Permission denied") { "permission_denied" }
                           else if contains(error_msg, "connect() failed") { "upstream_connection_failed" }
                           else if contains(error_msg, "upstream timed out") { "upstream_timeout" }
                           else if contains(error_msg, "SSL") || contains(error_msg, "ssl") { "ssl_error" }
                           else if contains(error_msg, "limiting requests") { "rate_limited" }
                           else { null }
} else {
    # Fallback
    .metadata.raw_message = message
    .timestamp = now()
    .action = "nginx_error"
}

.source_type = "nginx_error"
$VRL$,
    '[
        "2024/01/15 10:30:00 [error] 1234#5678: *9012 open() \"/var/www/html/missing.html\" failed (2: No such file or directory), client: 192.168.1.100, server: example.com, request: \"GET /missing.html HTTP/1.1\", host: \"example.com\"",
        "2024/01/15 10:31:00 [error] 1234#5678: *9013 connect() failed (111: Connection refused) while connecting to upstream, client: 10.0.0.50, server: api.example.com, request: \"POST /api/data HTTP/1.1\", upstream: \"http://127.0.0.1:8080/api/data\", host: \"api.example.com\"",
        "2024/01/15 10:32:00 [warn] 1234#5678: *9014 limiting requests, excess: 10.234 by zone \"api_limit\", client: 172.16.0.1, server: example.com, request: \"GET /api/users HTTP/1.1\", host: \"example.com\""
    ]'::jsonb,
    '{
        "timestamp": "Nginx error timestamp YYYY/MM/DD HH:MM:SS",
        "src_ip": "Extracted from client: field",
        "dest_host": "Extracted from server: field",
        "action": "Derived from log level",
        "status": "failure for error/crit/alert/emerg",
        "metadata.level": "Nginx log level",
        "metadata.error_type": "Categorized error type"
    }'::jsonb,
    '1.0.0',
    true
) ON CONFLICT (name) DO UPDATE SET
    parser_vrl = EXCLUDED.parser_vrl,
    sample_logs = EXCLUDED.sample_logs,
    field_mappings = EXCLUDED.field_mappings,
    updated_at = NOW();

-- Detection patterns for application parsers
INSERT INTO detection_patterns (source_type, patterns, priority, enabled)
VALUES 
    ('apache_access', '[
        {"field": "message", "regex": "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\s+-\\s+", "weight": 0.6},
        {"field": "message", "regex": "\\[\\d{2}/\\w{3}/\\d{4}:\\d{2}:\\d{2}:\\d{2}", "weight": 0.7},
        {"field": "message", "regex": "\"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\s+", "weight": 0.5}
    ]'::jsonb, 70, true),
    ('apache_error', '[
        {"field": "message", "regex": "^\\[\\w{3}\\s+\\w{3}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}", "weight": 0.6},
        {"field": "message", "regex": "\\[\\w+:error\\]|\\[error\\]|\\[warn\\]", "weight": 0.7},
        {"field": "message", "regex": "AH\\d{5}", "weight": 0.8}
    ]'::jsonb, 72, true),
    ('nginx_access', '[
        {"field": "message", "regex": "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\s+-\\s+", "weight": 0.5},
        {"field": "message", "regex": "HTTP/[12]\\.[01]\"\\s+\\d{3}\\s+\\d+", "weight": 0.6},
        {"field": "message", "regex": "nginx|Nginx", "weight": 0.4}
    ]'::jsonb, 68, true),
    ('nginx_error', '[
        {"field": "message", "regex": "^\\d{4}/\\d{2}/\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}", "weight": 0.7},
        {"field": "message", "regex": "\\[error\\]|\\[warn\\]|\\[crit\\]", "weight": 0.6},
        {"field": "message", "regex": "\\d+#\\d+:", "weight": 0.5}
    ]'::jsonb, 71, true)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- SUMMARY
-- ============================================================================
-- This migration seeds the parser_library table with pre-built parsers for:
-- 
-- ENDPOINT (2 parsers):
--   - windows_event: Windows Security Event Logs
--   - sysmon: Microsoft Sysmon endpoint telemetry
--
-- NETWORK (3 parsers):
--   - palo_alto: Palo Alto Networks firewall logs
--   - cisco_asa: Cisco ASA firewall logs
--   - syslog: Standard syslog (RFC 3164/5424)
--
-- CLOUD (3 parsers):
--   - aws_cloudtrail: AWS CloudTrail API audit logs
--   - aws_guardduty: AWS GuardDuty threat findings
--   - azure_activity: Azure Activity Log
--
-- IDENTITY (2 parsers):
--   - okta: Okta System Log
--   - azure_ad_signin: Azure AD Sign-in logs
--
-- APPLICATION (4 parsers):
--   - apache_access: Apache HTTP access logs
--   - apache_error: Apache HTTP error logs
--   - nginx_access: Nginx HTTP access logs
--   - nginx_error: Nginx HTTP error logs
--
-- Total: 14 pre-built parsers with detection patterns for auto-detection
