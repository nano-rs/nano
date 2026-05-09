-- Migration: Query Library
-- A collection of example queries to help users learn the query language
-- and discover useful patterns for security analysis.

CREATE TABLE IF NOT EXISTS query_library (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    query TEXT NOT NULL,
    category TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    difficulty TEXT NOT NULL DEFAULT 'beginner', -- beginner, intermediate, advanced
    use_case TEXT, -- detection, investigation, reporting, dashboard
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_builtin BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(name)
);

-- Index for category filtering
CREATE INDEX IF NOT EXISTS idx_query_library_category ON query_library(category);

-- Index for tag searches
CREATE INDEX IF NOT EXISTS idx_query_library_tags ON query_library USING GIN(tags);

-- Comments
COMMENT ON TABLE query_library IS 'Library of example queries to help users learn the query language';
COMMENT ON COLUMN query_library.category IS 'Category: basics, filtering, aggregation, risk, network, authentication, threat-hunting, reporting';
COMMENT ON COLUMN query_library.difficulty IS 'Difficulty level: beginner, intermediate, advanced';
COMMENT ON COLUMN query_library.use_case IS 'Primary use case: detection, investigation, reporting, dashboard';
COMMENT ON COLUMN query_library.is_builtin IS 'Whether this is a built-in query (vs user-created)';

-- =============================================================================
-- BASICS - Getting Started
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('All Events', 'Show all events (no filter)', '*', 'basics', ARRAY['getting-started'], 'beginner', 'investigation'),
('Search by Keyword', 'Find events containing a specific word', 'error', 'basics', ARRAY['getting-started', 'text-search'], 'beginner', 'investigation'),
('Multiple Keywords (AND)', 'Find events containing multiple words', 'error AND authentication', 'basics', ARRAY['getting-started', 'text-search'], 'beginner', 'investigation'),
('Multiple Keywords (OR)', 'Find events containing either word', 'error OR warning', 'basics', ARRAY['getting-started', 'text-search'], 'beginner', 'investigation'),
('Exclude Keywords', 'Find events without a specific word', 'error NOT debug', 'basics', ARRAY['getting-started', 'text-search'], 'beginner', 'investigation'),
('Wildcard Search', 'Search with wildcards', 'fail*', 'basics', ARRAY['getting-started', 'text-search', 'wildcard'], 'beginner', 'investigation'),
('Phrase Search', 'Search for an exact phrase', '"connection refused"', 'basics', ARRAY['getting-started', 'text-search'], 'beginner', 'investigation');

-- =============================================================================
-- FILTERING - Field-based queries
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('Filter by Source Type', 'Show events from a specific source', 'source_type=apache', 'filtering', ARRAY['field-filter', 'source'], 'beginner', 'investigation'),
('Filter by Status Code', 'Find HTTP errors (4xx/5xx)', 'status>=400', 'filtering', ARRAY['field-filter', 'http', 'errors'], 'beginner', 'investigation'),
('Filter by IP Address', 'Find events from a specific IP', 'src_ip="192.168.1.100"', 'filtering', ARRAY['field-filter', 'network', 'ip'], 'beginner', 'investigation'),
('Filter by User', 'Find events for a specific user', 'user="admin"', 'filtering', ARRAY['field-filter', 'authentication'], 'beginner', 'investigation'),
('Filter by Action', 'Find specific actions', 'action="login"', 'filtering', ARRAY['field-filter', 'authentication'], 'beginner', 'investigation'),
('Combine Filters', 'Multiple field conditions', 'source_type=apache status>=400 method="POST"', 'filtering', ARRAY['field-filter', 'http'], 'intermediate', 'investigation'),
('Not Equal Filter', 'Exclude specific values', 'status!=200', 'filtering', ARRAY['field-filter', 'http'], 'beginner', 'investigation'),
('Numeric Range', 'Filter by numeric range', 'bytes>1000000', 'filtering', ARRAY['field-filter', 'network'], 'beginner', 'investigation'),
('IN Operator', 'Match multiple values', 'status IN (401, 403, 404)', 'filtering', ARRAY['field-filter', 'http'], 'intermediate', 'investigation'),
('CIDR Network Filter', 'Filter by IP subnet', 'src_ip IN CIDR "10.0.0.0/8"', 'filtering', ARRAY['field-filter', 'network', 'ip', 'cidr'], 'intermediate', 'investigation');

-- =============================================================================
-- AGGREGATION - Stats and grouping
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('Count All Events', 'Total event count', '* | stats count()', 'aggregation', ARRAY['stats', 'count'], 'beginner', 'reporting'),
('Count by Source', 'Events per source type', '* | stats count() by source_type', 'aggregation', ARRAY['stats', 'count', 'group-by'], 'beginner', 'reporting'),
('Count by Status', 'HTTP status code distribution', 'source_type=apache | stats count() by status', 'aggregation', ARRAY['stats', 'count', 'http'], 'beginner', 'reporting'),
('Top IPs by Request Count', 'Most active IP addresses', '* | stats count() as requests by src_ip | sort -requests | head 10', 'aggregation', ARRAY['stats', 'top', 'network'], 'intermediate', 'investigation'),
('Average Response Size', 'Average bytes per request', 'source_type=apache | stats avg(bytes) as avg_bytes', 'aggregation', ARRAY['stats', 'avg', 'http'], 'beginner', 'reporting'),
('Sum of Bytes Transferred', 'Total data transfer', 'source_type=apache | stats sum(bytes) as total_bytes', 'aggregation', ARRAY['stats', 'sum', 'network'], 'beginner', 'reporting'),
('Min/Max Values', 'Find extremes', '* | stats min(bytes) as min_bytes, max(bytes) as max_bytes', 'aggregation', ARRAY['stats', 'min', 'max'], 'beginner', 'reporting'),
('Distinct Count', 'Count unique values', '* | stats dc(src_ip) as unique_ips', 'aggregation', ARRAY['stats', 'distinct', 'cardinality'], 'intermediate', 'reporting'),
('Multiple Aggregations', 'Combine multiple stats', '* | stats count() as events, dc(src_ip) as unique_ips, sum(bytes) as total_bytes by source_type', 'aggregation', ARRAY['stats', 'multiple'], 'intermediate', 'reporting'),
('Percentiles', 'Calculate percentiles', 'source_type=apache | stats p50(response_time) as median, p95(response_time) as p95, p99(response_time) as p99', 'aggregation', ARRAY['stats', 'percentile', 'performance'], 'advanced', 'reporting');

-- =============================================================================
-- TIME ANALYSIS - Time-based queries
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('Events Over Time (Hourly)', 'Event count per hour', '* | bin span=1h | stats count() by _time', 'time-analysis', ARRAY['timechart', 'hourly'], 'beginner', 'dashboard'),
('Events Over Time (Daily)', 'Event count per day', '* | bin span=1d | stats count() by _time', 'time-analysis', ARRAY['timechart', 'daily'], 'beginner', 'dashboard'),
('Errors Over Time', 'Error trend analysis', 'status>=400 | bin span=1h | stats count() by _time', 'time-analysis', ARRAY['timechart', 'errors'], 'intermediate', 'dashboard'),
('Traffic by Hour of Day', 'Hourly traffic pattern', '* | eval hour=strftime("%H", timestamp) | stats count() by hour | sort hour', 'time-analysis', ARRAY['pattern', 'hourly'], 'intermediate', 'reporting'),
('Busiest Hours', 'Find peak traffic times', '* | bin span=1h | stats count() as events by _time | sort -events | head 10', 'time-analysis', ARRAY['peak', 'performance'], 'intermediate', 'reporting');

-- =============================================================================
-- RISK & SIGNALS - Risk-based alerting
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('All Signals', 'View all detection signals', 'source_type=signals', 'risk', ARRAY['signals', 'detection'], 'beginner', 'investigation'),
('Signals by Severity', 'Group signals by severity level', 'source_type=signals | stats count() by severity', 'risk', ARRAY['signals', 'severity'], 'beginner', 'reporting'),
('High Risk Entities (24h)', 'Entities with risk score > 80 in last 24 hours', 'source_type=signals | bin span=24h | stats sum(risk_score) as total_risk by risk_entity | where total_risk > 80', 'risk', ARRAY['signals', 'risk-score', 'threshold'], 'intermediate', 'detection'),
('High Risk Entities (7d)', 'Entities with sustained high risk over 7 days', 'source_type=signals | bin span=7d | stats sum(risk_score) as total_risk by risk_entity | where total_risk > 90', 'risk', ARRAY['signals', 'risk-score', 'threshold'], 'intermediate', 'detection'),
('Risk Score Distribution', 'Distribution of risk scores', 'source_type=signals | stats count() by risk_score | sort risk_score', 'risk', ARRAY['signals', 'risk-score', 'distribution'], 'beginner', 'reporting'),
('Top Risky IPs', 'IPs with highest cumulative risk', 'source_type=signals | stats sum(risk_score) as total_risk, count() as signal_count by risk_entity | sort -total_risk | head 20', 'risk', ARRAY['signals', 'risk-score', 'top'], 'intermediate', 'investigation'),
('Signals by Rule', 'Which detection rules are firing most', 'source_type=signals | stats count() by rule_name | sort -count', 'risk', ARRAY['signals', 'detection', 'rules'], 'beginner', 'reporting'),
('Alert Timeline', 'Alerts over time', 'source_type=signals signal_type=alert | bin span=1h | stats count() by _time', 'risk', ARRAY['signals', 'alerts', 'timeline'], 'beginner', 'dashboard'),
('Risk Accumulation Rate', 'How fast is risk accumulating per entity', 'source_type=signals | bin span=1h | stats sum(risk_score) as hourly_risk by risk_entity, _time | sort risk_entity, _time', 'risk', ARRAY['signals', 'risk-score', 'trend'], 'advanced', 'investigation');

-- =============================================================================
-- NETWORK ANALYSIS
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('Top Talkers', 'Most active source IPs', '* | stats count() as connections by src_ip | sort -connections | head 20', 'network', ARRAY['ip', 'traffic', 'top'], 'beginner', 'investigation'),
('Top Destinations', 'Most accessed destination IPs', '* | stats count() as connections by dst_ip | sort -connections | head 20', 'network', ARRAY['ip', 'traffic', 'top'], 'beginner', 'investigation'),
('Unique IPs per Hour', 'IP diversity over time', '* | bin span=1h | stats dc(src_ip) as unique_ips by _time', 'network', ARRAY['ip', 'cardinality', 'timeline'], 'intermediate', 'dashboard'),
('Data Transfer by IP', 'Bandwidth usage per IP', '* | stats sum(bytes) as total_bytes by src_ip | sort -total_bytes | head 20', 'network', ARRAY['ip', 'bandwidth', 'top'], 'intermediate', 'investigation'),
('Internal vs External Traffic', 'Traffic from internal networks', 'src_ip IN CIDR "10.0.0.0/8" OR src_ip IN CIDR "192.168.0.0/16" OR src_ip IN CIDR "172.16.0.0/12" | stats count() as internal_traffic', 'network', ARRAY['ip', 'cidr', 'internal'], 'intermediate', 'reporting'),
('Port Scan Detection', 'IPs hitting many ports', '* | stats dc(dst_port) as unique_ports by src_ip | where unique_ports > 100 | sort -unique_ports', 'network', ARRAY['ip', 'port-scan', 'threat'], 'advanced', 'detection'),
('Unusual Ports', 'Traffic on non-standard ports', 'dst_port NOT IN (80, 443, 22, 21, 25, 53) | stats count() by dst_port | sort -count | head 20', 'network', ARRAY['port', 'anomaly'], 'intermediate', 'investigation');

-- =============================================================================
-- AUTHENTICATION & ACCESS
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('Failed Logins', 'All failed authentication attempts', 'action=login status=failure', 'authentication', ARRAY['login', 'failure', 'security'], 'beginner', 'investigation'),
('Failed Logins by User', 'Users with most failed logins', 'action=login status=failure | stats count() as failures by user | sort -failures | head 20', 'authentication', ARRAY['login', 'failure', 'brute-force'], 'intermediate', 'detection'),
('Failed Logins by IP', 'IPs with most failed logins', 'action=login status=failure | stats count() as failures by src_ip | sort -failures | head 20', 'authentication', ARRAY['login', 'failure', 'brute-force'], 'intermediate', 'detection'),
('Brute Force Detection', 'IPs with >10 failed logins in 5 minutes', 'action=login status=failure | bin span=5m | stats count() as attempts by src_ip, _time | where attempts > 10', 'authentication', ARRAY['login', 'brute-force', 'detection'], 'advanced', 'detection'),
('Successful Logins After Failures', 'Potential compromised accounts', 'action=login | stats count(eval(status="failure")) as failures, count(eval(status="success")) as successes by user | where failures > 5 AND successes > 0', 'authentication', ARRAY['login', 'compromise', 'detection'], 'advanced', 'detection'),
('Login Times', 'When do users typically log in', 'action=login status=success | eval hour=strftime("%H", timestamp) | stats count() by hour | sort hour', 'authentication', ARRAY['login', 'pattern', 'baseline'], 'intermediate', 'reporting'),
('Off-Hours Logins', 'Logins outside business hours (before 8am or after 6pm)', 'action=login status=success | eval hour=strftime("%H", timestamp) | where hour < 8 OR hour > 18', 'authentication', ARRAY['login', 'anomaly', 'off-hours'], 'intermediate', 'detection'),
('Admin Activity', 'Track administrator actions', 'user IN ("admin", "root", "administrator") | stats count() by action, user', 'authentication', ARRAY['admin', 'privileged', 'audit'], 'beginner', 'investigation');

-- =============================================================================
-- HTTP/WEB ANALYSIS
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('HTTP Error Rate', 'Percentage of requests that are errors', 'source_type=apache | stats count() as total, count(eval(status>=400)) as errors | eval error_rate=round(errors/total*100, 2)', 'http', ARRAY['errors', 'rate', 'health'], 'intermediate', 'dashboard'),
('Top URLs', 'Most requested URLs', 'source_type=apache | stats count() as requests by uri | sort -requests | head 20', 'http', ARRAY['url', 'top', 'traffic'], 'beginner', 'reporting'),
('404 Not Found', 'Missing resources', 'source_type=apache status=404 | stats count() by uri | sort -count | head 20', 'http', ARRAY['404', 'errors', 'missing'], 'beginner', 'investigation'),
('500 Server Errors', 'Internal server errors', 'source_type=apache status>=500 | stats count() by uri, status | sort -count', 'http', ARRAY['500', 'errors', 'server'], 'beginner', 'investigation'),
('Slow Requests', 'Requests taking > 5 seconds', 'source_type=apache response_time>5000 | stats count() by uri | sort -count | head 20', 'http', ARRAY['performance', 'slow', 'latency'], 'intermediate', 'investigation'),
('HTTP Methods Distribution', 'Breakdown by HTTP method', 'source_type=apache | stats count() by method', 'http', ARRAY['method', 'distribution'], 'beginner', 'reporting'),
('Large Responses', 'Responses over 10MB', 'source_type=apache bytes>10000000 | stats count() by uri | sort -count', 'http', ARRAY['bandwidth', 'large', 'performance'], 'intermediate', 'investigation'),
('User Agents', 'Top user agents (browsers/bots)', 'source_type=apache | stats count() by user_agent | sort -count | head 20', 'http', ARRAY['user-agent', 'browser', 'bot'], 'beginner', 'reporting'),
('Bot Detection', 'Identify potential bots', 'source_type=apache user_agent="*bot*" OR user_agent="*crawler*" OR user_agent="*spider*" | stats count() by user_agent, src_ip', 'http', ARRAY['bot', 'crawler', 'detection'], 'intermediate', 'investigation'),
('Referrer Analysis', 'Where is traffic coming from', 'source_type=apache referrer!="" referrer!="-" | stats count() by referrer | sort -count | head 20', 'http', ARRAY['referrer', 'traffic-source'], 'beginner', 'reporting');

-- =============================================================================
-- THREAT HUNTING
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('SQL Injection Attempts', 'Potential SQL injection in URLs', 'uri="*SELECT*" OR uri="*UNION*" OR uri="*DROP*" OR uri="*--*" OR uri="*;*"', 'threat-hunting', ARRAY['sqli', 'injection', 'attack'], 'intermediate', 'detection'),
('XSS Attempts', 'Potential cross-site scripting', 'uri="*<script*" OR uri="*javascript:*" OR uri="*onerror=*"', 'threat-hunting', ARRAY['xss', 'injection', 'attack'], 'intermediate', 'detection'),
('Path Traversal', 'Directory traversal attempts', 'uri="*..*" OR uri="*%2e%2e*"', 'threat-hunting', ARRAY['path-traversal', 'lfi', 'attack'], 'intermediate', 'detection'),
('Suspicious User Agents', 'Known malicious user agents', 'user_agent="*sqlmap*" OR user_agent="*nikto*" OR user_agent="*nmap*" OR user_agent="*masscan*"', 'threat-hunting', ARRAY['scanner', 'tool', 'recon'], 'intermediate', 'detection'),
('High Volume Single IP', 'Single IP making many requests', '* | stats count() as requests by src_ip | where requests > 1000 | sort -requests', 'threat-hunting', ARRAY['dos', 'volume', 'anomaly'], 'intermediate', 'detection'),
('Rare User Agents', 'Uncommon user agents (potential tools)', 'source_type=apache | stats count() as requests by user_agent | where requests < 10 | sort requests', 'threat-hunting', ARRAY['user-agent', 'rare', 'anomaly'], 'advanced', 'investigation'),
('Geographic Anomaly', 'Access from unusual locations', '* | stats dc(src_ip) as unique_ips, count() as requests by country | sort -requests', 'threat-hunting', ARRAY['geo', 'location', 'anomaly'], 'advanced', 'investigation'),
('After Hours Activity', 'Activity during non-business hours', '* | eval hour=strftime("%H", timestamp) | where hour < 6 OR hour > 22 | stats count() by src_ip, hour', 'threat-hunting', ARRAY['off-hours', 'anomaly', 'insider'], 'intermediate', 'detection'),
('Data Exfiltration', 'Large outbound data transfers', 'bytes>50000000 | stats sum(bytes) as total_bytes by src_ip, dst_ip | sort -total_bytes | head 20', 'threat-hunting', ARRAY['exfiltration', 'data-loss', 'dlp'], 'advanced', 'detection'),
('Beaconing Detection', 'Regular interval connections (C2)', '* | bin span=1m | stats count() as connections by src_ip, dst_ip, _time | stats stdev(connections) as stdev, avg(connections) as avg by src_ip, dst_ip | where stdev < 1 AND avg > 0', 'threat-hunting', ARRAY['c2', 'beaconing', 'malware'], 'advanced', 'detection');

-- =============================================================================
-- REPORTING & DASHBOARDS
-- =============================================================================

INSERT INTO query_library (name, description, query, category, tags, difficulty, use_case) VALUES
('Daily Summary', 'Daily event summary by source', '* | bin span=1d | stats count() as events, dc(src_ip) as unique_ips by source_type, _time', 'reporting', ARRAY['summary', 'daily', 'overview'], 'beginner', 'dashboard'),
('Error Summary', 'Error breakdown by type and source', 'status>=400 | stats count() by source_type, status | sort source_type, status', 'reporting', ARRAY['errors', 'summary'], 'beginner', 'dashboard'),
('Security Posture', 'Overall security metrics', '* | stats count() as total_events, count(eval(status>=400)) as errors, dc(src_ip) as unique_sources', 'reporting', ARRAY['security', 'metrics', 'kpi'], 'intermediate', 'dashboard'),
('Top 10 Everything', 'Top sources, IPs, and URLs', '* | stats count() as events by source_type | append [search * | stats count() as events by src_ip | head 10] | append [search source_type=apache | stats count() as events by uri | head 10]', 'reporting', ARRAY['top', 'overview'], 'advanced', 'dashboard'),
('Hourly Heatmap Data', 'Events by hour and day for heatmap', '* | eval hour=strftime("%H", timestamp), day=strftime("%A", timestamp) | stats count() by day, hour', 'reporting', ARRAY['heatmap', 'pattern', 'visualization'], 'intermediate', 'dashboard');

