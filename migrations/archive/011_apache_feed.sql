-- Apache Access Log Feed
-- Adds feed definition for Apache Combined Log Format

INSERT INTO feeds (
    name, 
    description, 
    match_field, 
    match_pattern, 
    match_values,
    category, 
    vendor, 
    product, 
    icon, 
    color,
    enabled
) VALUES (
    'apache_access',
    'Apache HTTP Server access logs in Combined Log Format. Contains web request details including client IP, request method, URL path, status code, response size, referrer, and user agent.',
    'source_type',
    '^apache_access$',
    ARRAY['apache_access'],
    'application',
    'Apache',
    'HTTP Server',
    'server',
    'orange',
    true
) ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    match_field = EXCLUDED.match_field,
    match_pattern = EXCLUDED.match_pattern,
    match_values = EXCLUDED.match_values,
    category = EXCLUDED.category,
    vendor = EXCLUDED.vendor,
    product = EXCLUDED.product,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    updated_at = NOW();
