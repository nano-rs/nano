-- NAN-1840: a legitimate write path for CLIENT-HOSTED agents.
--
-- NAN-686 reserved the AI notebook entry types (ai_chat_response, ai_query,
-- ai_summary, …) to trusted server-side flows, because the notebook UI renders by
-- entry_type and a client-written entry would therefore appear with pivt branding.
-- That defense is right, and it has one casualty: nano Desktop runs pivt LOCALLY,
-- on the analyst's machine, so it has no server flow to record through — and its
-- transcripts were silently dropped.
--
-- This permission gates a separate endpoint (POST /api/notebooks/{id}/agent-entries)
-- which DOES accept the AI types, but stamps the provenance server-side so a
-- client-hosted agent's entry can never masquerade as one the server produced.
-- The original entries endpoint still refuses AI types.

INSERT INTO permissions (id, name, description, category) VALUES
    (
        'notebooks:agent_record',
        'Record Client-Agent Entries',
        'Record an agent transcript (answers, tool calls) into a notebook from a client-hosted agent such as nano Desktop. Entries are stamped as client-agent provenance and cannot impersonate a server-side flow.',
        'notebooks'
    )
ON CONFLICT (id) DO NOTHING;

-- Admin
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000001', 'notebooks:agent_record')
ON CONFLICT DO NOTHING;

-- Editor / analyst: running pivt from the desktop app is ordinary analyst work.
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', 'notebooks:agent_record')
ON CONFLICT DO NOTHING;
