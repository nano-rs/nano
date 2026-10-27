// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540 — DTO fixtures for Automation unit tests only. Shapes follow the
 * server contract; nothing here is imported by application code.
 */
import type {
  SoarApproval,
  SoarCatalog,
  SoarCatalogPack,
  SoarConnection,
  SoarFlow,
  SoarRun,
  SoarRunDetail,
  SoarSettings,
} from '@/lib/api/soar';

export function settings(enabled: boolean): SoarSettings {
  return {
    soar_enabled: enabled,
    revision: 1,
    ai_daily_token_budget: 0,
    ai_usage: {} as SoarSettings['ai_usage'],
  };
}

export function pack(over: Partial<SoarCatalogPack> = {}): SoarCatalogPack {
  return {
    origin: 'upstream',
    availability: 'available',
    name: 'crowdstrike',
    display_name: 'CrowdStrike Falcon',
    description: 'EDR containment',
    vendor: 'CrowdStrike',
    categories: ['edr'],
    version: '1.2.0',
    installed_version: '1.2.0',
    installed: true,
    upstream_changed: false,
    upstream_version: null,
    enabled: true,
    withdrawn: false,
    change_summary: '',
    config_fields: [{ name: 'base_url', label: 'Base URL', required: true, one_of: [], default: null }],
    credential_fields: [{ name: 'client_secret', label: 'Client secret', required: true, configured: false }],
    actions: [
      {
        name: 'contain_host',
        display_name: 'Contain host',
        description: 'Network-isolate a host',
        effect: 'destructive',
        approval_required: true,
        approval_forced: true,
        idempotent: true,
        inputs: [{ name: 'hostname', type: 'string', required: true, pattern: null }],
        require_one_of: [],
        rollback: 'lift_containment',
      },
      {
        name: 'get_host',
        display_name: 'Get host details',
        description: '',
        effect: 'read',
        approval_required: false,
        approval_forced: false,
        idempotent: true,
        inputs: [{ name: 'hostname', type: 'string', required: true, pattern: null }],
        require_one_of: [],
        rollback: null,
      },
    ],
    test_action: 'get_host',
    per_minute: 60,
    per_day: 1000,
    ...over,
  };
}

export function catalog(packs: SoarCatalogPack[] = [pack()]): SoarCatalog {
  return { upstream_changed_count: 0, packs } as SoarCatalog;
}

export function connection(over: Partial<SoarConnection> = {}): SoarConnection {
  return {
    id: 'c0000000-0000-4000-8000-000000000001',
    pack_name: 'crowdstrike',
    label: 'Falcon US-1',
    config: { base_url: 'https://api.example.test' },
    credential_fields: [{ name: 'client_secret', label: 'Client secret', required: true, configured: true }],
    ready: true,
    created_at: '2026-10-25T10:00:00Z',
    updated_at: '2026-10-25T10:00:00Z',
    last_test_at: null,
    last_test_status: null,
    active_runs: 0,
    can_delete: true,
    ...over,
  };
}

export function run(over: Partial<SoarRun> = {}): SoarRun {
  return {
    id: 'r0000000-0000-4000-8000-000000000001',
    connection_id: 'c0000000-0000-4000-8000-000000000001',
    pack_name: 'crowdstrike',
    pack_version: '1.2.0',
    action: 'contain_host',
    inputs: { hostname: 'ws-0142' },
    case_id: null,
    dry_run: false,
    status: 'succeeded',
    requested_by: 'u1',
    approval_required: true,
    created_at: new Date(Date.now() - 60_000).toISOString(),
    outputs: null,
    error_class: null,
    flow_id: null,
    flow_version: null,
    trigger_kind: 'manual',
    trigger_ref: null,
    started_at: new Date(Date.now() - 55_000).toISOString(),
    finished_at: new Date(Date.now() - 50_000).toISOString(),
    executor_pending: false,
    ...over,
  };
}

export function runDetail(over: Partial<SoarRunDetail> = {}): SoarRunDetail {
  const base = run();
  return {
    ...base,
    ai_usage: { reported_tokens: 0, budget_tokens: 0, cache_hits: 0 },
    steps: [
      {
        id: 's1',
        module_id: 'contain',
        iteration: null,
        attempt: 1,
        attempt_group: 0,
        status: 'succeeded',
        outputs: { contained: true },
        error_class: null,
        started_at: base.started_at!,
        finished_at: base.finished_at,
        ai_tokens: 0,
        ai_budget_tokens: 0,
        ai_cached: false,
        phase: 'done',
        started_at_ms: Date.parse(base.started_at!),
        finished_at_ms: Date.parse(base.finished_at!),
        output_is_placeholder: false,
        placeholder_inputs: [],
        skip_reason: null,
      },
    ],
    approvals: [],
    next_steps_offset: null,
    ...over,
  };
}

export function approval(over: Partial<SoarApproval> = {}): SoarApproval {
  return {
    id: 'a0000000-0000-4000-8000-000000000001',
    run_id: 'r0000000-0000-4000-8000-000000000001',
    module_id: 'contain',
    requested_action: { pack: 'crowdstrike', action: 'contain_host', inputs: { hostname: 'ws-0142' } },
    requested_by: 'someone-else',
    requested_source: 'flow',
    ambiguous: false,
    status: 'pending',
    created_at: new Date(Date.now() - 5 * 60_000).toISOString(),
    expires_at: new Date(Date.now() + 55 * 60_000).toISOString(),
    decided_by: null,
    decided_at: null,
    choice: null,
    reason: null,
    ...over,
  };
}

export function flow(over: Partial<SoarFlow> = {}): SoarFlow {
  return {
    id: 'f0000000-0000-4000-8000-000000000001',
    name: 'Contain on critical EDR alert',
    version: 3,
    status: 'live',
    definition: {
      summary: 'Contain',
      description: 'Contain the host after an analyst approves.',
      value: {
        modules: [
          { id: 'lookup', value: { type: 'action', pack: 'crowdstrike', action: 'get_host' } },
          { id: 'gate', value: { type: 'approval', prompt: 'Contain this host?', options: ['contain', 'skip'] } },
          { id: 'contain', value: { type: 'action', pack: 'crowdstrike', action: 'contain_host' } },
        ],
      },
    },
    trigger: { on: 'alert', match: 'severity >= high' },
    created_at: '2026-10-20T10:00:00Z',
    updated_at: '2026-10-24T10:00:00Z',
    next_run_at: null,
    ...over,
  };
}

export function httpError(status: number, message = `HTTP ${status}`) {
  return Object.assign(new Error(message), { status });
}
