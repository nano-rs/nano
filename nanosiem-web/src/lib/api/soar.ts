// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Tenant SOAR opt-in (NAN-4462, docs/soar/M3-API-HANDOFF.md).
 *
 * `GET /api/soar/settings` defaults automation off, revision 0, and the Judge
 * token budget to 250,000 tokens per UTC day. It includes current usage. `PUT` is revision-checked: a stale
 * `expected_revision` answers 409, a contested lock 503. Only a human tenant
 * admin (`settings:system`) can save; API keys are refused server-side.
 */

export interface SoarAiDailyUsage {
  /** UTC accounting date. */
  day: string;
  /** Includes conservative reservations for calls with unknown usage. */
  budget_tokens: number;
  reported_tokens: number;
  inferences: number;
  cache_hits: number;
  denied: number;
}

export interface SoarSettings {
  soar_enabled: boolean;
  revision: number;
  ai_daily_token_budget: number;
  ai_usage: SoarAiDailyUsage;
}

export interface UpdateSoarSettingsRequest {
  /** Omit to retain the current limit; 0 refuses new Judge inferences. */
  ai_daily_token_budget?: number;
  soar_enabled: boolean;
  expected_revision: number;
  /** Required, 1–2048 bytes; recorded in the audit trail. */
  reason: string;
}

export interface EmailRecipient { name: string; address: string }
export interface EmailRecipients { recipients: EmailRecipient[]; revision: number; daily_send_cap: number }
export interface SmtpConfig {
  host: string; port: number; tls: 'starttls' | 'implicit_tls'; username: string | null; from: string;
}
export interface MailTransport {
  transport: 'nano' | 'smtp'; smtp: SmtpConfig | null; has_password: boolean;
  revision: number; nano_mailer_available: boolean;
}
export interface UpdateMailTransportRequest {
  transport: 'nano' | 'smtp'; smtp: SmtpConfig | null; password?: string;
  expected_revision: number; reason: string;
}

export interface SoarPackVersion {
  name: string;
  version: string;
  installed_version: string | null;
  installed: boolean;
  upstream_changed: boolean;
  upstream_version: string | null;
}
export interface SoarPacks {
  packs: SoarPackVersion[];
  upstream_changed_count: number;
  catalog_status: string;
  catalog_expires_at: string | null;
}
export interface SoarUpstreamUpdate {
  pack_name: string;
  display_name: string;
  installed_version: string;
  upstream_version: string;
  change_summary: string;
}
export interface SoarUpstreamUpdates { updates: SoarUpstreamUpdate[]; total_count: number }
export interface ApplySoarUpstreamResult {
  pack_name: string; updated: boolean; version: string | null; message: string;
}
export interface BulkApplySoarUpstreamResult {
  updated: number; failed: number; results: ApplySoarUpstreamResult[];
}

export class SoarApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  listFlows(): Promise<{ flows: SoarReadFlow[] }> {
    return this.request('/api/soar/flows');
  }
  listRuns(): Promise<{ runs: SoarReadRun[] }> {
    return this.request('/api/soar/runs');
  }
  listPacks(): Promise<{ packs: SoarReadPack[] }> {
    return this.request('/api/soar/packs');
  }
  runDetail(id: string): Promise<SoarReadRun & { steps: SoarReadStep[] }> {
    return this.request('/api/soar/runs/' + encodeURIComponent(id));
  }

  getPacks(): Promise<SoarPacks> {
    return this.request('/api/soar/packs');
  }
  getUpstreamUpdates(): Promise<SoarUpstreamUpdates> {
    return this.request('/api/soar/packs/upstream-updates');
  }
  applyUpstreamUpdate(packName: string, version: string): Promise<SoarPacks> {
    return this.request(`/api/soar/packs/${encodeURIComponent(packName)}/upgrade`, {
      method: 'POST', body: JSON.stringify({ version }),
    });
  }
  applyAllUpstreamUpdates(): Promise<BulkApplySoarUpstreamResult> {
    return this.request('/api/soar/packs/apply-all-upstream-updates', { method: 'POST' });
  }

  getRecipients(): Promise<EmailRecipients> {
    return this.request<EmailRecipients>('/api/soar/recipients');
  }
  updateRecipients(body: { recipients: EmailRecipient[]; expected_revision: number; reason: string }): Promise<EmailRecipients> {
    return this.request<EmailRecipients>('/api/soar/recipients', { method: 'PUT', body: JSON.stringify(body) });
  }
  getMailTransport(): Promise<MailTransport> {
    return this.request<MailTransport>('/api/soar/mail-transport');
  }
  updateMailTransport(body: UpdateMailTransportRequest): Promise<MailTransport> {
    return this.request<MailTransport>('/api/soar/mail-transport', { method: 'PUT', body: JSON.stringify(body) });
  }
  sendTestEmail(to: string): Promise<{ status: string }> {
    return this.request<{ status: string }>('/api/soar/mail-transport/test', { method: 'POST', body: JSON.stringify({ to }) });
  }

  getSettings(): Promise<SoarSettings> {
    return this.request<SoarSettings>('/api/soar/settings');
  }

  // ── Automation workspace (NAN-4540) ────────────────────────────────────
  // Reads are the existing tenant-scoped routes; every effect below calls an
  // existing route that enforces permissions, case privacy and the demo fence.

  /** Full catalog: packs with action schemas and config/credential fields. */
  getCatalog(): Promise<SoarCatalog> {
    return this.request<SoarCatalog>('/api/soar/packs');
  }
  installPack(name: string, version: string): Promise<SoarCatalog> {
    return this.request<SoarCatalog>(`/api/soar/packs/${encodeURIComponent(name)}/install`, {
      method: 'POST', body: JSON.stringify({ version }),
    });
  }
  /** DELETE /api/soar/packs/{name} (soar:manage); 409 while referenced. */
  removePack(name: string): Promise<{ deleted: boolean }> {
    return this.request<{ deleted: boolean }>(`/api/soar/packs/${encodeURIComponent(name)}`, { method: 'DELETE' });
  }
  getFlows(): Promise<SoarFlows> {
    return this.request<SoarFlows>('/api/soar/flows');
  }
  getFlow(id: string): Promise<SoarFlow> {
    return this.request<SoarFlow>('/api/soar/flows/' + encodeURIComponent(id));
  }
  updateFlow(id: string, body: UpdateSoarFlowRequest): Promise<SoarFlow> {
    return this.request<SoarFlow>('/api/soar/flows/' + encodeURIComponent(id), {
      method: 'PUT', body: JSON.stringify(body),
    });
  }
  /** NAN-4546: POST /api/soar/flows (soar:manage). Body mirrors CreateFlow. */
  createFlow(body: Omit<UpdateSoarFlowRequest, 'expected_version'>): Promise<SoarFlow> {
    return this.request<SoarFlow>('/api/soar/flows', { method: 'POST', body: JSON.stringify(body) });
  }
  /** NAN-4651: with `trigger`, alert.* references that trigger never carries come back in `findings`. */
  validateFlow(definition: unknown, trigger?: SoarTriggerKind): Promise<SoarFlowValidation> {
    return this.request<SoarFlowValidation>('/api/soar/flows/validate', {
      method: 'POST', body: JSON.stringify(trigger ? { definition, trigger } : { definition }),
    });
  }
  queueFlow(id: string, body: RunSoarFlowRequest): Promise<SoarRun> {
    return this.request<SoarRun>(`/api/soar/flows/${encodeURIComponent(id)}/run`, {
      method: 'POST', body: JSON.stringify(body),
    });
  }
  /**
   * Compile one draft search step exactly as flow save would (NAN-4585).
   * Pure: nothing runs and no tenant data is read. Needs soar:manage.
   */
  validateSearch(body: SoarValidateSearchRequest): Promise<SoarSearchValidation> {
    return this.request<SoarSearchValidation>('/api/soar/flows/validate-search', {
      method: 'POST', body: JSON.stringify(body),
    });
  }
  /**
   * Test a saved flow against a real alert or given inputs (exactly one).
   * Permitted reads run live, other actions render; never attaches to a case.
   */
  testFlow(id: string, body: { alert_id: string } | { inputs: unknown }): Promise<SoarTestRun> {
    return this.request<SoarTestRun>(`/api/soar/flows/${encodeURIComponent(id)}/test`, {
      method: 'POST', body: JSON.stringify(body),
    });
  }
  /** Per-flow run/success/fail counts over the last 24 h (one aggregate query). */
  getFlowStats(): Promise<SoarFlowStats> {
    return this.request<SoarFlowStats>('/api/soar/flows/stats');
  }
  getRuns(page: SoarRunsQuery = {}): Promise<SoarRuns> {
    return this.request<SoarRuns>('/api/soar/runs' + query({
      limit: page.limit, offset: page.offset, case_id: page.case_id,
      created_after: page.created_after, created_before: page.created_before,
    }));
  }
  /** NAN-4556: visible run counts per bucket (same visibility as getRuns). */
  getRunVolume(q: { hours?: number; bucket_minutes?: number } = {}): Promise<SoarRunVolume> {
    return this.request<SoarRunVolume>('/api/soar/runs/volume' + query({ hours: q.hours, bucket_minutes: q.bucket_minutes }));
  }
  getRun(id: string, page: SoarRunDetailQuery = {}): Promise<SoarRunDetail> {
    return this.request<SoarRunDetail>('/api/soar/runs/' + encodeURIComponent(id) + query({
      steps_limit: page.steps_limit, steps_offset: page.steps_offset,
      approvals_limit: page.approvals_limit, approvals_offset: page.approvals_offset,
    }));
  }
  cancelRun(id: string): Promise<SoarRun> {
    return this.request<SoarRun>(`/api/soar/runs/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
  }
  queueAction(body: SoarActionRunRequest): Promise<SoarRun> {
    return this.request<SoarRun>('/api/soar/actions/run', { method: 'POST', body: JSON.stringify(body) });
  }
  getApprovals(page: SoarApprovalsQuery = {}): Promise<SoarApprovals> {
    return this.request<SoarApprovals>('/api/soar/approvals' + query({
      status: page.status, limit: page.limit, offset: page.offset,
    }));
  }
  getApproval(id: string): Promise<SoarApproval> {
    return this.request<SoarApproval>('/api/soar/approvals/' + encodeURIComponent(id));
  }
  /** Interactive human session only; the server refuses API keys and self-approval. */
  approve(id: string, body: { choice?: string; reason?: string }): Promise<SoarApproval> {
    return this.request<SoarApproval>(`/api/soar/approvals/${encodeURIComponent(id)}/approve`, {
      method: 'POST', body: JSON.stringify(body),
    });
  }
  /** Reject never carries a choice. */
  reject(id: string, body: { reason?: string }): Promise<SoarApproval> {
    return this.request<SoarApproval>(`/api/soar/approvals/${encodeURIComponent(id)}/reject`, {
      method: 'POST', body: JSON.stringify(body),
    });
  }
  getConnections(): Promise<SoarConnections> {
    return this.request<SoarConnections>('/api/soar/connections');
  }
  createConnection(body: SoarCreateConnectionRequest): Promise<SoarConnection> {
    return this.request<SoarConnection>('/api/soar/connections', { method: 'POST', body: JSON.stringify(body) });
  }
  updateConnection(id: string, body: SoarUpdateConnectionRequest): Promise<SoarConnection> {
    return this.request<SoarConnection>('/api/soar/connections/' + encodeURIComponent(id), {
      method: 'PUT', body: JSON.stringify(body),
    });
  }
  deleteConnection(id: string): Promise<{ deleted: boolean }> {
    return this.request<{ deleted: boolean }>('/api/soar/connections/' + encodeURIComponent(id), { method: 'DELETE' });
  }
  testConnection(id: string, inputs: Record<string, unknown> = {}): Promise<SoarTestResult> {
    return this.request<SoarTestResult>(`/api/soar/connections/${encodeURIComponent(id)}/test`, {
      method: 'POST', body: JSON.stringify({ inputs }),
    });
  }

  updateSettings(body: UpdateSoarSettingsRequest): Promise<SoarSettings> {
    return this.request<SoarSettings>('/api/soar/settings', {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }
}

/** Safe read projection shared by ordinary and demo views. Sensitive fields
 * are deliberately absent: the server omits them for demo principals. */
export interface SoarReadFlow { id: string; name: string; version: number; status: string; definition: unknown }
export interface SoarReadRun { id: string; status: string; dry_run: boolean; created_at: string; trigger_kind: string; flow_id?: string | null }
export interface SoarReadPack { name: string; display_name: string; vendor: string; version: string; installed: boolean }
export interface SoarReadStep { id: string; module_id: string; status: string; phase: string; outputs: unknown }

function query(params: Record<string, string | number | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  }
  const text = search.toString();
  return text ? '?' + text : '';
}

// ── Automation DTOs (NAN-4540). Mirrors the enterprise SOAR backend's
// soar/dto.rs and executor/types.rs. Fields a demo projection omits are optional.

export type SoarEffect = 'read' | 'write' | 'destructive';

export interface SoarActionInput { name: string; type: string; required: boolean; pattern: string | null }
export interface SoarCatalogAction {
  name: string;
  display_name: string;
  description: string;
  effect: SoarEffect | string;
  /** Effective default: approval unless a flow step explicitly selects auto. */
  approval_required: boolean;
  /** Mandatory minimum a flow cannot waive. */
  approval_forced: boolean;
  idempotent: boolean;
  inputs: SoarActionInput[];
  require_one_of: string[][];
  rollback: string | null;
  /** NAN-4556: declared receipt polling; absent for one-shot actions. */
  poll?: { interval_secs: number; max_secs: number } | null;
}
export interface SoarConfigField { name: string; label: string; required: boolean; one_of: string[]; default: string | null }
export interface SoarCredentialField { name: string; label: string; required: boolean; configured: boolean }
export interface SoarCatalogPack {
  origin: string;
  availability: string;
  name: string;
  display_name: string;
  description: string;
  vendor: string;
  categories: string[];
  version: string;
  installed_version: string | null;
  installed: boolean;
  upstream_changed: boolean;
  upstream_version: string | null;
  enabled: boolean;
  withdrawn: boolean;
  change_summary: string;
  config_fields?: SoarConfigField[];
  credential_fields?: SoarCredentialField[];
  actions: SoarCatalogAction[];
  test_action: string | null;
  per_minute: number;
  per_day: number;
}
export interface SoarCatalog {
  upstream_changed_count: number;
  catalog_status: string;
  catalog_expires_at: string | null;
  packs: SoarCatalogPack[];
}

export interface SoarFlowTrigger { on: string; match?: string | null; cron?: string | null }
export interface SoarFlow {
  id: string;
  name: string;
  version: number;
  status: string;
  definition: unknown;
  trigger: SoarFlowTrigger;
  created_by?: string;
  updated_by?: string;
  created_at: string;
  updated_at: string;
  next_run_at: string | null;
}
export interface SoarFlows {
  flows: SoarFlow[];
  event_overflow_count: number;
  last_event_overflow_at: string | null;
  admission_backpressure: { reason: string; since: string } | null;
}
export interface UpdateSoarFlowRequest {
  expected_version: number;
  name: string;
  definition: unknown;
  trigger: SoarFlowTrigger;
  status: string;
}
export interface SoarFlowValidation {
  valid: boolean;
  module_count: number;
  summary: string;
  /** NAN-4651: trigger-scope findings, e.g. "module `hunt`: alert.user.name: a manual trigger has no alert; …". */
  findings?: string[];
}
export interface RunSoarFlowRequest { inputs: Record<string, unknown>; case_id?: string; dry_run?: boolean }

export type SoarTriggerKind = 'manual' | 'alert' | 'case' | 'case.triage_verdict' | 'schedule';
/** POST /api/soar/flows/validate-search request. */
export interface SoarValidateSearchRequest {
  /** nPL with optional `{{alert.*}}` / `{{steps.*}}` / `{{flow_input.*}}` / `{{run.*}}` bindings. */
  query: string;
  /** Lookback, e.g. `24h` (at most 30d). */
  window: string;
  /** Row limit, 1..=1000. */
  limit: number;
  trigger?: SoarTriggerKind;
  /** Ids of steps that run before this one. */
  prior_steps?: string[];
  in_loop?: boolean;
}
export interface SoarSearchDiagnostic {
  /** `query`, `window` or `limit`. */
  field: string;
  message: string;
  start: number | null;
  end: number | null;
  line: number | null;
  column: number | null;
}
export interface SoarSearchValidation {
  valid: boolean;
  /** Empty when valid; otherwise the first error, as save reports it. */
  errors: SoarSearchDiagnostic[];
}

/** POST /api/soar/flows/{id}/test: the test run plus what production admission would do. */
export interface SoarTestRun extends SoarRun {
  admission: {
    /** Production dedupe would apply to this event. */
    would_dedupe: boolean;
    /** Scheduled-flow spacing; tests never advance it. */
    cooldown_until: string | null;
  };
}

export interface SoarRun {
  id: string;
  connection_id?: string | null;
  pack_name: string | null;
  pack_version: string | null;
  action: string | null;
  inputs?: unknown;
  case_id: string | null;
  /** NAN-4556: human case number (list/detail reads only). */
  case_number?: number | null;
  dry_run: boolean;
  status: string;
  requested_by?: string;
  /** Display name of the requesting member; absent for demo principals or unknown actors. */
  requested_by_name?: string | null;
  /** Distinct module iterations that sent an outbound request (blast radius). */
  affected_entities?: number | null;
  approval_required: boolean;
  created_at: string;
  outputs: unknown;
  error_class: string | null;
  wall_delivery?: unknown;
  flow_id: string | null;
  flow_version: number | null;
  trigger_kind: string;
  trigger_ref: string | null;
  started_at: string | null;
  finished_at: string | null;
  executor_pending: boolean;
}
export interface SoarRuns { runs: SoarRun[]; limit: number; offset: number }
export interface SoarFlowRunStats { flow_id: string; runs: number; succeeded: number; failed: number }
export interface SoarFlowStats { window_hours: number; since: string; flows: SoarFlowRunStats[] }
export interface SoarRunsQuery {
  limit?: number; offset?: number; case_id?: string;
  /** NAN-4556: created window, [created_after, created_before), ISO-8601. */
  created_after?: string; created_before?: string;
}
/** NAN-4556: GET /api/soar/runs/volume — zero-filled, oldest first. */
export interface SoarRunVolumeBucket { start: string; runs: number; failed: number; waiting: number; running: number }
export interface SoarRunVolume { since: string; until: string; bucket_minutes: number; total: number; buckets: SoarRunVolumeBucket[] }
export interface SoarRunDetailQuery {
  steps_limit?: number; steps_offset?: number; approvals_limit?: number; approvals_offset?: number;
}
export interface SoarStepResult {
  id: string;
  module_id: string;
  iteration: unknown;
  attempt: number;
  attempt_group: number;
  status: string;
  outputs: unknown;
  error_class: string | null;
  started_at: string;
  finished_at: string | null;
  ai_tokens: number;
  ai_budget_tokens: number;
  ai_cached: boolean;
  phase: string;
  started_at_ms: number;
  finished_at_ms: number | null;
  /** Redacted request summary; omitted for demo principals. */
  rendered_request?: unknown;
  output_is_placeholder: boolean;
  placeholder_inputs: string[];
  skip_reason: string | null;
  /** Approval stage deadline while the step awaits approval. */
  deadline_at?: string | null;
}
export interface SoarRunDetail extends SoarRun {
  ai_usage: { reported_tokens: number; budget_tokens: number; cache_hits: number };
  steps: SoarStepResult[];
  approvals?: SoarApproval[];
  next_steps_offset: number | null;
  next_approvals_offset?: number | null;
}
export interface SoarActionRunRequest {
  connection_id: string;
  action: string;
  inputs: Record<string, unknown>;
  case_id?: string;
  dry_run?: boolean;
}

export interface SoarApprovalRequest {
  prompt?: string;
  options?: string[];
  note_required_on?: string | null;
  ambiguous?: boolean;
  pack?: string;
  action?: string;
  version?: string;
  connection_id?: string;
  inputs?: Record<string, unknown>;
  rendered?: unknown;
  [key: string]: unknown;
}
export interface SoarApproval {
  id: string;
  run_id: string;
  module_id: string;
  requested_action: SoarApprovalRequest;
  requested_by: string;
  requested_source: string;
  ambiguous: boolean;
  status: string;
  created_at: string;
  expires_at: string;
  decided_by: string | null;
  requested_by_name?: string | null;
  decided_by_name?: string | null;
  decided_at: string | null;
  choice: unknown;
  reason: string | null;
  /** NAN-4556: the run's case (visible cases only). */
  case_id?: string | null;
  case_number?: number | null;
}
export interface SoarApprovals { approvals: SoarApproval[]; limit: number; offset: number }
export type SoarApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'canceled';
export interface SoarApprovalsQuery { status?: SoarApprovalStatus; limit?: number; offset?: number }

export interface SoarConnection {
  id: string;
  pack_name: string;
  label: string;
  config: Record<string, unknown> | null;
  credential_fields: SoarCredentialField[];
  ready: boolean;
  created_at: string;
  updated_at: string;
  last_test_at: string | null;
  last_test_status: string | null;
  active_runs: number;
  can_delete: boolean;
}
export interface SoarConnections { connections: SoarConnection[] }
export interface SoarCreateConnectionRequest {
  pack_name: string;
  label: string;
  config: Record<string, string>;
  credentials: Record<string, string>;
}
export interface SoarUpdateConnectionRequest {
  label?: string;
  config?: Record<string, string>;
  /** Omitted fields keep stored values; empty values remove optional credentials. */
  credentials?: Record<string, string>;
}
export interface SoarTestResult { status: string; message: string | null; outputs: unknown; tested_at: string }
