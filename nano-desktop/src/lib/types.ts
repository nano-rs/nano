// Wire types. These mirror nanosiem-core/src/auth/types.rs and the search
// handler; keep them in sync with nanosiem-web/src/lib/api/types.ts.

export interface ServerConfig {
  base_url: string;
  /** Set only when the search service is not reachable on the main origin. */
  search_url: string | null;
  allow_insecure: boolean;
  /** Who last signed in here — labels the trusted-device card. Not a credential. */
  last_email: string | null;
}

export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
}

export type LoginOutcome =
  | { status: 'authenticated'; user: User }
  | { status: 'mfa_required'; challenge_token: string }
  | { status: 'mfa_setup_required'; challenge_token: string };

export interface RestoreOutcome {
  server: ServerConfig | null;
  /** Only after an unlock — launching the app no longer signs you in by itself. */
  user: User | null;
  /** The keychain holds a refresh token: Touch ID can get us in without a password. */
  trusted: boolean;
  email: string | null;
}

export interface TimeRange {
  start: string;
  end: string;
}

export interface SearchRequest {
  query: string;
  time_range: TimeRange;
  limit?: number;
  table_view?: boolean;
  skip_histogram?: boolean;
}

export interface HistogramBucket {
  time: string;
  count: number;
}

export interface FieldInfo {
  name: string;
  field_type: string;
  count: number;
}

/** GET /api/schema/fields — the deployment's active field universe. */
export interface SchemaFieldsResponse {
  schema: string;
  fields: { name: string; type: string; category: string }[];
}

/** Whether coding agents launched in the terminal can reach this nano instance. */
export interface AgentStatus {
  provisioned: boolean;
  key_prefix: string | null;
  workspace: string;
  claude_installed: boolean;
  codex_installed: boolean;
  granted_permissions: string[];
}

export interface SchemaProfile {
  isOcsf: boolean;
  /** Promoted columns of the active profile — drives the "Core" field bucket. */
  knownFields: Set<string>;
}

export interface QueryWarning {
  message: string;
  code?: string;
  severity?: string;
  suggestion?: string;
  impact?: string;
}

/**
 * Delivered after the rows (or alongside them, for aggregate queries). Only
 * total_count and execution_time_ms are always present — a plain search omits
 * `fields` and `column_order` entirely, so everything else is optional.
 */
export interface SearchStreamMetadata {
  total_count: number;
  execution_time_ms: number;
  fields?: FieldInfo[];
  histogram?: HistogramBucket[];
  warnings?: QueryWarning[];
  column_order?: string[];
  cost_score?: number;
  display_type?: string;
}

export interface SearchProgress {
  rows_read?: number;
  progress_percent?: number;
}

/**
 * SSE frames from /api/search/stream, forwarded verbatim by the Rust client.
 * `cache_meta` is synthesized from the X-Nano-Cache response headers.
 */
export type StreamEvent =
  | { event: 'cache_meta'; data: { hit: boolean; age_secs: number | null } }
  | { event: 'queued'; data: { queue_position: number; estimated_wait_seconds: number } }
  | { event: 'started'; data: { job_id: string; query_id: string; is_streaming: boolean } }
  | { event: 'progress'; data: SearchProgress }
  | {
      event: 'rows';
      data: { rows: Record<string, unknown>[]; batch_index: number; cumulative_count: number };
    }
  | { event: 'metadata'; data: SearchStreamMetadata }
  | { event: 'completed'; data: { total_rows_delivered: number } }
  | { event: 'error'; data: { code: string; message: string } }
  | { event: 'done'; data: unknown };

/** One asset (host/IP) that saw an indicator, and how many times. */
export interface AssetHit {
  asset: string;
  hits: number;
}

/**
 * Quick Search's indicator peek, from a `ioc = "<value>"` search: how much, on
 * which assets, since when. `seen` is just whether any event matched — CONTEXT,
 * not a malicious/benign verdict.
 */
export interface IocPeek {
  indicator: string;
  seen: boolean;
  events: number;
  /** Distinct source assets that saw it. */
  assets: number;
  first_seen: string | null;
  last_seen: string | null;
  top_assets: AssetHit[];
  window_days: number;
}

/** One indicator's standing in the data, from the bulk lookup. */
export interface BulkIocHit {
  indicator: string;
  seen: boolean;
  events: number;
  assets: number;
  first_seen: string | null;
  last_seen: string | null;
  top_assets: AssetHit[];
  /**
   * The search for THIS indicator failed. Not the same as `seen: false`, which
   * means we looked and found nothing — the table must never present the two the
   * same way.
   */
  error: string | null;
}

/**
 * A past pivt investigation. It IS a notebook — pivt records every question, tool
 * call and answer into one — so a session list is a filtered notebook list.
 */
export interface PivtSession {
  id: string;
  title: string;
  status: string;
  created_at: string;
  updated_at: string;
}

/** One line of a session's transcript. */
export interface NotebookEntry {
  id: string;
  entry_type: string;
  content: Record<string, unknown>;
  created_at: string;
}

/** One tool the agent can reach, as the MCP server itself declares it. */
export interface McpTool {
  name: string;
  description: string;
  input_schema: Record<string, unknown> | null;
  /**
   * The nano permission it needs — `null` where we genuinely don't know. nano
   * publishes no per-tool permission metadata, so this is only populated where it
   * has been verified; the UI must say "unknown", never guess.
   */
  permission: string | null;
}

/** One hour of ingest. */
export interface Bucket {
  at: string;
  count: number;
}

/** Everything the SOC Overview shows, in one round trip. */
export interface Dashboard {
  events_24h: number;
  /** Averaged over the window — never present this as an instantaneous rate. */
  eps: number;
  ingest: Bucket[];
  top_talkers: AssetHit[];
  alerts_total: number;
  alerts_new: number;
  by_severity: Record<string, number>;
  latest: Record<string, unknown>[];
  sources: number;
  generated_at: string;
  /** Panels that failed. Shown, never swallowed into a confident zero. */
  degraded: string[];
}

/** Error shape produced by the Rust `Error` enum (tag = kind, content = message). */
export interface IpcError {
  kind:
    | 'invalid_url'
    | 'unreachable'
    | 'tls'
    | 'not_nano'
    | 'unauthorized'
    | 'session_expired'
    | 'not_connected'
    | 'server'
    | 'internal';
  message?: string;
}

// ---------------------------------------------------------------------------
// Dashboards — the SAME entities the web app reads and writes.
//
// Dashboard-level fields are snake_case (real columns); everything inside
// `panels` and `layout` is camelCase (opaque JSON the frontend owns). That split
// is the contract, not a typo.
// ---------------------------------------------------------------------------

/** What GET /api/dashboards returns: summaries, with panel_count and no panels. */
export interface DashboardSummary {
  id: string;
  name: string;
  description?: string;
  panel_count: number;
  owner_name?: string;
  visibility: string;
  created_at: string;
  updated_at: string;
}

export type VisualizationType =
  | 'bar'
  | 'line'
  | 'area'
  | 'pie'
  | 'table'
  | 'single_value'
  | 'timeline'
  | 'ranked_bar'
  | 'transaction'
  | 'tree'
  | 'flow'
  | 'obs_metric';

export interface PanelConfig {
  id: string;
  title: string;
  query: string;
  queryMode: 'piped' | 'sql';
  visualizationType: VisualizationType;
  visualizationConfig: {
    orientation?: 'horizontal' | 'vertical';
    stacked?: boolean;
    showPoints?: boolean;
    smooth?: boolean;
    fillOpacity?: number;
    showLabels?: boolean;
    pageSize?: number;
    unit?: string;
    showTrend?: boolean;
    thresholds?: { value: number; color: string; label?: string }[];
    columns?: { field: string; label: string }[];
  };
  timeRangeMode: 'dashboard' | 'custom';
  customTimeRange?: TimeRange;
  drilldownEnabled?: boolean;
}

export interface LayoutItem {
  i: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface DashboardVariable {
  name: string;
  label: string;
  type: 'dropdown' | 'text' | 'query';
  defaultValue?: string;
  options?: string[];
  query?: string;
  queryField?: string;
}

export interface DashboardLayout {
  columns: number;
  rowHeight: number;
  items: LayoutItem[];
  /** Variables live INSIDE layout, purely for persistence. */
  variables?: DashboardVariable[];
  defaultTimeRange?:
    | { type: 'preset'; preset: string }
    | { type: 'custom'; start: string; end: string };
  autoRun?: boolean;
}

export interface DashboardDetail {
  id: string;
  name: string;
  description?: string;
  layout: DashboardLayout;
  panels: PanelConfig[];
  refresh_interval?: number;
  visibility: string;
  updated_at: string;
}

export interface PanelQueryResponse {
  results: Record<string, unknown>[];
  total_count: number;
  execution_time_ms: number;
  /** Group-bys first, aggregates last. Without it a chart cannot be drawn correctly. */
  column_order?: string[];
  truncated?: boolean;
  cached?: boolean;
  cache_age_secs?: number;
}
