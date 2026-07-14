import { Channel, invoke } from '@tauri-apps/api/core';

import type { UdmFieldInfo } from '@/lib/query-autocomplete';

import type {
  AgentStatus,
  BulkIocHit,
  Dashboard as DashboardData,
  DashboardDetail,
  DashboardSummary,
  IocPeek,
  PanelQueryResponse,
  TimeRange,
  IpcError,
  LoginOutcome,
  McpTool,
  NotebookEntry,
  PivtSession,
  User,
  RestoreOutcome,
  SchemaFieldsResponse,
  SearchRequest,
  SearchStreamMetadata,
  ServerConfig,
  StreamEvent,
} from './types';

const FALLBACK_MESSAGE = 'Something went wrong.';

export function isIpcError(error: unknown): error is IpcError {
  return typeof error === 'object' && error !== null && 'kind' in error;
}

/** Human-readable text for anything thrown out of an IPC call. */
export function errorMessage(error: unknown): string {
  if (isIpcError(error)) return error.message ?? error.kind.replace(/_/g, ' ');
  if (error instanceof Error) return error.message;
  return FALLBACK_MESSAGE;
}

export const api = {
  connect: (
    url: string,
    searchUrl: string | null,
    allowInsecure = false
  ): Promise<ServerConfig> => invoke('connect', { url, searchUrl, allowInsecure }),

  login: (email: string, password: string): Promise<LoginOutcome> =>
    invoke('login', { email, password }),

  verifyMfa: (challengeToken: string, code: string): Promise<LoginOutcome> =>
    invoke('verify_mfa', { challengeToken, code }),

  restoreSession: (): Promise<RestoreOutcome> => invoke('restore_session'),

  /** Touch ID, then exchange the stored refresh token for a live session. */
  unlockSession: (): Promise<User> => invoke('unlock_session'),

  schemaFields: (): Promise<SchemaFieldsResponse> => invoke('schema_fields'),

  sourceTypes: (start?: string, end?: string): Promise<[string, number][]> =>
    invoke('source_types', { start: start ?? null, end: end ?? null }),

  udmFields: (): Promise<{ fields?: UdmFieldInfo[] }> => invoke('udm_fields'),

  /** Ends the session but keeps the device trusted — Touch ID gets back in. */
  lockSession: (): Promise<void> => invoke('lock_session'),

  /** Ends the session AND destroys device trust — password required next time. */
  logout: (): Promise<void> => invoke('logout'),

  disconnect: (): Promise<void> => invoke('disconnect'),

  /**
   * Rows stream in over a Channel as ClickHouse produces them, so the table
   * paints progressively. Resolves when the stream closes.
   */
  searchStream: (
    /** The tab's id. Cancellation is keyed by it, so tabs stream independently. */
    searchId: string,
    request: SearchRequest,
    onEvent: (event: StreamEvent) => void,
    /** Force a live recompute past the server-side cache. */
    bypass = false
  ): Promise<void> => {
    const channel = new Channel<StreamEvent>();
    channel.onmessage = onEvent;
    return invoke('search_stream', { searchId, request, bypass, onEvent: channel });
  },

  cancelSearch: (searchId: string): Promise<void> => invoke('cancel_search', { searchId }),

  /** Is there a live session? Quick Search shows a sign-in prompt if not. */
  isAuthenticated: (): Promise<boolean> => invoke('is_authenticated'),

  /** Hide the Quick Search spotlight (Esc / after handoff). */
  hideQuick: (): Promise<void> => invoke('hide_quick'),

  /** Hand a query to the main window; `range` optionally sets its time window. */
  openInMain: (query: string, range?: string): Promise<void> =>
    invoke('open_in_main', { query, range: range ?? null }),

  /** Hand a question to pivt in the main window (opens the agent panel on it). */
  askPivt: (prompt: string): Promise<void> => invoke('ask_pivt', { prompt }),

  /** Quick Search's indicator peek: how much / which assets / since when. */
  iocPeek: (value: string): Promise<IocPeek> => invoke('ioc_peek', { value }),

  /** "Which of these have we seen?" — one search per indicator, bounded. */
  bulkIocPeek: (values: string[], windowDays: number): Promise<BulkIocHit[]> =>
    invoke('bulk_ioc_peek', { values, windowDays }),

  /** The SOC Overview, in one call. Panels degrade individually. */
  dashboard: (): Promise<DashboardData> => invoke('dashboard'),

  /** Pin one of the built-in overview widgets to the desktop. */
  pinWidget: (kind: 'detections' | 'ingest' | 'agent'): Promise<void> =>
    invoke('pin_widget', { kind }),

  /** Pin ANY panel of ANY dashboard as an always-on-top window. */
  pinPanel: (dashboardId: string, panelId: string): Promise<void> =>
    invoke('pin_panel', { dashboardId, panelId }),

  /** What is this widget window showing? Asked by the widget itself on load. */
  widgetSpec: (): Promise<{
    kind: 'detections' | 'ingest' | 'agent' | 'panel';
    dashboard_id: string | null;
    panel_id: string | null;
  }> => invoke('widget_spec'),

  /** Unpin — closes the widget window this is called from. */
  closeWidget: (): Promise<void> => invoke('close_widget'),

  /** The dashboards this analyst can see. Summaries, not full dashboards. */
  listDashboards: (): Promise<DashboardSummary[]> => invoke('list_dashboards'),

  /** One dashboard in full — panels + layout. */
  getDashboard: (id: string): Promise<DashboardDetail> => invoke('get_dashboard', { id }),

  /**
   * Run one panel. Goes through the DASHBOARD endpoint, not search: it enforces
   * per-source RBAC and substitutes $variables with the platform's own rules, so
   * this client and the web app cannot render the same panel differently.
   */
  panelQuery: (
    query: string,
    queryMode: 'piped' | 'sql',
    timeRange: TimeRange,
    variables?: Record<string, string>,
    bypassCache = false
  ): Promise<PanelQueryResponse> =>
    invoke('dashboard_panel_query', {
      query,
      queryMode,
      timeRange,
      variables: variables ?? null,
      bypassCache,
    }),

  /** Past pivt investigations (Enterprise: notebooks). */
  pivtSessions: (): Promise<PivtSession[]> => invoke('pivt_sessions'),

  /** One session's transcript, in order. */
  notebookEntries: (notebookId: string): Promise<NotebookEntry[] | { entries: NotebookEntry[] }> =>
    invoke('notebook_entries', { notebookId }),

  /** The real tool inventory, asked of the MCP server itself. */
  mcpTools: (): Promise<McpTool[]> => invoke('mcp_tools'),

  agentStatus: (): Promise<AgentStatus> => invoke('agent_status'),

  /** Mints a read-only API key and writes the Claude Code + Codex MCP configs. */
  provisionAgent: (): Promise<AgentStatus> => invoke('provision_agent'),

  revokeAgent: (): Promise<AgentStatus> => invoke('revoke_agent'),
};

export type { SearchStreamMetadata };
