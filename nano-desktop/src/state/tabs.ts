import type { Indicator } from '../lib/indicator';
import type {
  BulkIocHit,
  DashboardDetail,
  PanelQueryResponse,
  SearchStreamMetadata,
  TimeRange,
} from '../lib/types';
import type { TimeRangeValue } from '@/lib/time-range';

export type TabStatus = 'idle' | 'running' | 'done' | 'error';

export interface CacheMeta {
  hit: boolean;
  age_secs: number | null;
}

/** What pivt asked nano for, and what came back — the body of a `tool` tab. */
export interface ToolRecord {
  /** Claude's `tool_use` id, so a later `tool_result` finds its tab. */
  callId: string;
  /** The bare tool name (`search_sql`), not the `mcp__nano__` wire name. */
  name: string;
  input: Record<string, unknown>;
  /** pivt's result, once it lands. Truncated — this is a record, not a result set. */
  result?: string;
  failed?: boolean;
}

/**
 * A pivt investigation, as a cluster of tabs.
 *
 * pivt runs several tools to answer one question. Left flat, those tabs bury the
 * analyst's own work in the strip; grouped, they read as "here is what pivt did,
 * as tabs you can open" — and they close together when the analyst is done.
 */
export interface TabGroup {
  id: string;
  /** The investigation's name — pivt's notebook title, once it has one. */
  label: string;
  /** Tool calls beyond the tab cap, still counted so the strip can't lie. */
  overflow: number;
}

/**
 * A pasted list of indicators, and what the data says about them.
 *
 * Lives on the tab like search results do, so a bulk lookup keeps running (and
 * keeps its answer) while the analyst works in another tab.
 */
export interface BulkState {
  /** What the analyst pasted, verbatim — the left rail shows it back to them. */
  text: string;
  /** What we found in it. */
  indicators: Indicator[];
  hits: BulkIocHit[];
  status: TabStatus;
  error: string | null;
  windowDays: number;
}

export const BULK_WINDOW_DAYS = 30;

/** Mirrors `PanelState` in components/Panel, kept structural to avoid a cycle. */
export type DraftPanelState =
  | { status: 'running' }
  | { status: 'done'; data: PanelQueryResponse }
  | { status: 'error'; message: string };

/**
 * One tab is one independent search. Results live here rather than in the
 * component, so a background tab keeps streaming while you look at another one.
 */
export interface Tab {
  id: string;
  /**
   * A search tab runs nPL; a tool tab records something pivt did that isn't one;
   * a bulk tab answers "which of these indicators have we seen?"; `sessions` and
   * `mcp` are the AGENT surfaces.
   */
  kind: 'search' | 'tool' | 'bulk' | 'sessions' | 'mcp' | 'dashboard' | 'overview';
  /** Who opened it. pivt's tabs are marked in the strip — no silent impersonation. */
  origin: 'user' | 'pivt';
  /** The investigation this belongs to, if any. */
  groupId?: string;

  query: string;
  range: TimeRangeValue;

  /**
   * Row cap for this tab's run. A mirrored agent tab is a PREVIEW: pivt can fire
   * a dozen searches in one answer, and pulling 500 rows for each — to show ten —
   * would put the analyst's own workspace behind the agent's exhaust.
   */
  limit: number;
  /** Set on a preview tab, so the pane can offer "run the full search". */
  preview?: boolean;

  /** Only on `kind: 'tool'`. */
  tool?: ToolRecord;
  /** Only on `kind: 'bulk'`. */
  bulk?: BulkState;

  /** Only on `kind: 'dashboard'`: which dashboard is open, if one is. */
  dashboardId?: string;
  /**
   * Only on `kind: 'dashboard'`: a dashboard pivt is still BUILDING. Rendered
   * exactly like a saved one — it just has no id yet, so panels appear in it as
   * pivt validates them rather than after it finishes.
   */
  draft?: DashboardDetail;
  /**
   * Results for the draft's panels, taken straight from pivt's tool results. The
   * agent already RAN each query; re-running it here would double the load on the
   * analyst's cluster to show them the same rows a second later.
   */
  draftStates?: Record<string, DraftPanelState>;

  rows: Record<string, unknown>[];
  metadata: SearchStreamMetadata | null;
  cache: CacheMeta | null;
  status: TabStatus;
  error: string | null;

  /** The query these results belong to, so the tab label can't lie. */
  ranQuery: string;
  /** The window they cover — decides whether rows carry a date. */
  ranRange: TimeRange | null;
}

export const DEFAULT_RANGE: TimeRangeValue = { type: 'preset', preset: 'Last 24 hours' };

/** A full run. What the analyst's own tabs get. */
export const FULL_LIMIT = 500;
/** A mirrored agent run. Enough to see what pivt saw, cheap enough to spam. */
export const PREVIEW_LIMIT = 10;

/**
 * How many tabs one pivt investigation may open. A long autonomous run can fire
 * dozens of tools; past this point the group stops opening tabs and counts the
 * rest (`overflow`) instead of burying the analyst. Every call is still listed in
 * the panel's activity card, so the cap hides nothing.
 */
export const MAX_GROUP_TABS = 8;

let counter = 0;

export function newTab(query = '', range: TimeRangeValue = DEFAULT_RANGE): Tab {
  counter += 1;
  return {
    // Doubles as the Rust-side search id, which is what keys cancellation.
    id: `tab-${counter}`,
    kind: 'search',
    origin: 'user',
    query,
    range,
    limit: FULL_LIMIT,
    rows: [],
    metadata: null,
    cache: null,
    status: 'idle',
    error: null,
    ranQuery: '',
    ranRange: null,
  };
}

/** A dashboard, open on one in particular. */
export function newDashboardTab(dashboardId?: string, draft?: DashboardDetail): Tab {
  return { ...newTab(), kind: 'dashboard', dashboardId, draft };
}

/** A search pivt ran, opened as a real (preview-capped) tab. */
export function newAgentSearchTab(
  groupId: string,
  query: string,
  range: TimeRangeValue
): Tab {
  return {
    ...newTab(query, range),
    origin: 'pivt',
    groupId,
    limit: PREVIEW_LIMIT,
    preview: true,
  };
}

/** Something pivt did that isn't an nPL search — kept as an inspectable record. */
export function newAgentToolTab(groupId: string, tool: ToolRecord): Tab {
  return {
    ...newTab(),
    kind: 'tool',
    origin: 'pivt',
    groupId,
    tool,
  };
}

/** A paste box the analyst hasn't filled in yet — and then what's in it. */
export function newBulkTab(): Tab {
  return {
    ...newTab(),
    kind: 'bulk',
    bulk: {
      text: '',
      indicators: [],
      hits: [],
      status: 'idle',
      error: null,
      windowDays: BULK_WINDOW_DAYS,
    },
  };
}

/**
 * The singleton destinations — Sessions, MCP tools, the dashboard. One tab each;
 * opening one that's already open re-focuses it rather than stacking a duplicate.
 */
export type SingletonKind = 'sessions' | 'mcp' | 'dashboard' | 'overview';

export function newSingletonTab(kind: SingletonKind): Tab {
  return { ...newTab(), kind };
}

/** An unrun tab has no query text to show, so it says what it is. */
export function tabLabel(tab: Tab): string {
  if (tab.kind === 'tool') return tab.tool?.name ?? 'tool';
  if (tab.kind === 'sessions') return 'Sessions';
  if (tab.kind === 'mcp') return 'MCP tools';
  if (tab.kind === 'dashboard') {
    if (tab.draft) return tab.draft.name || 'New dashboard';
    return tab.dashboardId ? 'Dashboard' : 'Dashboards';
  }
  if (tab.kind === 'overview') return 'SOC Overview';
  if (tab.kind === 'bulk') {
    const count = tab.bulk?.indicators.length ?? 0;
    return count > 0 ? `Bulk lookup · ${count}` : 'Bulk lookup';
  }
  return searchLabel(tab.ranQuery || tab.query);
}

/**
 * The DISTINCTIVE part of a query, not its first thirty characters.
 *
 * pivt's tabs all share a long filter prefix — six mirrored searches on an OCSF
 * tenant every one of which begins `class_uid=…` — so labelling by the head of the
 * string gave a strip of tabs reading "cl…", "cl…", "cl…". The aggregation is what
 * makes each one different, so lead with it.
 */
export function searchLabel(query: string): string {
  const trimmed = query.trim();
  if (!trimmed) return 'New search';

  const segments = trimmed.split('|').map((segment) => segment.trim());
  const aggregate = segments.find((segment) => /^(stats|timechart|top|rare|table)\b/i.test(segment));

  return aggregate ?? segments[0] ?? trimmed;
}

export type TabAction =
  | { type: 'add'; tab: Tab }
  | { type: 'close'; id: string }
  | { type: 'select'; id: string }
  | { type: 'patch'; id: string; patch: Partial<Tab> }
  | { type: 'appendRows'; id: string; rows: Record<string, unknown>[] }
  | { type: 'openGroup'; group: TabGroup }
  | { type: 'renameGroup'; id: string; label: string }
  | { type: 'countOverflow'; id: string }
  | { type: 'closeGroup'; id: string }
  /** A `tool_result` landing against the tab that recorded its call. */
  | { type: 'toolResult'; callId: string; result: string; failed: boolean };

export interface TabsState {
  tabs: Tab[];
  activeId: string;
  groups: TabGroup[];
}

export function initialTabs(): TabsState {
  const tab = newTab();
  return { tabs: [tab], activeId: tab.id, groups: [] };
}

export function tabsReducer(state: TabsState, action: TabAction): TabsState {
  switch (action.type) {
    case 'add':
      return { ...state, tabs: [...state.tabs, action.tab], activeId: action.tab.id };

    case 'select':
      return { ...state, activeId: action.id };

    case 'close': {
      const index = state.tabs.findIndex((tab) => tab.id === action.id);
      if (index === -1) return state;

      const closing = state.tabs[index];
      const tabs = state.tabs.filter((tab) => tab.id !== action.id);
      // Closing the last tab leaves an empty one rather than an empty window.
      if (tabs.length === 0) {
        const tab = newTab();
        return { tabs: [tab], activeId: tab.id, groups: [] };
      }
      // Closing the active tab selects its neighbour, the way a browser does.
      const activeId =
        state.activeId === action.id
          ? (tabs[index] ?? tabs[index - 1] ?? tabs[0]).id
          : state.activeId;
      return { ...state, tabs, activeId, groups: pruneGroups(state.groups, tabs, closing) };
    }

    case 'patch':
      return {
        ...state,
        tabs: state.tabs.map((tab) => (tab.id === action.id ? { ...tab, ...action.patch } : tab)),
      };

    case 'appendRows':
      return {
        ...state,
        tabs: state.tabs.map((tab) =>
          tab.id === action.id ? { ...tab, rows: [...tab.rows, ...action.rows] } : tab
        ),
      };

    case 'openGroup':
      if (state.groups.some((group) => group.id === action.group.id)) return state;
      return { ...state, groups: [...state.groups, action.group] };

    case 'renameGroup':
      return {
        ...state,
        groups: state.groups.map((group) =>
          group.id === action.id ? { ...group, label: action.label } : group
        ),
      };

    case 'countOverflow':
      return {
        ...state,
        groups: state.groups.map((group) =>
          group.id === action.id ? { ...group, overflow: group.overflow + 1 } : group
        ),
      };

    case 'closeGroup': {
      const tabs = state.tabs.filter((tab) => tab.groupId !== action.id);
      const groups = state.groups.filter((group) => group.id !== action.id);
      if (tabs.length === 0) {
        const tab = newTab();
        return { tabs: [tab], activeId: tab.id, groups };
      }
      // The active tab may have been inside the group that just went away.
      const activeId = tabs.some((tab) => tab.id === state.activeId)
        ? state.activeId
        : tabs[tabs.length - 1].id;
      return { tabs, activeId, groups };
    }

    case 'toolResult':
      return {
        ...state,
        tabs: state.tabs.map((tab) =>
          tab.kind === 'tool' && tab.tool?.callId === action.callId
            ? {
                ...tab,
                tool: { ...tab.tool, result: action.result, failed: action.failed },
              }
            : tab
        ),
      };

    default:
      return state;
  }
}

/**
 * A group with no tabs left is not a group. Dropping it here — rather than
 * leaving an empty chip in the strip — is what makes closing pivt's tabs one at
 * a time behave the same as closing the group.
 */
function pruneGroups(groups: TabGroup[], tabs: Tab[], closed: Tab): TabGroup[] {
  if (!closed.groupId) return groups;
  const stillPopulated = tabs.some((tab) => tab.groupId === closed.groupId);
  return stillPopulated ? groups : groups.filter((group) => group.id !== closed.groupId);
}
