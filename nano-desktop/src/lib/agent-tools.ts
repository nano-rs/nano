import type { TimeRangeValue } from '@/lib/time-range';

/**
 * Turning pivt's tool calls into the product's own surfaces.
 *
 * The point of the desktop app's agent integration is that pivt doesn't narrate
 * what it did — it *does it in the app*. A search pivt runs becomes a real search
 * tab the analyst can read, re-run, widen, and pivot off. This module is the
 * translation layer: MCP tool name + arguments in, a description of the tab to
 * open out.
 *
 * The tool names here are the REAL ones exposed by
 * `@nano-rs/investigator-mcp-server` (`search`, `search_sql`, `get_field_values`,
 * `explain_query`, …), reaching the panel prefixed as `mcp__nano__search`. They
 * are NOT the `nano.search` names in the design mock — those were illustrative.
 */

/** What opening this tool call should produce in the workspace. */
export type Mirror =
  /** A real search tab: nPL we can hand straight to `/api/search`. */
  | { as: 'search'; query: string; range: TimeRangeValue; run: boolean; label: string }
  /**
   * A panel of the dashboard pivt is building. Drawn into the live draft the
   * moment it is validated, so the analyst watches the dashboard assemble.
   */
  | { as: 'draft-panel' }
  /** pivt saved a dashboard: open the real, saved thing. */
  | { as: 'dashboard' }
  /** Everything else: an inspectable record of the call and what came back. */
  | { as: 'tool'; label: string }
  /** Deliberately not mirrored — see NOISE. */
  | { as: 'skip' };

/**
 * Tools that carry no investigative content and would only add junk tabs.
 * `get_schema` is a once-per-session lookup of the column inventory; mirroring it
 * gives the analyst a tab that says "pivt read the schema", which nobody wants.
 * The activity card in the panel still shows the call, so nothing is hidden.
 */
const NOISE = new Set([
  'get_schema',
  'list_saved_searches',
  'get_saved_search',
  // Reading the dashboard contract and checking a draft against it are pivt
  // thinking, not pivt doing. Both are visible in the activity card.
  'get_dashboard_schema',
  'validate_dashboard',
  'list_dashboards',
]);

const NANO_PREFIX = 'mcp__nano__';

/** `mcp__nano__search` → `search`. */
export function baseName(toolName: string): string {
  return toolName.startsWith(NANO_PREFIX) ? toolName.slice(NANO_PREFIX.length) : toolName;
}

/**
 * The MCP server takes relative times (`-24h`, `-7d`, `-30m`), `now`, or ISO 8601
 * — mirroring `parseRelativeTime` in the server. A relative window maps onto the
 * product's own preset where one matches exactly, so the tab's picker reads
 * "Last 24 hours" rather than a pair of frozen timestamps that stop tracking now.
 */
const RELATIVE_TO_PRESET: Record<string, string> = {
  '-5m': 'Last 5 minutes',
  '-15m': 'Last 15 minutes',
  '-30m': 'Last 30 minutes',
  '-1h': 'Last hour',
  '-4h': 'Last 4 hours',
  '-12h': 'Last 12 hours',
  '-24h': 'Last 24 hours',
  '-1d': 'Last 24 hours',
  '-7d': 'Last 7 days',
  '-30d': 'Last 30 days',
  '-90d': 'Last 90 days',
};

const RELATIVE = /^-(\d+)(m|h|d|w)$/;

export function toRange(startTime: unknown, endTime: unknown): TimeRangeValue {
  const start = typeof startTime === 'string' ? startTime.trim() : '';
  const end = typeof endTime === 'string' ? endTime.trim() : '';

  // A relative start with an open (or "now") end is the overwhelmingly common
  // shape, and the only one a preset can honestly represent.
  const openEnded = !end || end === 'now';
  if (openEnded) {
    const preset = RELATIVE_TO_PRESET[start.toLowerCase()];
    if (preset) return { type: 'preset', preset };

    // A relative window with no exact preset (e.g. "-3h", "-2w") still has to
    // resolve to something true, so pin it to concrete timestamps rather than
    // rounding it to a neighbouring preset and quietly searching the wrong window.
    const match = RELATIVE.exec(start.toLowerCase());
    if (match) {
      const value = Number(match[1]);
      const now = new Date();
      const from = new Date(now);
      if (match[2] === 'm') from.setMinutes(from.getMinutes() - value);
      if (match[2] === 'h') from.setHours(from.getHours() - value);
      if (match[2] === 'd') from.setDate(from.getDate() - value);
      if (match[2] === 'w') from.setDate(from.getDate() - value * 7);
      return { type: 'custom', start: from, end: now };
    }
  }

  const from = parseAbsolute(start);
  const to = openEnded ? new Date() : parseAbsolute(end);
  if (from && to) return { type: 'custom', start: from, end: to };

  // `start_time` is required by the tool schema, so we only land here on a
  // malformed one. The server's own default is 24h; match it rather than
  // inventing a window pivt never asked for.
  return { type: 'preset', preset: 'Last 24 hours' };
}

function parseAbsolute(value: string): Date | null {
  if (!value || value === 'now') return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * Decide what a tool call becomes in the workspace.
 *
 * Only nPL is runnable as a search tab: `/api/search` takes a piped query, not
 * SQL (`SearchRequest.query` in nanosiem-core). So `search_sql` — which is the
 * server's PRIMARY tool and what pivt reaches for most — is mirrored as an
 * inspectable tool tab showing the SQL it ran, NOT as a search tab we'd have to
 * fake. Showing the analyst SQL that the tab can't actually run would be worse
 * than showing it plainly.
 */
export function mirrorFor(toolName: string, input: Record<string, unknown>): Mirror {
  // Only nano's tools are the product. Claude Code brings its own built-ins along
  // (a real run opens with a `ToolSearch` call before it ever reaches for nano),
  // and mirroring those would put tabs in the analyst's workspace for things that
  // have nothing to do with their data. They stay visible in the panel's activity
  // card; they just don't become tabs.
  if (!toolName.startsWith(NANO_PREFIX)) return { as: 'skip' };

  const name = baseName(toolName);
  if (NOISE.has(name)) return { as: 'skip' };

  const range = () => toRange(input.start_time, input.end_time);

  switch (name) {
    case 'search': {
      const query = asString(input.query);
      if (!query) return { as: 'tool', label: 'search' };
      // A source_type argument is a filter in its own right; fold it into the
      // query so the tab searches what pivt searched, not a wider set.
      const sourceType = asString(input.source_type);
      const full = sourceType ? `source_type="${sourceType}" ${query}` : query;
      return { as: 'search', query: full, range: range(), run: true, label: full };
    }

    case 'explain_query': {
      // pivt asked what this COMPILES to; it deliberately did not run it. The tab
      // is staged with the query and left idle — running it would be the app
      // doing something pivt chose not to.
      const query = asString(input.query);
      if (!query) return { as: 'tool', label: 'explain_query' };
      return { as: 'search', query, range: range(), run: false, label: query };
    }

    // pivt validating a panel of the dashboard it is building. Each one is drawn
    // as it lands — the point of the whole exercise. A `dashboard_panel_query`
    // with NO panel hint is pivt just looking at data; that's a search.
    case 'dashboard_panel_query': {
      if (input.panel && typeof input.panel === 'object') return { as: 'draft-panel' };
      const query = asString(input.query);
      if (!query || input.query_mode === 'sql') return { as: 'tool', label: 'dashboard_panel_query' };
      return { as: 'search', query, range: range(), run: true, label: query };
    }

    // It SAVED. Open the real dashboard, not a description of it.
    case 'create_dashboard':
    case 'update_dashboard':
      return { as: 'dashboard' };

    // Reading one is not saving one. Mapping this to `dashboard` meant a re-read —
    // which pivt does routinely, e.g. after a 409 on expected_updated_at — turned
    // the analyst's live draft into some OTHER, existing dashboard and threw the
    // draft away.
    case 'get_dashboard':
      return { as: 'skip' };

    case 'get_field_values': {
      // "Top values of field F" IS an nPL aggregation. Mirroring it as the
      // equivalent query gives the analyst a tab they can actually build on,
      // rather than a screenshot of pivt's answer.
      const field = asString(input.field);
      if (!field) return { as: 'tool', label: 'get_field_values' };
      const scope = asString(input.query);
      const limit = typeof input.limit === 'number' ? Math.trunc(input.limit) : 10;
      const head = limit > 0 && limit <= 1000 ? limit : 10;
      const prefix = scope && scope !== '*' ? `${scope} | ` : '';
      const query = `${prefix}stats count by ${field} | sort -count | head ${head}`;
      return { as: 'search', query, range: range(), run: true, label: query };
    }

    default:
      return { as: 'tool', label: name };
  }
}
