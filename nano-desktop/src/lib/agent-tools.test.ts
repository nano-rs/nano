import { describe, expect, it } from 'vitest';

import { baseName, mirrorFor, toRange } from './agent-tools';

/**
 * This module decides what pivt's tool calls become in the analyst's workspace.
 * Getting it wrong is not a cosmetic bug: a mirrored tab that searches a
 * DIFFERENT window, or a different query, than the one pivt actually ran is a
 * tab that lies about what the agent did.
 */

describe('baseName', () => {
  it('strips the MCP wire prefix', () => {
    expect(baseName('mcp__nano__search')).toBe('search');
    expect(baseName('mcp__nano__search_sql')).toBe('search_sql');
  });

  it('leaves a bare name alone', () => {
    expect(baseName('search')).toBe('search');
  });
});

describe('toRange', () => {
  it('maps the relative windows the MCP server accepts onto product presets', () => {
    expect(toRange('-24h', 'now')).toEqual({ type: 'preset', preset: 'Last 24 hours' });
    expect(toRange('-7d', undefined)).toEqual({ type: 'preset', preset: 'Last 7 days' });
    expect(toRange('-15m', 'now')).toEqual({ type: 'preset', preset: 'Last 15 minutes' });
  });

  it('pins a relative window with no matching preset to real timestamps', () => {
    // "-3h" has no preset. Rounding it to "Last 4 hours" would search an hour
    // pivt never asked about.
    const range = toRange('-3h', 'now');
    expect(range.type).toBe('custom');
    const spanHours = (range.end!.getTime() - range.start!.getTime()) / 3_600_000;
    expect(spanHours).toBeCloseTo(3, 1);
  });

  it('honours an absolute window', () => {
    const range = toRange('2026-07-01T00:00:00Z', '2026-07-02T00:00:00Z');
    expect(range.type).toBe('custom');
    expect(range.start?.toISOString()).toBe('2026-07-01T00:00:00.000Z');
    expect(range.end?.toISOString()).toBe('2026-07-02T00:00:00.000Z');
  });

  it('falls back to the server default rather than inventing a window', () => {
    expect(toRange('gibberish', undefined)).toEqual({ type: 'preset', preset: 'Last 24 hours' });
    expect(toRange(undefined, undefined)).toEqual({ type: 'preset', preset: 'Last 24 hours' });
  });
});

describe('mirrorFor — searches become real search tabs', () => {
  it('mirrors an nPL search verbatim and runs it', () => {
    const mirror = mirrorFor('mcp__nano__search', {
      query: 'user=admin | stats count by src_ip',
      start_time: '-7d',
    });
    expect(mirror).toEqual({
      as: 'search',
      query: 'user=admin | stats count by src_ip',
      range: { type: 'preset', preset: 'Last 7 days' },
      run: true,
      label: 'user=admin | stats count by src_ip',
    });
  });

  it('folds a source_type argument into the query, so the tab searches what pivt searched', () => {
    const mirror = mirrorFor('mcp__nano__search', {
      query: 'logon failure',
      start_time: '-24h',
      source_type: 'windows',
    });
    expect(mirror.as).toBe('search');
    if (mirror.as !== 'search') throw new Error('expected a search mirror');
    // Without this, the tab would search ALL sources and show more than pivt saw.
    expect(mirror.query).toBe('source_type="windows" logon failure');
  });

  it('translates get_field_values into the aggregation it actually is', () => {
    const mirror = mirrorFor('mcp__nano__get_field_values', {
      field: 'process_name',
      start_time: '-24h',
      limit: 5,
    });
    if (mirror.as !== 'search') throw new Error('expected a search mirror');
    expect(mirror.query).toBe('stats count by process_name | sort -count | head 5');
    expect(mirror.run).toBe(true);
  });

  it('scopes get_field_values by its query when it has one', () => {
    const mirror = mirrorFor('mcp__nano__get_field_values', {
      field: 'dest_port',
      query: 'src_ip=10.0.0.1',
      start_time: '-24h',
    });
    if (mirror.as !== 'search') throw new Error('expected a search mirror');
    expect(mirror.query).toBe('src_ip=10.0.0.1 | stats count by dest_port | sort -count | head 10');
  });

  it('stages explain_query WITHOUT running it — pivt chose not to run it either', () => {
    const mirror = mirrorFor('mcp__nano__explain_query', {
      query: 'src_ip=10.0.0.1',
      start_time: '-1h',
    });
    if (mirror.as !== 'search') throw new Error('expected a search mirror');
    expect(mirror.run).toBe(false);
  });
});

describe('mirrorFor — everything else', () => {
  it('records search_sql as a tool tab, since /api/search takes nPL and not SQL', () => {
    const mirror = mirrorFor('mcp__nano__search_sql', {
      sql: 'SELECT * FROM logs LIMIT 1',
      start_time: '-24h',
    });
    // Offering to "run" SQL in a tab that can only run nPL would run something else.
    expect(mirror).toEqual({ as: 'tool', label: 'search_sql' });
  });

  it('records an unknown tool rather than dropping it', () => {
    expect(mirrorFor('mcp__nano__list_detections', {})).toEqual({
      as: 'tool',
      label: 'list_detections',
    });
  });

  it('skips the metadata chatter that would only add junk tabs', () => {
    expect(mirrorFor('mcp__nano__get_schema', {}).as).toBe('skip');
  });

  it("skips Claude Code's own built-ins — they are not the product", () => {
    // Observed in a real pivt run: the agent opens with a `ToolSearch` call
    // before it ever reaches nano. A tab for that would be pure noise.
    expect(mirrorFor('ToolSearch', { query: 'nano events' }).as).toBe('skip');
    expect(mirrorFor('TodoWrite', {}).as).toBe('skip');
  });

  it('falls back to a tool tab when a search call carries no query', () => {
    expect(mirrorFor('mcp__nano__search', { start_time: '-24h' }).as).toBe('tool');
  });
});
