// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5571: the Search page's pivt registration — what pivt knows here and
// what it may do. Read from the page's own state; nothing is fetched.
//
// Actions (as the analyst; state changes go through `pivtApi`, marked via pivt):
// - search.run          run an nPL query here via the page's own search (one click)
// - search.save         save the current search          (search:save, confirm)
// - search.create_rule  create a STAGING rule from it    (detections:create, confirm)
//
// Humans see nPL (machines → SQL, humans → nPL): `search.run` takes nPL only,
// and the rule action is offered only for an nPL search.
import { useMemo } from 'react';
import { definePivtAction, usePivtPage, type PivtActionSpec } from '@/contexts/pivt-page';
import { pivtApi } from '@/lib/api/pivt-api';
import type { CreateDetectionRequest, SavedSearchTimeRange } from '@/lib/api/types';

export interface SearchPivtState {
  query: string;
  queryMode: 'piped' | 'sql';
  /** Human label of the time window, e.g. "Last 24 hours". */
  timeLabel: string;
  hasSearched: boolean;
  /** The query bar still holds the query that ran (and its mode). */
  queryIsCurrent: boolean;
  total: number;
  executionTimeMs: number | null;
  /** Top fields from the field index (name → distinct values seen). */
  topFields: Array<{ field: string; distinct?: number }>;
  /** A few rows from the page, already on screen. */
  sampleRows: Array<Record<string, unknown>>;
  /** Run `query` here as nPL (the page's own run path). */
  runQuery: (query: string) => void;
  /** The time range to store on a saved search. */
  savedTimeRange: () => SavedSearchTimeRange | undefined;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];

/** Page state a Search action applies to, frozen into its params by `bind`
    when the card first shows (NAN-5571 review: Apply must do what the card
    showed, even after the analyst runs another query). */
interface Bound {
  query?: string;
  window?: string;
  time_range?: SavedSearchTimeRange;
}

function buildActions(s: SearchPivtState): PivtActionSpec[] {
  const bindPage = <P extends object>(p: P): P & Bound => ({
    ...p,
    query: s.query,
    window: s.timeLabel,
    time_range: s.savedTimeRange(),
  });
  const actions: PivtActionSpec[] = [
    definePivtAction<{ query: string }>({
      name: 'search.run',
      description: 'Run an nPL query on this Search page (replaces the query bar). Use for refinements and pivots.',
      params: { query: { type: 'string', description: 'The nPL query to run', required: true, maxLength: 4000 } },
      permission: 'search:execute',
      mutates: false,
      preview: (p) => ({ summary: 'Run this search', rows: [['nPL', p.query]] }),
      // Runs through the page's own search path (the analyst's session); a
      // search changes no state and is not audited as an action.
      run: async (p) => {
        s.runQuery(p.query);
        return { summary: 'Search started' };
      },
    }),
  ];
  // Save / rule only for an nPL search that has run and is still in the bar:
  // humans see nPL, and the card shows exactly the query that ran.
  const savable = s.hasSearched && s.queryMode === 'piped' && !!s.query.trim() && s.queryIsCurrent;
  if (savable) {
    actions.push(
      definePivtAction<{ name: string; visibility?: 'private' | 'public' } & Bound>({
        name: 'search.save',
        description: 'Save the current search under a name.',
        params: {
          name: { type: 'string', description: 'Saved search name', required: true, maxLength: 120 },
          visibility: { type: 'enum', description: 'private (default) or public', values: ['private', 'public'] },
        },
        permission: 'search:save',
        mutates: true,
        bind: bindPage,
        preview: (p) => ({
          summary: `Save the search as "${p.name}"`,
          rows: [
            ['nPL', p.query ?? ''],
            ['window', p.window ?? ''],
            ['visibility', p.visibility ?? 'private'],
          ],
        }),
        run: async (p) => {
          const saved = await pivtApi.createSavedSearch({
            name: p.name,
            query: p.query ?? '',
            query_mode: 'piped',
            time_range: p.time_range,
            visibility: p.visibility ?? 'private',
          });
          return { summary: `Saved "${saved.name}"` };
        },
      }),
      definePivtAction<{ name: string; severity: string; description?: string } & Bound>({
        name: 'search.create_rule',
        description: 'Create a detection rule from the current nPL search, in staging (not executed until promoted).',
        params: {
          name: { type: 'string', description: 'Rule name', required: true, maxLength: 160 },
          severity: { type: 'enum', description: 'Rule severity', required: true, values: SEVERITIES },
          description: { type: 'string', description: 'What the rule detects', maxLength: 1000 },
        },
        permission: 'detections:create',
        mutates: true,
        bind: bindPage,
        preview: (p) => ({
          summary: `Create staging rule "${p.name}" from this search`,
          rows: [
            ['nPL', p.query ?? ''],
            ['severity', p.severity],
            ['mode', 'staging'],
            ...(p.description ? ([['description', p.description]] as Array<[string, string]>) : []),
          ],
        }),
        run: async (p) => {
          const rule = await pivtApi.createDetection({
            name: p.name,
            description: p.description,
            query: p.query ?? '',
            severity: p.severity as CreateDetectionRequest['severity'],
            mode: 'staging',
            ai_generated: true,
          });
          return { summary: `Created staging rule ${rule.name}`, href: `/rules/editor/${rule.id}` };
        },
      }),
    );
  }
  return actions;
}

export function useSearchPivtPage(s: SearchPivtState): void {
  // Actions close over the latest state through `s`; rebuilt when it changes.
  const actions = useMemo(() => buildActions(s), [s]);
  usePivtPage({
    icon: 'Search',
    getContext: () => ({
      pageKey: 'search',
      title: s.hasSearched ? 'Search · results' : 'Search',
      facts: s.hasSearched
        ? [
            { label: s.queryMode === 'sql' ? 'SQL' : 'nPL', value: s.query || '— (empty)' },
            { label: 'window', value: s.timeLabel },
            { label: 'results', value: s.total > 0 ? `${s.total.toLocaleString()} events` : 'no matches' },
            ...(s.executionTimeMs !== null ? [{ label: 'took', value: `${s.executionTimeMs} ms` }] : []),
          ]
        : [{ label: 'viewing', value: 'search console' }],
      data: s.hasSearched
        ? {
            query: s.query,
            query_language: s.queryMode === 'sql' ? 'sql' : 'npl',
            window: s.timeLabel,
            total: s.total,
            top_fields: s.topFields.slice(0, 15),
            sample_rows: s.sampleRows.slice(0, 5),
          }
        : undefined,
    }),
    actions,
    suggestions: s.hasSearched
      ? s.total > 0
        ? ['Summarize these results', 'Which source IPs stand out?', 'Create a detection from this query']
        : ['Why might this return nothing?', 'Widen the time range']
      : undefined,
  });
}

/** For tests. */
export const buildSearchActions = buildActions;
