// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Splitting an nPL query into its base search and its pipeline (NAN-2209).
 *
 * This logic existed twice — a regex-aware copy in `pages/Search.tsx` and a
 * quote-only copy in `components/search/SearchResults.tsx`. The second silently
 * split inside regex literals, so `user=/admin|root/ | stats …` yielded the
 * base `user=/admin`. That does not error: the planner compiles it to
 * `lower("user") = '/admin'` (an equality match on a literal string) instead of
 * the intended `iLike '%admin%' OR iLike '%root%'`, so the analyst's filter is
 * silently dropped. One implementation, used everywhere, is the fix.
 */

// Explicit `.ts` extension (tsconfig `allowImportingTsExtensions`) so this
// module resolves under the `node --test` runner as well as Vite/tsc.
import { nplQuoted } from './npl-quote.ts';

/**
 * Index of the first `|` that is a genuine command separator — i.e. not inside
 * a double-quoted string and not inside a `field=/regex/` literal. `-1` when
 * the query has no pipeline.
 *
 * Regex detection keys off the `=` / `!=` immediately preceding the opening
 * `/`, which is what makes `user=/admin|root/` survive intact while a bare
 * `path=/var/log` (no operator before the second slash) still behaves.
 */
export function findFirstPipePosition(q: string): number {
  let inRegex = false;
  let inQuote = false;
  let escapeNext = false;

  for (let i = 0; i < q.length; i++) {
    const c = q[i];

    if (escapeNext) {
      escapeNext = false;
      continue;
    }

    if (c === '\\') {
      escapeNext = true;
      continue;
    }

    if (c === '"' && !inRegex) {
      inQuote = !inQuote;
      continue;
    }

    if (c === '/' && !inQuote) {
      if (!inRegex) {
        // Opening delimiter only when it directly follows a comparison operator.
        const before = q.substring(0, i).trimEnd();
        if (before.endsWith('=') || before.endsWith('!=')) {
          inRegex = true;
        }
      } else {
        inRegex = false;
      }
      continue;
    }

    if (c === '|' && !inRegex && !inQuote) {
      return i;
    }
  }

  return -1;
}

/** The search terms before the first top-level `|` (the whole query if none). */
export function getBaseSearch(q: string): string {
  const pipePos = findFirstPipePosition(q);
  return pipePos === -1 ? q.trim() : q.substring(0, pipePos).trim();
}

/** The pipeline from the first top-level `|` onward (empty when there is none). */
export function getPipeCommands(q: string): string {
  const pipePos = findFirstPipePosition(q);
  return pipePos === -1 ? '' : q.substring(pipePos).trim();
}

/** Rows returned by a one-click group-by before the analyst edits the query. */
export const GROUP_BY_ROW_LIMIT = 20;

/**
 * A bare (unquoted) nPL field reference: an identifier, optionally dotted for
 * OCSF paths (`src_endpoint.ip`, `actor.process.name`) or `ext.` keys.
 */
const NPL_BARE_FIELD = /^[A-Za-z_][A-Za-z0-9_.]*$/;

/**
 * A field name in a position that expects an identifier (e.g. `stats … by`).
 *
 * UDM/OCSF column names are bare identifiers and dotted OCSF paths parse
 * correctly unquoted — verified against the live query planner, which emits
 * `"src_endpoint.ip"` in the generated SQL either way. But `ext.*` keys come
 * from parsed log data and can carry spaces or punctuation, so anything that is
 * not a plain identifier is quoted (the parser accepts the quoted form in the
 * same position).
 */
export function nplFieldRef(field: string): string {
  return NPL_BARE_FIELD.test(field) ? field : nplQuoted(field);
}

/**
 * The one-click "group by this field" query (NAN-2209): keep the analyst's
 * existing filters, drop whatever pipeline followed them, and aggregate.
 *
 * Takes the analyst's FULL query and extracts the base itself — callers must
 * not pre-extract, or we reopen the split-implementation bug this module was
 * created to close. An empty or `*` base becomes an explicit `*`: nPL needs a
 * search term before the first pipe, and a bare leading `|` is not the shape we
 * want to put in front of the analyst.
 */
export function buildGroupByQuery(query: string | undefined, field: string): string {
  const base = getBaseSearch(query ?? '');
  const prefix = base && base !== '*' ? base : '*';
  return `${prefix} | stats count by ${nplFieldRef(field)} | sort -count | head ${GROUP_BY_ROW_LIMIT}`;
}
