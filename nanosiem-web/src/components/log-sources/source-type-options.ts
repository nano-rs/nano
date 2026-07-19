// SPDX-License-Identifier: AGPL-3.0-or-later

import type { LogSource } from '@/lib/api';

export interface SourceTypeOption {
  /** Canonical `source_type` stamped on a feed when this parser is chosen. */
  sourceType: string;
  /** Human-facing parser / log-source name shown as the subtitle. */
  parserName: string;
  /**
   * Routing aliases the parser also matches (`match_values` minus the canonical
   * `source_type`). Used for search and for resolving an already-stored value —
   * NOT rendered as separate rows (NAN-1916).
   */
  aliases: string[];
}

/**
 * Transport sentinels that are not parsers and must never appear as a selectable
 * "route this feed to a parser" option (`SourceType::Routed` / `Vector` — the
 * markers AddFeed writes for pull-transport / vector-native feeds).
 */
const SENTINEL_SOURCE_TYPES = new Set(['routed', 'vector']);

/**
 * Build **one option per parser** (log source).
 *
 * NAN-1916: the picker used to flatten each log source's `source_type` AND every
 * `match_value` into its own row, so a parser declaring N aliases (e.g.
 * LimaCharlie EDR: `limacharlie` / `lima_charlie` / `lc_sensor` / `lc_edr`)
 * showed N near-identical rows. `match_values` are routing aliases — the parser
 * accepts events tagged any of them — not distinct user choices, so they are
 * kept only for search/selection matching here.
 */
export function buildSourceTypeOptions(logSources: LogSource[]): SourceTypeOption[] {
  const seen = new Set<string>();
  const result: SourceTypeOption[] = [];

  for (const ls of logSources) {
    const declared = ls.source_type;
    if (!declared || SENTINEL_SOURCE_TYPES.has(declared)) {
      continue;
    }
    const matchValues = (ls.match_values ?? []).filter(Boolean);

    // The value we stamp must be one the router will actually match. The router
    // matches `.source_type` against `match_values` only (falling back to the
    // parser name when match_values is empty), NOT against the log source's
    // `source_type` column — so if a parser's declared source_type isn't among
    // its match_values, stamp the primary match_value instead of a value that
    // would silently never route.
    const canonical =
      matchValues.length === 0 || matchValues.includes(declared)
        ? declared
        : matchValues[0];

    if (seen.has(canonical)) {
      continue;
    }
    seen.add(canonical);

    // Everything else that should still resolve to this parser (search + an
    // already-stored value) but isn't the stamped canonical.
    const aliases = Array.from(
      new Set([...matchValues, declared].filter((v) => v && v !== canonical))
    );

    result.push({ sourceType: canonical, parserName: ls.name, aliases });
  }

  return result.sort((a, b) => a.sourceType.localeCompare(b.sourceType));
}

/**
 * Resolve the option for a stored value, matching the canonical `source_type` OR
 * any alias — so a feed saved on an alias (e.g. `lc_edr`) still shows its parser
 * instead of flashing "no parser" (NAN-1916).
 */
export function findSelectedOption(
  options: SourceTypeOption[],
  value: string
): SourceTypeOption | undefined {
  if (!value) return undefined;
  return options.find((o) => o.sourceType === value || o.aliases.includes(value));
}

/** Whether an option matches a search query (source_type, parser name, or any alias). */
export function optionMatchesSearch(option: SourceTypeOption, search: string): boolean {
  if (!search) return true;
  const q = search.toLowerCase();
  return (
    option.sourceType.toLowerCase().includes(q) ||
    option.parserName.toLowerCase().includes(q) ||
    option.aliases.some((a) => a.toLowerCase().includes(q))
  );
}
