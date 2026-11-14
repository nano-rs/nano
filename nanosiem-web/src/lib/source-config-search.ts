// SPDX-License-Identifier: AGPL-3.0-or-later

import { nplExactEquals, nplLiteral } from '@/lib/npl-quote';

/**
 * The Search URL for a source configuration's events (NAN-5348).
 *
 * A source configuration is a transport; its events are the source types its
 * routing rules tag them with. `field` is the profile's routing-key field
 * (`metadata.log_source` on OCSF, `source_type` on UDM — see
 * `useSchemaFieldMap().field('logSource')`). Search reads the query from the
 * `q` fragment parameter. With no routing target there is nothing to filter
 * on, so Search opens unfiltered.
 */
export function sourceConfigSearchUrl(field: string, targetSourceTypes: readonly string[]): string {
  const targets = [...new Set(targetSourceTypes.map((t) => t.trim()).filter(Boolean))];
  if (targets.length === 0) return '/search';
  const query =
    targets.length === 1
      ? nplExactEquals(field, targets[0]!)
      : `${field} IN (${targets.map((t) => nplLiteral(t).literal).join(', ')})`;
  return `/search#q=${encodeURIComponent(query)}`;
}
