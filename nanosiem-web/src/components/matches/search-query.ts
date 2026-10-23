// SPDX-License-Identifier: AGPL-3.0-or-later
import { parseNplFlow } from '@/lib/npl-flow-parser';
import { nplFieldRef } from '@/lib/npl-pipeline';
import { nplQuoted, nplQuotedBody } from '@/lib/npl-quote';

const AGGREGATIONS = new Set(['stats', 'eventstats', 'streamstats', 'timechart', 'chart', 'top', 'rare']);

// Tokenize identifiers separately from literals and function arguments so a
// "by" inside an aggregate expression cannot become the group-by clause.
function groupFields(stage: string): string[] {
  const tokens = stage.match(/"[^"\n]*"|'[^'\n]*'|[A-Za-z_][A-Za-z0-9_.]*|[^\s]/g) ?? [];
  let depth = 0;
  const by = tokens.findIndex((token) => {
    if (token === '(') depth++;
    if (token === ')') depth--;
    return depth === 0 && token.toLowerCase() === 'by';
  });
  if (by < 0) return [];
  return tokens.slice(by + 1).filter((token) => token !== ',').map((token) => token.replace(/^["']|["']$/g, ''));
}

function fieldValue(row: Record<string, unknown>, field: string): unknown {
  if (Object.prototype.hasOwnProperty.call(row, field)) return row[field];
  return field.split('.').reduce<unknown>((value, key) =>
    value && typeof value === 'object' ? (value as Record<string, unknown>)[key] : undefined, row);
}

/** Raw contributing events: keep detection transforms/filters, stop before aggregation. */
export function ruleMatchSearchQuery(
  query: string,
  events: Record<string, unknown>[],
  entity?: { raw?: string; label?: string; type: string } | null,
  ocsf = true,
): string {
  const { stages } = parseNplFlow(query);
  const aggregate = stages.findIndex((stage) => AGGREGATIONS.has(stage.command));
  const prefix = (aggregate < 0 ? stages : stages.slice(0, aggregate)).map((stage) => stage.rawText).join(' | ') || '*';
  const fields = aggregate < 0 ? [] : groupFields(stages[aggregate].rawText);
  let filter = '';
  if (fields.length) {
    const groups = events.map((row) => fields.map((field) => {
      const value = fieldValue(row, field);
      if (typeof value === 'string') return `${nplFieldRef(field)}=${nplQuoted(value)}`;
      if ((typeof value === 'number' && Number.isFinite(value)) || typeof value === 'boolean') return `${nplFieldRef(field)}=${value}`;
      return undefined;
    }));
    // Never guess a user/IP for an aggregate group. Older matches can omit
    // group columns; show the detection's raw event scope in that case.
    if (groups.length && groups.every((group) => group.every(Boolean))) {
      filter = [...new Set(groups.map((group) => `(${group.join(' AND ')})`))].join(' OR ');
    }
  } else if (entity) {
    const raw = (entity.raw || entity.label || '').trim();
    const escaped = nplQuotedBody(raw);
    let entityFilter: string;
    switch (entity.type) {
      case 'user':
      case 'role':
      case 'service':
        entityFilter = ocsf
          ? raw.startsWith('arn:')
            ? `(actor.user.uid="${escaped}" OR actor.user.name="${escaped}")`
            : `(actor.user.name="${escaped}" OR actor.user.uid="${escaped}" OR user.name="${escaped}" OR user.uid="${escaped}")`
          : raw.startsWith('arn:')
            ? `user_identity.arn="${escaped}"`
            : `user="${escaped}"`;
        break;
      case 'host':
        entityFilter = ocsf
          ? `(device.hostname="${escaped}" OR src_endpoint.hostname="${escaped}" OR dst_endpoint.hostname="${escaped}")`
          : `(src_host="${escaped}" OR dest_host="${escaped}" OR hostname="${escaped}")`;
        break;
      case 'ip':
        entityFilter = ocsf
          ? `(src_endpoint.ip="${escaped}" OR dst_endpoint.ip="${escaped}")`
          : `(src_ip="${escaped}" OR dest_ip="${escaped}")`;
        break;
      default:
        entityFilter = `"${escaped}"`;
    }
    if (raw) filter = entityFilter;
  }
  if (!filter) return prefix;
  // A pipeline filter must follow pre-aggregation eval/where stages, because
  // group fields may be computed there. Preserve source OR precedence too.
  return aggregate === 1 || stages.length === 1 ? `(${prefix}) (${filter})`
    : `${prefix} | ${!fields.length && entity?.type === 'other' ? 'search' : 'where'} ${filter}`;
}
