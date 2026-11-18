// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5588: what pivt knows and may do on the Alerts surfaces (the shared
// `usePivtPage` contract, NAN-5571). Context comes from data the pages already
// hold; actions call the REST client as the analyst (`pivtApi`, audited with
// `request_origin: pivt`).
//
// Targets are frozen when the card first shows (`bind`), and only alerts the
// page is showing can be targeted: pivt can never act on an alert id it read
// from log text or made up.
import { definePivtAction, PivtRefusal, type PivtActionSpec, type PivtParamSchema } from '@/contexts/pivt-page';
import { pivtApi } from '@/lib/api/pivt-api';
import type { Alert } from '@/lib/api/types';

export type Disposition = 'true_positive' | 'false_positive' | 'benign';
const DISPOSITIONS: Disposition[] = ['true_positive', 'false_positive', 'benign'];

/** Compact, serialisable view of an alert for the page context. */
export function alertSummary(a: Alert) {
  return {
    id: a.id,
    rule: a.rule_name ?? null,
    severity: a.severity,
    status: a.status,
    disposition: a.disposition ?? null,
    assignee: a.assignee_name ?? a.assigned_to ?? null,
    created_at: a.created_at,
    events: a.matched_event_count ?? a.matched_events?.length ?? 0,
    triage_verdict: a.triage_verdict ?? null,
  };
}

const EVENT_FIELDS = [
  'time', 'timestamp', '@timestamp', 'class_name', 'activity_name', 'source_type', 'metadata.product.name',
  'src_endpoint.ip', 'dst_endpoint.ip', 'src_ip', 'dest_ip', 'dst_endpoint.port', 'dest_port',
  'actor.user.name', 'user.name', 'user', 'device.hostname', 'src_endpoint.hostname', 'host', 'src_host',
  'process.name', 'process.cmd_line', 'process_name', 'command_line', 'file.path', 'url.url_string',
  'status', 'message',
];

function flatten(v: unknown, prefix = '', out: Record<string, unknown> = {}, depth = 0): Record<string, unknown> {
  if (v && typeof v === 'object' && !Array.isArray(v) && depth < 4) {
    for (const [k, inner] of Object.entries(v as Record<string, unknown>)) flatten(inner, prefix ? `${prefix}.${k}` : k, out, depth + 1);
  } else if (prefix) {
    out[prefix] = v;
  }
  return out;
}

/** A matched event reduced to the fields an analyst triages on (log data:
    the server fences it; this keeps it small enough to survive the cap). */
export function projectEvent(e: Record<string, unknown>): Record<string, string> {
  const flat = flatten(e);
  const out: Record<string, string> = {};
  for (const key of EVENT_FIELDS) {
    const v = flat[key];
    if (v === undefined || v === null || v === '') continue;
    const s = typeof v === 'string' ? v : JSON.stringify(v);
    out[key] = s.length > 200 ? `${s.slice(0, 200)}…` : s;
  }
  return out;
}

export interface AlertTargets {
  /** Alerts the page shows now (the only ones an action may target). */
  visible: () => Alert[];
  /** Ids the analyst selected, if the page has a selection. */
  selected?: () => string[];
  /** Fixed target (alert detail page). */
  fixed?: () => Alert | null;
  /** Refresh the page after a change. */
  onChanged?: () => void;
}

/** Most alerts one pivt action may change (the card lists every one). */
export const MAX_TARGETS = 25;

interface Bound {
  alert_ids?: string[];
}

/** Resolve the alerts an action applies to, now; throws a reason if none. */
function resolveTargets(t: AlertTargets, alertId?: string): string[] {
  const fixed = t.fixed?.();
  if (fixed) {
    if (alertId && alertId !== fixed.id) throw new PivtRefusal('This card targets a different alert than the one open.');
    return [fixed.id];
  }
  const visible = new Set(t.visible().map((a) => a.id));
  if (alertId) {
    if (!visible.has(alertId)) throw new PivtRefusal(`Alert ${alertId} is not on this page.`);
    return [alertId];
  }
  const selected = (t.selected?.() ?? []).filter((id) => visible.has(id));
  if (selected.length === 0) throw new PivtRefusal('Select the alerts first, or name one alert.');
  if (selected.length > MAX_TARGETS) {
    throw new PivtRefusal(`${selected.length} alerts are selected; pivt acts on at most ${MAX_TARGETS} at a time.`);
  }
  return selected;
}

function rowsFor(ids: string[], t: AlertTargets): Array<[string, string]> {
  const byId = new Map(t.visible().map((a) => [a.id, a]));
  const fixed = t.fixed?.();
  if (fixed) byId.set(fixed.id, fixed);
  // Every target is listed: the analyst approves exactly these.
  return ids.map((id) => {
    const a = byId.get(id);
    return [id, a ? `${a.severity} · ${a.status} · ${a.rule_name ?? 'alert'}` : 'alert'];
  });
}

async function forEachId(ids: string[], fn: (id: string) => Promise<unknown>): Promise<{ ok: number; failed: number }> {
  let ok = 0;
  let failed = 0;
  for (const id of ids) {
    try {
      await fn(id);
      ok += 1;
    } catch {
      failed += 1;
    }
  }
  return { ok, failed };
}

/**
 * Acknowledge / close actions for an alerts surface.
 *
 * Offered only where the page itself offers triage (NAN-1066): on a tenant
 * licensed for Cases, alert triage happens in the case, so pivt does not add
 * a path the UI removed. Monitor alerts keep triage. `states` limits which
 * actions fit the open alert (no acknowledging a closed one).
 */
export function alertActions(
  t: AlertTargets,
  opts: { triageAllowed: boolean; status?: Alert['status'] } = { triageAllowed: true },
): PivtActionSpec[] {
  if (!opts.triageAllowed || opts.status === 'closed') return [];
  const ackFits = opts.status === undefined || opts.status === 'new';
  const idParam: PivtParamSchema = t.fixed
    ? {}
    : {
        alert_id: {
          type: 'string' as const,
          description: 'One alert id shown on this page; omit to use the selected alerts',
          maxLength: 64,
        },
      };
  const actions: PivtActionSpec[] = [];
  if (ackFits) actions.push(
    definePivtAction<{ alert_id?: string } & Bound>({
      name: 'alerts.acknowledge',
      description: t.fixed ? 'Acknowledge this alert.' : 'Acknowledge the selected alerts, or one alert shown on this page.',
      params: idParam,
      permission: 'alerts:acknowledge',
      mutates: true,
      bind: (p) => ({ ...p, alert_ids: resolveTargets(t, p.alert_id) }),
      preview: (p) => ({
        summary: `Acknowledge ${p.alert_ids?.length ?? 0} alert${p.alert_ids?.length === 1 ? '' : 's'}`,
        rows: rowsFor(p.alert_ids ?? [], t),
      }),
      run: async (p) => {
        const r = await forEachId(p.alert_ids ?? [], (id) => pivtApi.acknowledgeAlert(id));
        t.onChanged?.();
        if (r.ok === 0) throw new Error('No alert was acknowledged.');
        return { summary: `Acknowledged ${r.ok}${r.failed ? `, ${r.failed} failed` : ''}` };
      },
    }),
  );
  actions.push(
    definePivtAction<{ alert_id?: string; disposition: Disposition } & Bound>({
      name: 'alerts.close',
      description: t.fixed
        ? 'Close this alert with a disposition.'
        : 'Close the selected alerts, or one alert shown on this page, with a disposition.',
      params: {
        ...idParam,
        disposition: { type: 'enum', description: 'Why it is closed', required: true, values: DISPOSITIONS },
      },
      permission: 'alerts:close',
      mutates: true,
      bind: (p) => ({ ...p, alert_ids: resolveTargets(t, p.alert_id) }),
      preview: (p) => ({
        summary: `Close ${p.alert_ids?.length ?? 0} alert${p.alert_ids?.length === 1 ? '' : 's'} as ${p.disposition.replace('_', ' ')}`,
        rows: rowsFor(p.alert_ids ?? [], t),
      }),
      run: async (p) => {
        const r = await forEachId(p.alert_ids ?? [], (id) =>
          pivtApi.closeAlert(id, { disposition: p.disposition }),
        );
        t.onChanged?.();
        if (r.ok === 0) throw new Error('No alert was closed.');
        return { summary: `Closed ${r.ok} as ${p.disposition.replace('_', ' ')}${r.failed ? `, ${r.failed} failed` : ''}` };
      },
    }),
  );
  return actions;
}

/** Read-only: open Search with an nPL query (a pivot from what is on screen). */
export function searchPivotAction(navigate: (to: string) => void): PivtActionSpec {
  return definePivtAction<{ query: string }>({
    name: 'search.pivot',
    description: 'Open Search with an nPL query (e.g. the entity from this alert).',
    params: { query: { type: 'string', description: 'nPL query', required: true, maxLength: 2000 } },
    permission: 'search:execute',
    mutates: false,
    preview: (p) => ({ summary: 'Open this search', rows: [['nPL', p.query]] }),
    run: async (p) => {
      navigate(`/search#q=${encodeURIComponent(p.query)}`);
      return { summary: 'Opened Search' };
    },
  });
}
