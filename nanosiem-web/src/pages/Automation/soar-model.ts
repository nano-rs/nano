// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540 — pure view models for the Automation workspace. Everything here is
 * derived from server DTOs; nothing is invented. Where the API has no field
 * (actor names, blast radius, live polling stage) the UI omits the element.
 */
import type {
  SoarApproval,
  SoarCatalog,
  SoarCatalogAction,
  SoarCatalogPack,
  SoarConnection,
  SoarRun,
  SoarStepResult,
} from '@/lib/api/soar';

export type Effect = 'read' | 'write' | 'destructive';
export type Outcome =
  | 'queued'
  | 'running'
  | 'waiting'
  | 'ok'
  | 'failed'
  | 'canceled'
  | 'timed_out'
  | 'unknown';

export const TERMINAL_RUN_STATUSES = new Set(['succeeded', 'failed', 'canceled', 'timed_out']);

export function isTerminal(status: string): boolean {
  return TERMINAL_RUN_STATUSES.has(status);
}

export function runOutcome(run: Pick<SoarRun, 'status'>, steps?: SoarStepResult[]): Outcome {
  // "Ambiguous" is a step outcome: the vendor may already have applied it.
  if (steps?.some((s) => s.status === 'ambiguous')) return 'unknown';
  switch (run.status) {
    case 'queued': return 'queued';
    case 'running': return 'running';
    case 'suspended': return 'waiting';
    case 'succeeded': return 'ok';
    case 'failed': return 'failed';
    case 'canceled': return 'canceled';
    case 'timed_out': return 'timed_out';
    default: return 'unknown';
  }
}

export function asEffect(value: string | null | undefined): Effect | null {
  return value === 'read' || value === 'write' || value === 'destructive' ? value : null;
}

export interface IndexedAction {
  pack: SoarCatalogPack;
  action: SoarCatalogAction;
}

export function actionIndex(catalog: SoarCatalog | undefined): Map<string, IndexedAction> {
  const index = new Map<string, IndexedAction>();
  for (const pack of catalog?.packs ?? []) {
    for (const action of pack.actions) index.set(`${pack.name}.${action.name}`, { pack, action });
  }
  return index;
}

export function lookupAction(
  index: Map<string, IndexedAction>,
  pack: string | null | undefined,
  action: string | null | undefined,
): IndexedAction | undefined {
  if (!pack || !action) return undefined;
  return index.get(`${pack}.${action}`);
}

export interface TargetValue {
  name: string;
  value: string;
  kind: EntityKind;
}

/** Scalar inputs of an action run, typed by the action schema when known. */
export function inputTargets(
  inputs: unknown,
  action?: SoarCatalogAction,
  max = 3,
): TargetValue[] {
  if (!inputs || typeof inputs !== 'object' || Array.isArray(inputs)) return [];
  const out: TargetValue[] = [];
  for (const [name, raw] of Object.entries(inputs as Record<string, unknown>)) {
    if (raw === null || raw === undefined || raw === '') continue;
    let value: string;
    if (typeof raw === 'string' || typeof raw === 'number' || typeof raw === 'boolean') value = String(raw);
    else if (Array.isArray(raw) && raw.every((x) => typeof x === 'string')) value = raw.join(', ');
    else continue;
    const schema = action?.inputs.find((i) => i.name === name);
    out.push({ name, value, kind: entityKindForInput(name, schema?.type) });
    if (out.length >= max) break;
  }
  return out;
}

export type EntityKind = 'host' | 'user' | 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'value';

export const ENTITY_KINDS: Array<{ kind: EntityKind; label: string }> = [
  { kind: 'host', label: 'Host' },
  { kind: 'user', label: 'User' },
  { kind: 'ip', label: 'IP' },
  { kind: 'domain', label: 'Domain' },
  { kind: 'hash', label: 'File hash' },
  { kind: 'url', label: 'URL' },
  { kind: 'email', label: 'Email' },
];

/** Map an action input (declared type first, then its name) to an entity kind. */
export function entityKindForInput(name: string, type?: string): EntityKind {
  const t = (type ?? '').toLowerCase();
  if (t === 'ip') return 'ip';
  if (t === 'domain') return 'domain';
  if (t === 'hash') return 'hash';
  if (t === 'url') return 'url';
  if (t === 'email') return /user|login|account/i.test(name) ? 'user' : 'email';
  if (/host|device|machine|endpoint|agent/i.test(name)) return 'host';
  if (/user|login|account|principal/i.test(name)) return 'user';
  if (/(^|_)ip($|_)|address/i.test(name)) return 'ip';
  if (/hash|sha|md5/i.test(name)) return 'hash';
  if (/url/i.test(name)) return 'url';
  if (/domain|fqdn/i.test(name)) return 'domain';
  if (/email|mail/i.test(name)) return 'email';
  return 'value';
}

/** Case entity types → the kinds an action input can accept. */
export function entityKindForCaseType(type: string): EntityKind | null {
  switch (type) {
    case 'host': return 'host';
    case 'user': return 'user';
    case 'ip': return 'ip';
    case 'domain': return 'domain';
    case 'hash':
    case 'file': return 'hash';
    case 'url': return 'url';
    case 'email': return 'email';
    default: return null;
  }
}

/** Packs that can execute right now: installed, enabled and not withdrawn. */
export function packUsable(pack: SoarCatalogPack): boolean {
  return pack.installed && pack.enabled && !pack.withdrawn;
}

export type PackState = 'available' | 'installed' | 'update' | 'disabled' | 'withdrawn';

export function packState(pack: SoarCatalogPack): PackState {
  if (pack.withdrawn) return 'withdrawn';
  if (pack.installed && !pack.enabled) return 'disabled';
  if (pack.installed && pack.upstream_changed) return 'update';
  if (pack.installed) return 'installed';
  return 'available';
}

export interface EntityActionChoice {
  pack: SoarCatalogPack;
  action: SoarCatalogAction;
  /** The input the entity value prefills. */
  input: string;
  connections: SoarConnection[];
  /** Why it cannot be requested now, or null. */
  blocked: string | null;
}

/**
 * Verb palette: actions whose declared input accepts this entity kind, from
 * installed packs only, with the tenant's connections for that pack.
 */
export function actionsForEntity(
  kind: EntityKind,
  catalog: SoarCatalog | undefined,
  connections: SoarConnection[],
): EntityActionChoice[] {
  const out: EntityActionChoice[] = [];
  for (const pack of catalog?.packs ?? []) {
    if (!pack.installed) continue;
    for (const action of pack.actions) {
      const input = action.inputs.find((i) => entityKindForInput(i.name, i.type) === kind);
      if (!input) continue;
      const packConnections = connections.filter((c) => c.pack_name === pack.name);
      const blocked = pack.withdrawn
        ? 'Release withdrawn'
        : !pack.enabled
          ? 'Pack disabled'
          : packConnections.length === 0
            ? 'No connection'
            : null;
      out.push({ pack, action, input: input.name, connections: packConnections, blocked });
    }
  }
  const order: Record<string, number> = { read: 0, write: 1, destructive: 2 };
  return out.sort(
    (a, b) =>
      Number(!!a.blocked) - Number(!!b.blocked) ||
      (order[a.action.effect] ?? 3) - (order[b.action.effect] ?? 3) ||
      a.action.display_name.localeCompare(b.action.display_name),
  );
}

export interface CapabilityCell {
  pack: SoarCatalogPack;
  actions: SoarCatalogAction[];
}

/** Entity kind × installed pack: which actions accept that entity. */
export function capabilityMatrix(catalog: SoarCatalog | undefined) {
  const packs = (catalog?.packs ?? []).filter((p) => p.installed);
  const rows = ENTITY_KINDS.map(({ kind, label }) => {
    const cells = packs.map((pack) => ({
      pack,
      actions: pack.actions.filter((a) => a.inputs.some((i) => entityKindForInput(i.name, i.type) === kind)),
    }));
    return { kind, label, cells, covered: cells.some((c) => c.actions.length > 0 && packUsable(c.pack)) };
  });
  return { packs, rows };
}

// ── Time ────────────────────────────────────────────────────────────────

export function utcTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().slice(11, 19);
}

export function utcDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  if (s < 10) return `${s.toFixed(1)}s`;
  // Round once, then split, so 119.6s reads "2m 0s" and never "1m 60s".
  const total = Math.round(s);
  if (total < 60) return `${total}s`;
  const m = Math.floor(total / 60);
  if (m < 60) return `${m}m ${total % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function runDuration(run: Pick<SoarRun, 'started_at' | 'finished_at' | 'created_at'>, now = Date.now()): string {
  const start = Date.parse(run.started_at ?? run.created_at);
  const end = run.finished_at ? Date.parse(run.finished_at) : now;
  return formatDuration(end - start);
}

/** Minutes until expiry (negative once expired). */
export function minutesLeft(expiresAt: string, now = Date.now()): number {
  return Math.floor((Date.parse(expiresAt) - now) / 60_000);
}

export function shortId(id: string | null | undefined): string {
  return id ? id.slice(0, 8) : '—';
}

/** "CASE-1042" when the server sent the number (NAN-4556), else "case 3a7c91e2". */
export function caseLabel(id: string | null | undefined, number?: number | null): string {
  if (!id) return 'no case';
  return number != null ? `CASE-${number}` : `case ${shortId(id)}`;
}

// ── Run trace ───────────────────────────────────────────────────────────

export type SpanKind = 'ok' | 'fail' | 'wait' | 'amb' | 'active' | 'none';

export interface StepSpan {
  step: SoarStepResult;
  start: number;
  duration: number;
  kind: SpanKind;
}

export function spanKind(status: string): SpanKind {
  switch (status) {
    case 'succeeded': return 'ok';
    case 'failed':
    case 'timed_out': return 'fail';
    case 'awaiting_approval':
    case 'would_wait': return 'wait';
    case 'ambiguous': return 'amb';
    case 'preparing':
    case 'sending':
    case 'running': return 'active';
    default: return 'none';
  }
}

/** Offsets on a run-local axis from server step timestamps. */
export function stepSpans(steps: SoarStepResult[], now = Date.now()): { spans: StepSpan[]; total: number } {
  if (steps.length === 0) return { spans: [], total: 1 };
  const t0 = Math.min(...steps.map((s) => s.started_at_ms));
  const spans = steps.map((step) => {
    const kind = spanKind(step.status);
    const end = step.finished_at_ms ?? (kind === 'none' ? step.started_at_ms : now);
    return { step, start: step.started_at_ms - t0, duration: Math.max(0, end - step.started_at_ms), kind };
  });
  const total = Math.max(1, ...spans.map((s) => s.start + s.duration));
  return { spans, total };
}

// ── Runs volume strip ──────────────────────────────────────────────────

export interface RunBucket {
  start: number;
  ok: number;
  fail: number;
  wait: number;
  run: number;
}

export const BUCKET_MS = 30 * 60_000;
export const BUCKETS_24H = 48;

/** 30-minute UTC buckets over the trailing 24h, from the loaded runs only. */
export function bucketRuns(runs: SoarRun[], now = Date.now()): RunBucket[] {
  const end = Math.ceil(now / BUCKET_MS) * BUCKET_MS;
  const begin = end - BUCKETS_24H * BUCKET_MS;
  const buckets: RunBucket[] = Array.from({ length: BUCKETS_24H }, (_, i) => ({
    start: begin + i * BUCKET_MS, ok: 0, fail: 0, wait: 0, run: 0,
  }));
  for (const run of runs) {
    const at = Date.parse(run.created_at);
    if (!(at >= begin && at < end)) continue;
    const bucket = buckets[Math.floor((at - begin) / BUCKET_MS)];
    const outcome = runOutcome(run);
    if (outcome === 'failed' || outcome === 'timed_out') bucket.fail++;
    else if (outcome === 'waiting') bucket.wait++;
    else if (outcome === 'running' || outcome === 'queued') bucket.run++;
    else bucket.ok++;
  }
  return buckets;
}

// ── Flow transit map ───────────────────────────────────────────────────

export type FlowNodeKind =
  | 'action'
  | 'approval'
  | 'loop'
  | 'branchone'
  | 'branchall'
  | 'identity'
  | 'search'
  | 'judge'
  | 'email'
  | 'unknown';

export interface FlowNode {
  id: string;
  summary: string;
  kind: FlowNodeKind;
  pack?: string;
  action?: string;
  /** Step approval policy: default, required or auto. */
  approval?: string;
  prompt?: string;
  options?: string[];
  query?: string;
  window?: string;
  question?: string;
  parallel?: boolean;
  timeoutSecs?: number;
  retries?: number;
  continueOnError?: boolean;
  skipIf?: string;
  branches: Array<{ label: string; nodes: FlowNode[] }>;
}

function rec(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}
function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function parseModules(value: unknown, depth: number): FlowNode[] {
  if (!Array.isArray(value) || depth > 6) return [];
  return value.map((raw, i) => parseModule(raw, depth, i));
}

function parseModule(raw: unknown, depth: number, i: number): FlowNode {
  const m = rec(raw) ?? {};
  const v = rec(m.value) ?? {};
  const type = str(v.type) ?? '';
  const kind: FlowNodeKind =
    type === 'action' ? 'action'
      : type === 'approval' ? 'approval'
        : type === 'forloopflow' ? 'loop'
          : type === 'branchone' ? 'branchone'
            : type === 'branchall' ? 'branchall'
              : type === 'identity' ? 'identity'
                : type === 'search' ? 'search'
                  : type === 'judge' ? 'judge'
                    : type === 'notify.email' ? 'email'
                      : 'unknown';
  const node: FlowNode = {
    id: str(m.id) ?? `step_${i + 1}`,
    summary: str(m.summary) ?? '',
    kind,
    branches: [],
  };
  if (kind === 'action') {
    node.pack = str(v.pack);
    node.action = str(v.action);
    node.approval = str(v.approval) ?? 'default';
  }
  if (kind === 'email') node.approval = str(v.approval) ?? 'default';
  if (kind === 'approval') {
    node.prompt = str(v.prompt);
    node.options = Array.isArray(v.options) ? v.options.filter((o): o is string => typeof o === 'string') : [];
  }
  if (kind === 'search') {
    node.query = str(v.query);
    node.window = str(v.window);
  }
  if (kind === 'judge') node.question = str(v.question);
  if (kind === 'loop') {
    node.parallel = v.parallel === true;
    node.branches = [{ label: 'for each', nodes: parseModules(v.modules, depth + 1) }];
  }
  if (kind === 'branchone') {
    const branches = Array.isArray(v.branches) ? v.branches : [];
    node.branches = branches.map((b, j) => {
      const br = rec(b) ?? {};
      return { label: str(br.expr) ?? str(br.summary) ?? `branch ${j + 1}`, nodes: parseModules(br.modules, depth + 1) };
    });
    node.branches.push({ label: 'default', nodes: parseModules(v.default, depth + 1) });
  }
  if (kind === 'branchall') {
    node.parallel = v.parallel === true;
    const branches = Array.isArray(v.branches) ? v.branches : [];
    node.branches = branches.map((b, j) => {
      const br = rec(b) ?? {};
      return { label: str(br.summary) || `branch ${j + 1}`, nodes: parseModules(br.modules, depth + 1) };
    });
  }
  const timeout = rec(m.timeout);
  if (timeout && typeof timeout.value === 'number') node.timeoutSecs = timeout.value;
  const retry = rec(m.retry);
  const policy = rec(retry?.constant) ?? rec(retry?.exponential);
  if (policy && typeof policy.attempts === 'number') node.retries = policy.attempts;
  if (m.continue_on_error === true) node.continueOnError = true;
  const skip = rec(m.skip_if);
  if (skip) node.skipIf = str(skip.expr);
  return node;
}

export interface FlowGraph {
  summary: string;
  description: string;
  nodes: FlowNode[];
}

export function flowGraph(definition: unknown): FlowGraph {
  const doc = rec(definition) ?? {};
  const value = rec(doc.value) ?? {};
  return {
    summary: str(doc.summary) ?? '',
    description: str(doc.description) ?? '',
    nodes: parseModules(value.modules, 0),
  };
}

export function countNodes(nodes: FlowNode[]): number {
  return nodes.reduce((n, node) => n + 1 + node.branches.reduce((b, br) => b + countNodes(br.nodes), 0), 0);
}

export function flowDepth(nodes: FlowNode[]): number {
  if (nodes.length === 0) return 0;
  return 1 + Math.max(0, ...nodes.flatMap((n) => n.branches.map((b) => flowDepth(b.nodes))));
}

export type LineStop = Effect | 'gate' | 'fork' | 'loop' | 'search' | 'judge' | 'email' | 'pass';

/** Top-level station sequence for the flow list preview line. */
export function flowLine(nodes: FlowNode[], index: Map<string, IndexedAction>): LineStop[] {
  return nodes.map((n) => {
    switch (n.kind) {
      case 'action': return asEffect(lookupAction(index, n.pack, n.action)?.action.effect) ?? 'write';
      case 'approval': return 'gate';
      case 'branchone':
      case 'branchall': return 'fork';
      case 'loop': return 'loop';
      case 'search': return 'search';
      case 'judge': return 'judge';
      case 'email': return 'email';
      default: return 'pass';
    }
  });
}

/** NAN-4535 / NAN-4588: router state the flow view reads to label a flow
 *  pivt just drafted (set by the pivt panel when it navigates to the draft). */
export interface PivtFlowDraftState {
  pivtDraft: { repaired: boolean; approval_gates: number };
}

export function triggerLabel(trigger: { on?: string; cron?: string | null; match?: string | null } | null | undefined): string {
  if (!trigger?.on) return 'manual';
  switch (trigger.on) {
    case 'manual': return 'Manual';
    case 'alert': return trigger.match ? `Alert committed · ${trigger.match}` : 'Alert committed';
    case 'case': return trigger.match ? `Case event · ${trigger.match}` : 'Case event';
    case 'case.triage_verdict': return 'Case triage verdict';
    case 'schedule': return trigger.cron ? `Schedule · ${trigger.cron} UTC` : 'Schedule';
    default: return trigger.on;
  }
}

// ── Approvals ──────────────────────────────────────────────────────────

export interface DecisionContext {
  userId: string | undefined;
  canApprove: boolean;
  demo: boolean;
  now?: number;
}

/** Why the current user cannot decide, mirroring the server's refusals. */
export function decisionBlock(approval: SoarApproval, ctx: DecisionContext): string | null {
  if (approval.status !== 'pending') return 'Already decided';
  if (Date.parse(approval.expires_at) <= (ctx.now ?? Date.now())) return 'Expired';
  if (ctx.demo) return 'Read-only demo';
  if (!ctx.canApprove) return 'Requires soar:approve';
  if (ctx.userId && approval.requested_by === ctx.userId) return 'You requested this; another approver must decide';
  return null;
}

export function approvalOptions(approval: SoarApproval): string[] {
  const options = approval.requested_action?.options;
  return Array.isArray(options) ? options.filter((o): o is string => typeof o === 'string') : [];
}

export function reasonRequired(approval: SoarApproval, choice: string | undefined): boolean {
  const note = approval.requested_action?.note_required_on;
  return typeof note === 'string' && note.length > 0 && note === choice;
}

export function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).length;
}

export const REASON_MAX_BYTES = 2048;

// ── NAN-4546: mock vocabulary ───────────────────────────────────────────

const VENDOR_CODES: Array<[RegExp, string]> = [
  [/crowdstrike|falcon/i, 'CS'],
  [/okta/i, 'OK'],
  [/virustotal|virus_total/i, 'VT'],
  [/abuse/i, 'AB'],
  [/palo|pan[-_]?os/i, 'PA'],
  [/defender|microsoft|entra|m365|graph/i, 'MD'],
  [/slack/i, 'SL'],
  [/jira|atlassian/i, 'JI'],
  [/urlscan/i, 'US'],
  [/nano|core|search/i, 'NA'],
  [/email|mail|smtp/i, 'EM'],
];

/** Two-letter vendor badge for a pack name (CS, OK, VT…). */
export function vendorCode(pack: string, label?: string): string {
  const s = `${pack} ${label ?? ''}`;
  for (const [re, code] of VENDOR_CODES) if (re.test(s)) return code;
  const parts = pack.replace(/^nano[-_]?/, '').split(/[-_.\s]+/).filter(Boolean);
  const code = parts.length > 1 ? `${parts[0][0]}${parts[1][0]}` : (parts[0] ?? pack).slice(0, 2);
  return code.toUpperCase() || '??';
}

const VERBS: Array<[RegExp, string]> = [
  [/lift|uncontain|release|unisolate|lift_containment/i, 'Lift containment'],
  [/contain|isolate|quarantine/i, 'Contain'],
  [/unblock|unban/i, 'Unblock'],
  [/block|ban|deny/i, 'Block'],
  [/unsuspend|reactivate|activate_user|unlock/i, 'Reactivate'],
  [/suspend|disable|deactivate|lock/i, 'Suspend'],
  [/clear_sessions|revoke|signout|sign_out|kill_session/i, 'Revoke sessions'],
  [/reset_password|password/i, 'Reset password'],
  [/add_ioc|ioc_add|add_indicator|create_ioc/i, 'Add IOC'],
  [/remove_ioc|delete_ioc/i, 'Remove IOC'],
  [/notify|post|message|send/i, 'Notify'],
  [/create_issue|ticket|create_ticket/i, 'Ticket'],
  [/scan|detonate|submit/i, 'Scan'],
  [/search|hunt|query/i, 'Hunt'],
  [/get|lookup|look_up|check|enrich|reputation|describe|list|read/i, 'Look up'],
];

/** Short analyst verb for an action ("Contain", "Look up", "Hunt"…). */
export function verbOf(action: string, title?: string | null): string {
  for (const [re, verb] of VERBS) if (re.test(action)) return verb;
  if (title) return title;
  const w = action.replace(/[_.-]+/g, ' ').trim();
  return w ? w[0].toUpperCase() + w.slice(1) : action;
}
