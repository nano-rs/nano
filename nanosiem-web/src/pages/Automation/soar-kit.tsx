// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — the SOAR visual grammar, ported from the v3 design mocks
 * (soar2-kit.jsx, soar2-b.jsx, soar-shell.jsx) onto app tokens.
 *
 * Effect: read = outline, write = solid warn, destructive = hatched danger.
 * ↺ = an inverse action exists. Colors come from index.css tokens only.
 */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { AlertTriangle, Eye, Globe, Hash, Link as LinkIcon, Lock, Mail, Monitor, PenLine, Tag, User, Zap } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button, type ButtonProps } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import type { Effect, EntityKind, Outcome as RunOutcome } from './soar-model';
import { minutesLeft, vendorCode } from './soar-model';

// ── Patterns (mock: HATCH / HATCH_SOFT / WAIT / FOG) ────────────────────
const danger = (pct: number) => `color-mix(in srgb, var(--destructive) ${pct}%, transparent)`;
const warn = (pct: number) => `color-mix(in srgb, var(--warning) ${pct}%, transparent)`;
export const HATCH = `repeating-linear-gradient(135deg, ${danger(75)} 0 1.5px, transparent 1.5px 4px)`;
export const HATCH_SOFT = `repeating-linear-gradient(135deg, ${danger(22)} 0 1.5px, transparent 1.5px 5px)`;
export const WAIT = `repeating-linear-gradient(135deg, ${warn(35)} 0 1.5px, transparent 1.5px 5px)`;
export const FOG = `repeating-linear-gradient(90deg, ${warn(50)} 0 2px, transparent 2px 6px)`;
export const AMBER = 'var(--warning)';

export const PAGE_TITLE = 'text-[20px] font-semibold leading-none tracking-[-0.01em] text-foreground';
export const smallButton = 'h-7 px-2.5 text-[11.5px] shadow-none';
export const xsButton = 'h-6 px-2 text-[11px] shadow-none';

export const EFF_TXT: Record<Effect, string> = { read: 'text-fg-2', write: 'text-warn', destructive: 'text-destructive' };
export const EFFECT_TEXT = EFF_TXT;

// ── Effect mark ──────────────────────────────────────────────────────────
export function EffMark({ e, size = 10, className }: { e: Effect | null | undefined; size?: number; className?: string }) {
  const base = { width: size, height: size, borderRadius: 2, flexShrink: 0, display: 'inline-block' } as const;
  if (!e) return <span aria-hidden className={className} style={{ ...base, height: 1 }} />;
  if (e === 'read') return <span aria-hidden className={className} style={{ ...base, border: '1.5px solid var(--muted-foreground)' }} />;
  if (e === 'write') return <span aria-hidden className={className} style={{ ...base, background: AMBER }} />;
  return <span aria-hidden className={className} style={{ ...base, background: HATCH, boxShadow: 'inset 0 0 0 1.5px var(--destructive)' }} />;
}
/** Legacy name. */
export function EffectMark({ effect, size = 9, className }: { effect: Effect | null; size?: number; className?: string }) {
  return <EffMark e={effect} size={size} className={className} />;
}

export function EffectTag({ effect, className }: { effect: Effect | null | undefined; className?: string }) {
  if (!effect) return null;
  return <span className={cn('shrink-0 font-mono text-[10.5px]', effect === 'read' ? 'text-muted-foreground' : EFF_TXT[effect], className)}>{effect}</span>;
}

/** Mock EffectBadge: bordered effect label. */
export function EffectBadge({ effect, className }: { effect: Effect | null | undefined; className?: string }) {
  if (!effect) return null;
  const cls = {
    read: 'text-fg-2 border-border-2 bg-foreground/[0.03]',
    write: 'text-warn border-warning/30 bg-warning/[0.07]',
    destructive: 'text-destructive border-destructive/35 bg-destructive/[0.08]',
  }[effect];
  return (
    <span className={cn('inline-flex h-[18px] items-center gap-1 whitespace-nowrap rounded-[3px] border px-1.5 font-mono text-[10px] font-medium', cls, className)}>
      {effect === 'read' ? <Eye className="h-[11px] w-[11px]" strokeWidth={1.5} /> : effect === 'write' ? <PenLine className="h-[11px] w-[11px]" strokeWidth={1.5} /> : <AlertTriangle className="h-[11px] w-[11px]" strokeWidth={1.5} />}
      {effect === 'read' ? 'Read' : effect === 'write' ? 'Write' : 'Destructive'}
    </span>
  );
}

export function Inv({ className }: { className?: string }) {
  return <span title="Inverse action available" className={cn('font-mono text-[11px] text-muted-foreground', className)}>↺</span>;
}

// ── Vendor badge ────────────────────────────────────────────────────────
export function Vendor({ p, label, ghost, struck, size = 18 }: { p: string; label?: string; ghost?: boolean; struck?: boolean; size?: number }) {
  return (
    <span
      title={label ?? p}
      className={cn(
        'relative inline-flex shrink-0 items-center justify-center rounded-[4px] font-mono font-semibold',
        ghost ? 'border border-dashed border-fg-4 text-fg-4' : 'border border-border-2 bg-foreground/[0.08] text-fg-2',
      )}
      style={{ width: size, height: size, fontSize: size * 0.48 }}
    >
      {vendorCode(p, label)}
      {struck && <span aria-hidden className="absolute inset-x-0.5 top-1/2 h-px rotate-[-30deg] bg-destructive" />}
    </span>
  );
}

// ── Entity ───────────────────────────────────────────────────────────────
export const ENT: Record<EntityKind | 'mailbox', typeof Monitor> = {
  host: Monitor,
  user: User,
  ip: Globe,
  hash: Hash,
  domain: Globe,
  url: LinkIcon,
  email: Mail,
  mailbox: Mail,
  value: Tag,
};

export function Entity({ t, v, size = 'md', className, title }: { t: EntityKind | 'mailbox'; v: string; size?: 'sm' | 'md' | 'lg'; className?: string; title?: string }) {
  const I = ENT[t] ?? Tag;
  return (
    <span
      title={title ?? v}
      className={cn(
        'inline-flex min-w-0 items-center gap-1.5 whitespace-nowrap rounded-[4px] border border-border-2 bg-foreground/[0.03] font-mono text-foreground',
        size === 'lg' ? 'h-[26px] px-2 text-[12.5px]' : size === 'sm' ? 'h-[18px] px-1.5 text-[10.5px]' : 'h-[22px] px-1.5 text-[11.5px]',
        className,
      )}
    >
      <I className={cn('shrink-0 text-muted-foreground', size === 'lg' ? 'h-3.5 w-3.5' : 'h-3 w-3')} strokeWidth={1.5} />
      <span className="truncate">{v}</span>
    </span>
  );
}
/** Legacy name. */
export function EntityChip({ kind, value, className, title }: { kind: EntityKind; value: string; className?: string; title?: string }) {
  return <Entity t={kind} v={value} size="sm" className={cn('max-w-[260px]', className)} title={title} />;
}

// ── Action chip: verb → target · vendor ─────────────────────────────────
export function ActionChip({
  e,
  effect,
  verb,
  t,
  v,
  targets,
  p,
  vendor,
  conn,
  inv,
  size = 'md',
  className,
}: {
  e?: Effect | null;
  /** Legacy alias of `e`. */
  effect?: Effect | null;
  verb: string;
  t?: EntityKind;
  v?: string;
  /** Legacy: several targets. */
  targets?: Array<{ kind: EntityKind; value: string }>;
  /** Pack name for the vendor badge. */
  p?: string | null;
  vendor?: string | null;
  conn?: ReactNode;
  inv?: boolean;
  size?: 'md' | 'lg';
  className?: string;
}) {
  const fx = e ?? effect ?? null;
  const lg = size === 'lg';
  const list = targets ?? (v ? [{ kind: t ?? 'value', value: v }] : []);
  return (
    <span
      className={cn(
        'inline-flex max-w-full items-center overflow-hidden whitespace-nowrap rounded-[6px] border',
        fx === 'destructive' ? 'border-destructive/45' : fx === 'write' ? 'border-warning/40' : 'border-border-2',
        className,
      )}
      data-testid="action-chip"
    >
      <span
        aria-hidden
        className={cn('shrink-0 self-stretch', lg ? 'w-2' : 'w-1.5')}
        style={fx === 'destructive' ? { background: HATCH } : fx === 'write' ? { background: AMBER } : { borderRight: '1px solid var(--border-2)' }}
      />
      <span className={cn('flex min-w-0 items-center', lg ? 'h-10 gap-2.5 px-3' : 'h-7 gap-2 px-2')}>
        <span className={cn('shrink-0 font-medium', fx ? EFF_TXT[fx] : 'text-foreground', lg ? 'text-[15px]' : 'text-[12.5px]')}>{verb}</span>
        {list.length > 0 && (
          <>
            <span className={cn('shrink-0 text-fg-4', lg ? 'text-[13px]' : 'text-[11px]')}>→</span>
            {list.map((x, i) => <Entity key={i} t={x.kind} v={x.value} size={lg ? 'lg' : 'md'} />)}
          </>
        )}
        {(p || vendor) && (
          <span className={cn('flex min-w-0 items-center gap-1.5 text-muted-foreground', lg ? 'text-[12px]' : 'text-[11px]')}>
            {p ? <Vendor p={p} label={vendor ?? undefined} size={lg ? 18 : 16} /> : <span className="truncate">{vendor}</span>}
            {conn && <span className="truncate">{conn}</span>}
          </span>
        )}
        {inv && <Inv className={lg ? 'text-[13px]' : ''} />}
      </span>
    </span>
  );
}

// ── Origin: who asked ────────────────────────────────────────────────────
export type OriginKind = 'pivt' | 'trigger' | 'user';
export function originOf(source: string | null | undefined): OriginKind {
  if (source === 'pivt' || source === 'ai') return 'pivt';
  if (source === 'trigger' || source === 'flow' || source === 'playbook' || source === 'schedule' || source === 'alert' || source === 'case') return 'trigger';
  return 'user';
}
export function Origin({ o, who, size = 18 }: { o: OriginKind; who?: ReactNode; size?: number }) {
  if (o === 'pivt') {
    return (
      <span className="inline-flex min-w-0 items-center gap-1.5 text-[11.5px] text-ai">
        <span className="flex shrink-0 items-center justify-center" style={{ width: size, height: size }}>
          <span style={{ width: size * 0.6, height: size * 0.6, transform: 'rotate(45deg)', border: '1.5px solid var(--ai)', background: 'color-mix(in srgb, var(--ai) 15%, transparent)' }} />
        </span>
        <span className="truncate">{who ?? 'pivt'}</span>
      </span>
    );
  }
  if (o === 'trigger') {
    return (
      <span className="inline-flex min-w-0 items-center gap-1.5 text-[11.5px] text-fg-2">
        <span className="flex shrink-0 items-center justify-center rounded-[4px] border border-border-2 text-muted-foreground" style={{ width: size, height: size }}>
          <Zap className="h-[11px] w-[11px]" strokeWidth={1.5} />
        </span>
        <span className="truncate">{who ?? 'trigger'}</span>
      </span>
    );
  }
  const text = typeof who === 'string' ? who : 'user';
  const ini = text.split(/[\s._-]+/).map((s) => s[0] ?? '').join('').slice(0, 2).toUpperCase() || 'U';
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 text-[11.5px] text-fg-2">
      <span className="flex shrink-0 items-center justify-center rounded-full bg-primary/15 font-mono font-semibold text-primary" style={{ width: size, height: size, fontSize: size * 0.42 }}>{ini}</span>
      <span className="truncate">{who ?? 'user'}</span>
    </span>
  );
}

// ── Expiry ring ─────────────────────────────────────────────────────────
export function Ring({ left, total = 60, size = 34, label }: { left: number; total?: number; size?: number; label?: string }) {
  const r = size / 2 - 3;
  const c = 2 * Math.PI * r;
  const f = Math.max(0, Math.min(1, left / total));
  const col = left <= 10 ? 'var(--destructive)' : left <= 20 ? AMBER : 'var(--fg-2)';
  const text = label ?? (left < 0 ? 'exp' : left >= 120 ? `${Math.floor(left / 60)}h` : `${left}m`);
  return (
    <span className="relative inline-flex shrink-0 items-center justify-center" style={{ width: size, height: size }} title={left < 0 ? 'Expired' : `${left}m left`}>
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border-2)" strokeWidth="2" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={col} strokeWidth="2" strokeDasharray={c} strokeDashoffset={c * (1 - f)} strokeLinecap="round" />
      </svg>
      <span className="absolute font-mono font-medium" style={{ fontSize: size * 0.3, color: col }}>{text}</span>
    </span>
  );
}
/** Ring against the approval's own window. */
export function ExpiryRing({ createdAt, expiresAt, size = 30, now = Date.now() }: { createdAt: string; expiresAt: string; size?: number; now?: number }) {
  const left = minutesLeft(expiresAt, now);
  const total = Math.max(1, (Date.parse(expiresAt) - Date.parse(createdAt)) / 60_000);
  return <Ring left={left} total={total} size={size} />;
}

// ── Outcome ─────────────────────────────────────────────────────────────
export type OutcomeKey = 'ok' | 'wait' | 'run' | 'fail' | 'amb' | 'rej';
export function outcomeKey(o: RunOutcome): OutcomeKey {
  switch (o) {
    case 'ok': return 'ok';
    case 'waiting': return 'wait';
    case 'queued':
    case 'running': return 'run';
    case 'failed':
    case 'timed_out': return 'fail';
    case 'unknown': return 'amb';
    default: return 'rej';
  }
}
const OUTCOME_META: Record<OutcomeKey, [string, string, string]> = {
  ok: ['Done', 'text-good', 'bg-success'],
  wait: ['Waiting on approver', 'text-warn', 'bg-warning'],
  run: ['Running', 'text-primary', 'bg-primary'],
  fail: ['Failed · no change', 'text-destructive', 'bg-destructive'],
  amb: ['Unknown · verify target', 'text-warn', ''],
  rej: ['Rejected', 'text-muted-foreground', 'bg-fg-4'],
};
export function Outcome({ s, label, className }: { s: OutcomeKey; label?: string; className?: string }) {
  const m = OUTCOME_META[s];
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap text-[11.5px]', m[1], className)}>
      {s === 'amb' ? <span aria-hidden className="h-1.5 w-2.5 rounded-sm" style={{ background: FOG }} /> : <span aria-hidden className={cn('h-1.5 w-1.5 rounded-full', m[2])} />}
      {label ?? m[0]}
    </span>
  );
}
const RUN_LABEL: Record<RunOutcome, string> = {
  queued: 'Queued', running: 'Running', waiting: 'Waiting on approver', ok: 'Succeeded', failed: 'Failed',
  canceled: 'Canceled', timed_out: 'Timed out', unknown: 'Unknown · verify target',
};
/** Run status with the run's own wording (Succeeded, Canceled, Timed out…). */
export function OutcomeBadge({ outcome, className }: { outcome: RunOutcome; className?: string }) {
  return <Outcome s={outcomeKey(outcome)} label={RUN_LABEL[outcome]} className={className} />;
}
export function OutcomeDot({ outcome }: { outcome: RunOutcome }) {
  const k = outcomeKey(outcome);
  return <span aria-hidden className={cn('h-1.5 w-1.5 shrink-0 rounded-full', RUN_DOT[k])} />;
}
export const RUN_DOT: Record<OutcomeKey, string> = {
  ok: 'bg-fg-4', run: 'bg-primary animate-pulse', wait: 'bg-warning', amb: 'bg-warning', fail: 'bg-destructive', rej: 'border border-fg-4',
};

// ── Receipt (case wall) ─────────────────────────────────────────────────
export function Receipt({ e, verb, t, v, p, vendor, inv, outcome, by, at, run, origin, originWho, onInverse }: {
  e: Effect | null; verb: string; t: EntityKind; v?: string; p?: string | null; vendor?: string; inv?: boolean;
  outcome: ReactNode; by?: string | null; at: string; run: ReactNode; origin: OriginKind; originWho?: ReactNode; onInverse?: () => void;
}) {
  return (
    <div className="flex overflow-hidden rounded-md border border-border bg-card" data-testid="receipt">
      <div aria-hidden className="w-1 shrink-0" style={e === 'destructive' ? { background: HATCH } : e === 'write' ? { background: AMBER } : { background: 'var(--border-2)' }} />
      <div className="flex min-w-0 flex-1 flex-col gap-1.5 px-3 py-2.5">
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground"><Origin o={origin} who={originWho} size={16} /><span className="flex-1" /><span className="font-mono">{at}</span></div>
        <div className="flex flex-wrap items-center gap-2">
          <span className={cn('text-[13px] font-medium', e ? EFF_TXT[e] : 'text-foreground')}>{verb}</span>
          {v && <Entity t={t} v={v} size="sm" />}
          {p && <Vendor p={p} label={vendor} size={16} />}
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px]">
          {outcome}
          {by && <span className="text-muted-foreground">approved by {by}</span>}
          <span className="flex-1" />
          {inv && onInverse && <button type="button" onClick={onInverse} className="font-mono text-[11px] text-fg-2 hover:text-foreground">↺ request inverse</button>}
          <span className="font-mono text-[11px] text-primary">{run}</span>
        </div>
      </div>
    </div>
  );
}

// ── Small text atoms ────────────────────────────────────────────────────
export function H({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground', className)}>{children}</div>;
}
export const SectionLabel = H;

export function Mono({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return <span title={title} className={cn('font-mono text-[11.5px]', className)}>{children}</span>;
}

export function Cite({ n }: { n: number }) {
  return <span className="inline-flex h-4 w-4 items-center justify-center rounded-[3px] bg-ai/15 align-[1px] font-mono text-[9.5px] text-ai">{n}</span>;
}

export function Spinner({ className = 'h-3 w-3' }: { className?: string }) {
  return <LoadingIcon className={className} strokeWidth={1.5} />;
}

export function Note({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('text-[10.5px] leading-[1.5] text-muted-foreground', className)}>{children}</div>;
}

const STATUS: Record<string, [string, string, string]> = {
  queued: ['Queued', 'text-fg-2', 'bg-muted-foreground'], running: ['Running', 'text-primary', 'bg-primary animate-pulse'], suspended: ['Suspended', 'text-warn', 'bg-warning'],
  succeeded: ['Succeeded', 'text-good', 'bg-success'], failed: ['Failed', 'text-destructive', 'bg-destructive'], canceled: ['Canceled', 'text-muted-foreground', 'bg-fg-4'], timed_out: ['Timed out', 'text-destructive', 'bg-destructive'],
  pending: ['Pending', 'text-warn', 'bg-warning'], approved: ['Approved', 'text-good', 'bg-success'], rejected: ['Rejected', 'text-destructive', 'bg-destructive'], expired: ['Expired', 'text-muted-foreground', 'bg-fg-4'],
  available: ['Available', 'text-fg-2', 'bg-muted-foreground'], installed: ['Installed', 'text-good', 'bg-success'], update: ['Update available', 'text-primary', 'bg-primary'], disabled: ['Disabled', 'text-muted-foreground', 'bg-fg-4'], withdrawn: ['Withdrawn', 'text-destructive', 'bg-destructive'],
  passed: ['Test passed', 'text-good', 'bg-success'], untested: ['Not tested', 'text-muted-foreground', 'bg-fg-4'], testfailed: ['Test failed', 'text-destructive', 'bg-destructive'],
  live: ['Live', 'text-good', 'bg-success'], draft: ['Draft', 'text-fg-2', 'bg-muted-foreground'], archived: ['Archived', 'text-muted-foreground', 'bg-fg-4'],
  ambiguous: ['Ambiguous · verify', 'text-warn', 'bg-warning'], waiting: ['Awaiting approval', 'text-warn', 'bg-warning'],
};
export function StatusPill({ s, className, label }: { s: string; className?: string; label?: string }) {
  const v = STATUS[s] ?? [s.replace(/_/g, ' '), 'text-fg-2', 'bg-muted-foreground'];
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap text-[11.5px]', v[1], className)}>
      <span aria-hidden className={cn('h-1.5 w-1.5 shrink-0 rounded-full', v[2])} />
      {label ?? v[0]}
    </span>
  );
}
/** Legacy mono status word. */
export function StatusText({ status, className }: { status: string; className?: string }) {
  return <StatusPill s={status} className={className} />;
}

export function KV({ rows, keyWidth = 130 }: { rows: Array<[ReactNode, ReactNode] | null | false | undefined>; keyWidth?: number }) {
  return (
    <dl className="grid gap-x-3 gap-y-1.5 text-[12px]" style={{ gridTemplateColumns: `${keyWidth}px minmax(0,1fr)` }}>
      {rows.filter(Boolean).map((row, i) => {
        const [k, v] = row as [ReactNode, ReactNode];
        return (
          <div key={i} className="contents">
            <dt className="text-muted-foreground">{k}</dt>
            <dd className="min-w-0 break-words text-foreground">{v}</dd>
          </div>
        );
      })}
    </dl>
  );
}
export function KeyValues({ rows }: { rows: Array<[ReactNode, ReactNode] | null | false> }) {
  return <KV rows={rows} />;
}

// ── Banner ──────────────────────────────────────────────────────────────
export type NoticeTone = 'neutral' | 'warn' | 'danger' | 'good' | 'brand';
export function Banner({ tone = 'neutral', icon, title, children, action, className }: {
  tone?: NoticeTone; icon?: ReactNode; title?: ReactNode; children?: ReactNode; action?: ReactNode; className?: string;
}) {
  const t = {
    neutral: 'border-border-2 bg-foreground/[0.02]', warn: 'border-warning/35 bg-warning/[0.06]', danger: 'border-destructive/35 bg-destructive/[0.06]',
    good: 'border-success/30 bg-success/[0.06]', brand: 'border-primary/30 bg-primary/[0.05]',
  }[tone];
  const ic = { neutral: 'text-muted-foreground', warn: 'text-warn', danger: 'text-destructive', good: 'text-good', brand: 'text-primary' }[tone];
  return (
    <div role={tone === 'danger' ? 'alert' : 'status'} className={cn('flex items-start gap-2.5 rounded-md border px-3 py-2.5', t, className)}>
      <span className={cn('mt-[1px] shrink-0 [&>svg]:h-[14px] [&>svg]:w-[14px]', ic)}>{icon ?? <AlertGlyph />}</span>
      <div className="min-w-0 flex-1 text-[12px] leading-[1.5]">
        {title && <div className="mb-0.5 font-medium text-foreground">{title}</div>}
        {children && <div className="text-fg-2">{children}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}
function AlertGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M12 3 2 20h20z" /><path d="M12 10v4M12 17h.01" />
    </svg>
  );
}
/** Legacy name. */
export function Notice({ tone = 'neutral', title, children, action, className }: { tone?: NoticeTone; title: ReactNode; children?: ReactNode; action?: ReactNode; className?: string }) {
  return <Banner tone={tone} title={title} action={action} className={className}>{children}</Banner>;
}

// ── Permission-gated button (mock GatedButton) ──────────────────────────
export function GatedButton({ allowed, why, reason, children, disabled, className, ...p }: ButtonProps & {
  /** False when the user lacks the permission (or the plan). */
  allowed: boolean;
  /** Tooltip when not allowed, e.g. "Requires soar:manage". */
  why?: string;
  /** Tooltip when allowed but disabled. */
  reason?: string;
}) {
  const title = !allowed ? why : disabled ? reason : undefined;
  return (
    <span title={title} className="inline-flex">
      <Button disabled={disabled || !allowed} className={cn('shadow-none', !allowed && 'cursor-not-allowed', className)} {...p}>
        {!allowed && <Lock className="h-3 w-3" strokeWidth={1.5} />}
        {children}
      </Button>
    </span>
  );
}

// ── Hold to approve (destructive gate) ──────────────────────────────────
export function HoldButton({ onDone, label = 'Hold to approve', ms = 1400, disabled, hotkey = 'a' }: { onDone: () => void; label?: string; ms?: number; disabled?: boolean; hotkey?: string }) {
  const [p, setP] = useState(0);
  const raf = useRef<number>(0);
  const t0 = useRef<number | null>(null);
  const done = useRef(false);
  const tick = (t: number) => {
    if (t0.current === null) t0.current = t;
    const v = Math.min(1, (t - t0.current) / ms);
    setP(v);
    if (v < 1) raf.current = requestAnimationFrame(tick);
    else if (!done.current) {
      done.current = true;
      onDone();
    }
  };
  const down = () => {
    if (disabled) return;
    done.current = false;
    t0.current = null;
    cancelAnimationFrame(raf.current);
    raf.current = requestAnimationFrame(tick);
  };
  const up = () => {
    cancelAnimationFrame(raf.current);
    if (!done.current) setP(0);
  };
  useEffect(() => () => cancelAnimationFrame(raf.current), []);
  return (
    <button
      type="button"
      disabled={disabled}
      aria-label={label}
      aria-keyshortcuts={hotkey.toUpperCase()}
      onPointerDown={down}
      onPointerUp={up}
      onPointerLeave={up}
      onKeyDown={(e) => { if ((e.key === 'Enter' || e.key === ' ' || e.key.toLowerCase() === hotkey) && !e.repeat) { e.preventDefault(); down(); } }}
      onKeyUp={(e) => { if (e.key === 'Enter' || e.key === ' ' || e.key.toLowerCase() === hotkey) up(); }}
      className="relative h-8 min-w-[180px] select-none overflow-hidden rounded-md border border-destructive/60 px-4 text-[12px] font-semibold text-foreground disabled:opacity-50"
      data-testid="hold-to-approve"
    >
      <span aria-hidden className="absolute inset-y-0 left-0 bg-destructive/85" style={{ width: `${p * 100}%` }} />
      <span aria-hidden className="absolute inset-0" style={{ background: HATCH_SOFT }} />
      <span className="relative flex items-center justify-center gap-2">
        {label}
        <span className="rounded border border-border-2 px-1 font-mono text-[10.5px] text-fg-2">{hotkey.toUpperCase()}</span>
      </span>
    </button>
  );
}

// ── Trace span fills ────────────────────────────────────────────────────
export const SPAN_BG: Record<string, React.CSSProperties> = {
  ok: { background: 'var(--fg-4)' },
  done: { background: 'var(--success)' },
  wait: { background: WAIT, boxShadow: `inset 0 0 0 1px ${warn(50)}` },
  poll: { backgroundImage: 'radial-gradient(circle, var(--primary) 1.2px, transparent 1.5px)', backgroundSize: '6px 6px', backgroundPosition: 'center', boxShadow: 'inset 0 0 0 1px color-mix(in srgb, var(--primary) 35%, transparent)' },
  active: { backgroundImage: 'radial-gradient(circle, var(--primary) 1.2px, transparent 1.5px)', backgroundSize: '6px 6px', backgroundPosition: 'center', boxShadow: 'inset 0 0 0 1px color-mix(in srgb, var(--primary) 35%, transparent)' },
  amb: { background: FOG, boxShadow: `inset 0 0 0 1px ${warn(50)}` },
  fail: { background: 'var(--destructive)' },
  cancel: { background: 'var(--fg-4)' },
  queue: { background: 'var(--fg-4)' },
};

// ── Filters ─────────────────────────────────────────────────────────────
export type SegOption<T extends string> = [T, string, number?] | { value: T; label: string; count?: number };
export function FilterSeg<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: Array<SegOption<T>>; label?: string }) {
  return (
    <div role="tablist" aria-label={label} className="inline-flex items-center gap-px rounded-md border border-border bg-foreground/[0.02] p-0.5">
      {options.map((o) => {
        const [v, l, n] = Array.isArray(o) ? o : [o.value, o.label, o.count];
        return (
          <button
            key={v}
            type="button"
            role="tab"
            aria-selected={value === v}
            onClick={() => onChange(v)}
            className={cn('flex h-6 items-center gap-1.5 whitespace-nowrap rounded-[3px] px-2 text-[11.5px]', value === v ? 'bg-primary/15 font-medium text-primary' : 'text-fg-2 hover:text-foreground')}
          >
            {l}
            {n != null && <span className="font-mono text-[10px] opacity-70">{n}</span>}
          </button>
        );
      })}
    </div>
  );
}
/** Legacy name. */
export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (value: T) => void; options: Array<{ value: T; label: string; count?: number }>; label: string }) {
  return <FilterSeg value={value} onChange={onChange} options={options} label={label} />;
}

/** "Label: value" dropdown on our Select. `all` is always the first option. */
export function FilterSelect({ label, value, onChange, options, className }: { label: string; value: string; onChange: (v: string) => void; options: Array<string | [string, string]>; className?: string }) {
  const opts: Array<[string, string]> = [['all', 'all'], ...options.map((o) => (Array.isArray(o) ? o : ([o, o] as [string, string])))];
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger aria-label={label} className={cn('h-7 w-auto min-w-[120px] max-w-[200px] gap-2 bg-background pl-2.5 pr-2 text-[11.5px] text-fg-2 shadow-none', className)}>
        <SelectValue>{`${label}: ${opts.find(([v]) => v === value)?.[1] ?? value}`}</SelectValue>
      </SelectTrigger>
      <SelectContent>
        {opts.map(([v, l]) => <SelectItem key={v} value={v} className="text-[12px]">{`${label}: ${l}`}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

// ── List states (mock ListShell / EmptyState) ───────────────────────────
export function ListState({ state, title, body, onRetry, action, cols }: {
  state: 'loading' | 'empty' | 'error' | 'forbidden' | 'filtered';
  title?: string;
  body?: ReactNode;
  onRetry?: () => void;
  action?: ReactNode;
  /** Skeleton column widths while loading. */
  cols?: number[];
}) {
  if (state === 'loading') {
    return (
      <div role="status" aria-label="Loading" className="flex flex-col">
        {[0, 1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="flex h-10 items-center gap-4 border-b border-border px-3">
            {(cols ?? [80, 140, 60]).map((w, j) => <div key={j} className="h-2.5 animate-pulse rounded bg-foreground/[0.06]" style={{ width: w }} />)}
          </div>
        ))}
      </div>
    );
  }
  const eyebrow = { empty: 'Nothing yet', error: 'Request failed', forbidden: '403 · forbidden', filtered: 'No matches' }[state];
  const fallback = { empty: 'Nothing here yet', error: 'Could not load this list', forbidden: 'You do not have access', filtered: 'No matches' }[state];
  return (
    <div className="p-6" data-testid={`list-state-${state}`}>
      <div className={cn('flex flex-col items-center rounded-[8px] border border-dashed px-6 py-8 text-center', state === 'error' ? 'border-destructive/40' : 'border-border')}>
        <H className={cn('mb-1.5', state === 'error' && 'text-destructive')}>{eyebrow}</H>
        <div className={cn('text-[13px] font-medium', state === 'error' ? 'text-destructive' : 'text-foreground')}>{title ?? fallback}</div>
        {body && <div className="mx-auto mt-1 max-w-sm text-[11.5px] text-muted-foreground">{body}</div>}
        {(onRetry || action) && (
          <div className="mt-3 flex justify-center gap-2">
            {onRetry && <Button size="sm" variant="outline" className={smallButton} onClick={onRetry}>Retry</Button>}
            {action}
          </div>
        )}
      </div>
    </div>
  );
}

/** Page header: title → meta row (breadcrumb lives in the top bar). */
export function PageHeader({ title, meta, actions, children, className }: { title: ReactNode; meta?: ReactNode; actions?: ReactNode; children?: ReactNode; className?: string }) {
  return (
    <div className={cn('shrink-0 border-b border-border px-5 pb-3 pt-4', className)}>
      <div className="flex flex-wrap items-end gap-x-4 gap-y-2">
        <div className="min-w-0">
          <h1 className={PAGE_TITLE}>{title}</h1>
          {meta && <div className="mt-1.5 flex flex-wrap gap-x-3 font-mono text-[11px] text-muted-foreground [&>*]:whitespace-nowrap">{meta}</div>}
        </div>
        <span className="flex-1" />
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </div>
  );
}

// ── Right sheet (mock DetailSheet / FormSheet) ──────────────────────────
export function DetailSheet({ open, onClose, eyebrow, title, meta, width = 560, footer, children, label }: {
  open: boolean; onClose: () => void; eyebrow?: ReactNode; title: ReactNode; meta?: ReactNode; width?: number; footer?: ReactNode; children: ReactNode; label?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-x-0 bottom-0 top-[42px] z-40 flex justify-end" data-testid={label ? `sheet-${label}` : undefined} role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : label}>
      <div className="absolute inset-0 bg-black/45" onClick={onClose} />
      <div className="relative flex h-full max-w-full flex-col border-l border-border-2 bg-card shadow-[-20px_0_60px_rgba(0,0,0,0.5)]" style={{ width }}>
        <div className="flex items-start gap-3 border-b border-border px-4 pb-3 pt-3.5">
          <div className="min-w-0 flex-1">
            {eyebrow && <H className="mb-1">{eyebrow}</H>}
            <div className="text-[15px] font-semibold tracking-[-0.01em] text-foreground">{title}</div>
            {meta && <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-muted-foreground">{meta}</div>}
          </div>
          <button type="button" onClick={onClose} aria-label="Close" title="Close (esc)" className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-foreground/5 hover:text-foreground">
            <svg viewBox="0 0 24 24" className="h-[14px] w-[14px]" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M6 6l12 12M18 6 6 18" /></svg>
          </button>
        </div>
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto px-4 py-3.5">{children}</div>
        {footer && <div className="flex items-center gap-2 border-t border-border px-4 py-3">{footer}</div>}
      </div>
    </div>
  );
}

/** Mock Field: label → control → error/hint. */
export function Field({ label, required, hint, error, children }: { label: ReactNode; required?: boolean | 'alt'; hint?: ReactNode; error?: ReactNode; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="flex items-center gap-1 text-[11.5px] text-fg-2">
        {label}
        {required === 'alt' ? null : required ? <span className="text-destructive">*</span> : <span className="text-[10.5px] text-fg-4">optional</span>}
      </span>
      {children}
      {error ? <span className="flex items-center gap-1 text-[11px] text-destructive">{error}</span> : hint ? <span className="text-[11px] text-muted-foreground">{hint}</span> : null}
    </label>
  );
}
export const inputCls = (err?: boolean) =>
  cn('h-8 w-full rounded-md border bg-transparent px-2.5 text-[12.5px] text-foreground placeholder:text-fg-4 focus:outline-none focus:ring-1 focus:ring-ring', err ? 'border-destructive/60' : 'border-border-2');

// ── Legend dot used by several headers ──────────────────────────────────
export function Swatch({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return <span aria-hidden className={cn('inline-block h-2 w-2 rounded-[1px]', className)} style={style} />;
}

// ── Flow-editor form primitives (NAN-4586) ──────────────────────────────

/** Inline sentence token: a small bordered pill that reads like a word. */
export const tokenCls = 'inline-flex h-6 max-w-full items-center align-middle gap-1 rounded-[3px] border border-border-2 bg-transparent px-1.5 text-[12px] text-foreground hover:border-fg-4 disabled:cursor-not-allowed disabled:opacity-60';

/** The "Advanced" switch at the right edge of an easy-mode control. */
export function AdvancedToggle({ on, onChange, disabled, label, title }: { on: boolean; onChange: (on: boolean) => void; disabled?: boolean; label: string; title?: string }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      aria-label={label}
      title={title}
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={cn(
        'inline-flex h-6 shrink-0 items-center rounded-[3px] border px-1.5 text-[11px] disabled:cursor-not-allowed disabled:opacity-60',
        on ? 'border-primary/40 bg-primary/10 text-primary' : 'border-border text-fg-2 hover:text-foreground',
      )}
    >
      Advanced
    </button>
  );
}

/** Compact search box at the top of a picker popover. */
export function SearchBox({ value, onChange, label, placeholder, onKeyDown, activeId, listId }: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  placeholder?: string;
  onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  /** id of the highlighted option (aria-activedescendant). */
  activeId?: string;
  listId?: string;
}) {
  return (
    <input
      autoFocus
      role={listId ? 'combobox' : undefined}
      aria-label={label}
      aria-controls={listId}
      aria-expanded={listId ? true : undefined}
      aria-activedescendant={activeId}
      aria-autocomplete={listId ? 'list' : undefined}
      autoComplete="off"
      spellCheck={false}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={onKeyDown}
      className={cn(inputCls(false), 'h-7 rounded-[3px] px-2 text-[12px]')}
    />
  );
}

/** One radio row in a ListBox. */
export function PickRow({ selected, onClick, children, label }: { selected: boolean; onClick: () => void; children: ReactNode; label: string }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      aria-label={label}
      onClick={onClick}
      className={cn('flex h-7 w-full items-center gap-2 border-b border-border px-2.5 text-left text-[12px] last:border-b-0 hover:bg-accent', selected && 'bg-primary/10')}
    >
      <span className={cn('h-2 w-2 shrink-0 rounded-full border', selected ? 'border-primary bg-primary' : 'border-fg-4')} />
      {children}
    </button>
  );
}

export type PickListState = 'loading' | 'error' | 'empty' | 'ok';
export const pickListState = (q: { isLoading: boolean; isError: boolean; data?: unknown[] }): PickListState =>
  q.isLoading ? 'loading' : q.isError ? 'error' : q.data?.length ? 'ok' : 'empty';

/** A short scrolling radio list with loading / error / empty states. */
export function ListBox({ label, children, state, fallback = 'Use sample values instead.' }: { label: string; children: ReactNode; state: PickListState; fallback?: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="max-h-[188px] overflow-auto rounded-md border border-border">
      {state === 'loading' && <div className="flex h-8 items-center gap-2 px-2.5 text-[11.5px] text-muted-foreground"><Spinner />Loading…</div>}
      {state === 'error' && <div className="px-2.5 py-2 text-[11.5px] text-muted-foreground">Not available. {fallback}</div>}
      {state === 'empty' && <div className="px-2.5 py-2 text-[11.5px] text-muted-foreground">Nothing recent. {fallback}</div>}
      {state === 'ok' && children}
    </div>
  );
}

/**
 * Keyboard model for a popup option list: arrows / Home / End move the
 * highlight, Enter picks it. Returns the active index, a keydown handler and
 * the option id for aria-activedescendant.
 */
export function useListNav(count: number, onPick: (i: number) => void, idPrefix: string) {
  const [active, setActive] = useState(0);
  const cur = count ? Math.min(active, count - 1) : -1;
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!count) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((cur + 1) % count); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((cur - 1 + count) % count); }
    else if (e.key === 'Home') { e.preventDefault(); setActive(0); }
    else if (e.key === 'End') { e.preventDefault(); setActive(count - 1); }
    else if (e.key === 'Enter' || (e.key === ' ' && (e.target as HTMLElement).tagName !== 'INPUT')) { e.preventDefault(); onPick(cur); }
  };
  const optionId = (i: number) => `${idPrefix}-opt-${i}`;
  return { active: cur, setActive, onKeyDown, optionId, activeId: cur >= 0 ? optionId(cur) : undefined };
}
