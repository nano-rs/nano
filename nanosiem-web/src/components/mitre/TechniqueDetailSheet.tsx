// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-516 — per-technique drawer overlaying the page body.
// Port of design-ref/shadcn/mitre-drawer.jsx. NOT the shadcn Sheet — the
// mockup uses an absolute-positioned 480px panel with a scrim covering the
// page body (rail + topbar stay visible).

import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronRight, Database, ExternalLink, Plus, X } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import {
  type CoveringRule,
  type RequiredDataSource,
  type StatusKey,
  type TacticCoverage,
  type TechniqueCoverage,
  readinessLabel,
  readinessOf,
  statusOf,
  tierFor,
} from './types';

function readinessPresentation(source: RequiredDataSource) {
  const readiness = readinessOf(source);
  const color = readiness === 'active'
    ? 'text-emerald-500'
    : readiness === 'stale'
      ? 'text-amber-500'
      : 'text-muted-foreground';
  const dot = readiness === 'active'
    ? 'bg-emerald-500'
    : readiness === 'stale'
      ? 'bg-amber-500'
      : 'bg-muted-foreground';
  const title = source.last_seen_at
    ? `Last event ${new Date(source.last_seen_at).toLocaleString()}`
    : readiness === 'stale'
      ? 'Configured, with no events observed in the retained telemetry window'
      : source.mapping_known === false
        ? 'No nano source mapping is available for this ATT&CK data source'
        : source.configured === false
        ? 'No enabled and deployed source is mapped to this data source'
        : readiness === 'unknown'
          ? 'Ingestion health is unavailable'
          : 'Active ingestion';

  return { color, dot, label: readinessLabel(source), title };
}

const TIER_BANNER: Record<ReturnType<typeof tierFor>, { label: string; cls: string; dot: string }> = {
  full:      { label: 'Full coverage',    cls: 'bg-emerald-500/12 border-emerald-500/40 text-emerald-500', dot: 'bg-emerald-500' },
  partial:   { label: 'Partial coverage', cls: 'bg-amber-500/12 border-amber-500/40 text-amber-500',       dot: 'bg-amber-500' },
  'hot-gap': { label: 'Hot gap',          cls: 'bg-rose-500/12 border-rose-500/40 text-rose-500',          dot: 'bg-rose-500' },
  gap:       { label: 'No coverage',      cls: 'bg-card border-border text-muted-foreground',              dot: 'bg-muted-foreground' },
};

const STATUS_PILL: Record<StatusKey, { label: string; cls: string }> = {
  live:     { label: 'LIVE',     cls: 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30' },
  review:   { label: 'REVIEW',   cls: 'bg-amber-500/15 text-amber-500 border-amber-500/30' },
  disabled: { label: 'DISABLED', cls: 'bg-foreground/8 text-muted-foreground border-border' },
};

function SeverityDot({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  const cls =
    s === 'critical' ? 'bg-rose-500'
    : s === 'high'    ? 'bg-amber-500'
    : s === 'medium'  ? 'bg-primary'
    : 'bg-muted-foreground';
  return <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', cls)} title={severity} />;
}

function StatusPill({ status }: { status: StatusKey }) {
  const cfg = STATUS_PILL[status];
  return (
    <span className={cn('inline-flex items-center gap-1 font-mono text-[9px] tracking-wider px-1 h-[14px] rounded border', cfg.cls)}>
      {cfg.label}
    </span>
  );
}

function RuleRow({ rule, onClick }: { rule: CoveringRule; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group flex items-center gap-2 px-2 py-1.5 rounded-md border border-border bg-card hover:bg-secondary text-left w-full transition-colors"
    >
      <SeverityDot severity={rule.severity} />
      <div className="flex-1 min-w-0">
        <div className="font-mono text-[11px] text-foreground truncate">{rule.name}</div>
        <div className="text-[10px] text-muted-foreground font-mono">
          {rule.source ? `${rule.source} · ` : ''}{rule.severity}
        </div>
      </div>
      <StatusPill status={statusOf(rule.mode)} />
      <ChevronRight className="w-[11px] h-[11px] text-muted-foreground group-hover:text-foreground shrink-0" />
    </button>
  );
}

interface TechniqueDetailSheetProps {
  technique: TechniqueCoverage | null;
  parentTechnique?: TechniqueCoverage | null;
  /** Sub-techniques of the parent — rendered as a list section. */
  subs?: TechniqueCoverage[];
  tactic?: TacticCoverage | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function TechniqueDetailSheet({
  technique,
  parentTechnique,
  subs = [],
  tactic,
  open,
  onOpenChange,
}: TechniqueDetailSheetProps) {
  const navigate = useNavigate();

  // Esc to close.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onOpenChange(false);
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onOpenChange]);

  if (!open || !technique) return null;

  const isSub = technique.is_subtechnique;
  const parentContext = isSub ? parentTechnique : null;

  // Every ATT&CK technique ID is its own coverage unit. The selected child's
  // rules and telemetry must never be inherited from its parent.
  const tier = tierFor(technique);
  const banner = TIER_BANNER[tier];
  const live = (technique.rules || []).filter((r) => statusOf(r.mode) === 'live');
  const review = (technique.rules || []).filter((r) => statusOf(r.mode) === 'review');
  const disabled = (technique.rules || []).filter((r) => statusOf(r.mode) === 'disabled');
  const orderedRules = [...live, ...review, ...disabled];

  const mitreId = technique.technique_id;
  const mitreUrl = `https://attack.mitre.org/techniques/${mitreId.replace('.', '/')}/`;

  const close = () => onOpenChange(false);

  return (
    <div className="fixed inset-0 z-40">
      <div
        className="absolute inset-0 bg-black/50"
        onClick={close}
        aria-hidden="true"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`Technique ${mitreId}`}
        className="absolute right-0 top-0 bottom-0 w-[480px] border-l border-border bg-background flex flex-col shadow-[0_24px_60px_rgba(0,0,0,0.5)]"
      >
        {/* Header */}
        <div className="shrink-0 px-4 pt-3 pb-3 border-b border-border">
          <div className="flex items-start gap-2">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
                {tactic && <span>{tactic.tactic_name}</span>}
                {tactic && <ChevronRight className="w-[9px] h-[9px]" />}
                {parentContext && (
                  <>
                    <span className="text-foreground/80">{parentContext.technique_id}</span>
                    <ChevronRight className="w-[9px] h-[9px]" />
                  </>
                )}
                <span>{technique.technique_id}</span>
              </div>
              <div className="text-[15px] font-semibold tracking-[-0.01em] text-foreground mt-0.5 break-words">
                {technique.technique_name}
              </div>
            </div>
            <Button variant="ghost" size="icon" className="h-[24px] w-[24px] shrink-0" onClick={close}>
              <X className="w-[13px] h-[13px]" />
            </Button>
          </div>

          <div className={cn('mt-3 flex items-center gap-2 px-2.5 py-1.5 rounded-md border', banner.cls)}>
            <span className={cn('w-1.5 h-1.5 rounded-full', banner.dot)} />
            <span className="text-[11px] font-semibold">{banner.label}</span>
            <span className="opacity-70 text-[10.5px] font-mono">·</span>
            <span className="text-[10.5px] font-mono">
              {live.length} live · {review.length} review · {disabled.length} disabled
            </span>
            {tier === 'hot-gap' && (
              <span className="ml-auto text-[10px] font-mono uppercase tracking-wider opacity-80">
                active telemetry
              </span>
            )}
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-auto">
          {/* Rules */}
          <section className="px-4 py-3 border-b border-border">
            <div className="flex items-center justify-between mb-2">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Rules mapped to {technique.technique_id}
              </div>
              <button
                type="button"
                onClick={() => navigate('/rules/new')}
                className="text-[10.5px] font-mono text-primary hover:underline flex items-center gap-1"
              >
                <Plus className="w-[10px] h-[10px]" /> New rule
              </button>
            </div>
            {orderedRules.length > 0 ? (
              <div className="flex flex-col gap-1.5">
                {orderedRules.map((rule) => (
                  <RuleRow
                    key={rule.id}
                    rule={rule}
                    onClick={() => navigate(`/rules/editor/${rule.id}`)}
                  />
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-muted-foreground italic py-2">
                No rules mapped. {tier === 'hot-gap'
                  ? 'Active telemetry would support detection here. Consider writing one.'
                  : 'Configure or restore active telemetry below to unlock coverage.'}
              </div>
            )}
          </section>

          {/* Parent is context only; its rules/readiness never roll down. */}
          {parentContext && (
            <section className="px-4 py-3 border-b border-border">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                Parent technique
              </div>
              <div className="flex items-center gap-2 px-2 py-1.5 rounded-md border border-border bg-card">
                <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                  {parentContext.technique_id}
                </span>
                <span className="text-[11.5px] text-foreground flex-1">
                  {parentContext.technique_name}
                </span>
                <span className="font-mono text-[9.5px] text-muted-foreground">
                  {parentContext.rule_count} parent-mapped
                </span>
              </div>
            </section>
          )}

          {/* Sub-techniques */}
          {subs.length > 0 && (
            <section className="px-4 py-3 border-b border-border">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                Sub-techniques ({subs.length})
              </div>
              <div className="flex flex-col gap-1">
                {subs.map((s) => {
                  const active = isSub && technique.technique_id === s.technique_id;
                  return (
                    <div
                      key={s.technique_id}
                      className={cn(
                        'flex items-center gap-2 px-2 py-1 rounded-md',
                        active ? 'bg-primary/10 text-primary' : 'text-foreground/80',
                      )}
                    >
                      <span className="font-mono text-[10px] text-muted-foreground shrink-0 w-[70px]">
                        {s.technique_id}
                      </span>
                      <span className="text-[11.5px] flex-1">{s.technique_name}</span>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* Data sources */}
          <section className="px-4 py-3 border-b border-border">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Required data sources</div>
            {(technique.data_sources ?? []).length === 0 ? (
              <div className="flex items-start gap-2 text-[11px] text-muted-foreground italic py-2">
                <Database className="w-[12px] h-[12px] mt-px shrink-0" />
                <span>
                  No data sources declared. MITRE may not have documented required sources, or the
                  ATT&amp;CK sync hasn&apos;t populated them yet.
                </span>
              </div>
            ) : (
              <div className="flex flex-col gap-1">
                {(technique.data_sources ?? []).map((d) => {
                  const presentation = readinessPresentation(d);
                  return (
                    <div
                      key={d.id}
                      title={presentation.title}
                      className="flex items-center gap-2 px-2 py-1 rounded-md border border-border bg-card"
                    >
                      <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', presentation.dot)} />
                      <span className="text-[11.5px] text-foreground flex-1">{d.name}</span>
                      <span className={cn(
                        'font-mono text-[9.5px] uppercase tracking-wider shrink-0 whitespace-nowrap',
                        presentation.color,
                      )}>
                        {presentation.label}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* Notes / external link */}
          <section className="px-4 py-3">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Notes</div>
            <div className="text-[11.5px] text-foreground/80 leading-relaxed text-muted-foreground italic">
              No analyst notes yet. Add context about detection strategy, noisy patterns, or known FPs.
            </div>
            <div className="mt-3">
              <a
                href={mitreUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10.5px] font-mono text-primary hover:underline inline-flex items-center gap-1"
              >
                Open on attack.mitre.org <ExternalLink className="w-[10px] h-[10px]" />
              </a>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="shrink-0 border-t border-border px-4 py-2.5 bg-card flex items-center gap-2">
          <Button variant="outline" size="sm" className="h-[28px]" onClick={close}>
            Close
          </Button>
          <div className="flex-1" />
          <Button size="sm" className="h-[28px]" onClick={() => navigate('/rules/new')}>
            <Plus className="w-[11px] h-[11px]" />
            Add rule
          </Button>
        </div>
      </div>
    </div>
  );
}
