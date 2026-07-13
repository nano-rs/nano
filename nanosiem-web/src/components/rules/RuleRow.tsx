// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-482 — single rule row + its expanded body.
// Port of design-ref/shadcn/rules-row.jsx against the real DetectionRule model.

import { useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ChevronRight,
  Pencil,
  Copy,
  Clock,
  MoreVertical,
  Terminal,
  ListFilter,
  Power,
  CircleCheck,
  Trash2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useDetectionMatches } from '@/hooks/use-api';
import { useAuth } from '@/contexts/AuthContext';
import {
  SEV_META,
  formatLastMatch,
  highlightLogic,
  type RuleView,
  type SeverityKey,
} from './helpers';

interface ChkProps {
  checked: boolean;
  indeterminate?: boolean;
  onChange?: () => void;
  onClick?: (e: React.MouseEvent) => void;
  ariaLabel?: string;
}

export function Chk({ checked, indeterminate, onChange, onClick, ariaLabel }: ChkProps) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = !!indeterminate;
  }, [indeterminate]);
  return (
    <label className="inline-flex items-center justify-center cursor-pointer" onClick={onClick}>
      <input
        ref={ref}
        type="checkbox"
        checked={checked || false}
        onChange={onChange || (() => {})}
        aria-label={ariaLabel}
        className="sr-only peer"
      />
      <span
        className={cn(
          'w-[14px] h-[14px] rounded-[3px] border flex items-center justify-center transition-colors shrink-0',
          checked || indeterminate
            ? 'bg-primary border-primary'
            : 'border-muted-foreground/50 hover:border-foreground bg-card',
        )}
      >
        {indeterminate ? (
          <svg
            viewBox="0 0 14 14"
            className="w-[10px] h-[10px]"
            fill="none"
            stroke="var(--brand-ink)"
            strokeWidth="2.5"
            strokeLinecap="round"
          >
            <path d="M3 7h8" />
          </svg>
        ) : checked ? (
          <svg
            viewBox="0 0 14 14"
            className="w-[10px] h-[10px]"
            fill="none"
            stroke="var(--brand-ink)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M3 7.5l3 3 5.5-6" />
          </svg>
        ) : null}
      </span>
    </label>
  );
}

// 28-day heat strip — each cell = 1 day, rightmost = today.
const ACTIVITY_DATE_FORMATTER = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  month: 'short',
  day: 'numeric',
});

function ActivityStrip({ data }: { data: number[] }) {
  const max = Math.max(...data, 1);
  // Anchor "today" once per render so all bars share the same reference date.
  // Use setDate() arithmetic (not millisecond subtraction) so DST transitions
  // can't slip a bar onto the wrong calendar day.
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return (
    <TooltipProvider delayDuration={80}>
      <div className="flex items-center gap-[2px]">
        {data.map((v, i) => {
          const intensity = v === 0 ? 0 : 0.25 + (v / max) * 0.75;
          const isToday = i === data.length - 1;
          const daysAgo = data.length - 1 - i;
          const dayDate = new Date(today);
          dayDate.setDate(dayDate.getDate() - daysAgo);
          const dateLabel = ACTIVITY_DATE_FORMATTER.format(dayDate);
          return (
            <Tooltip key={i}>
              <TooltipTrigger asChild>
                <div
                  className="w-[5px] h-[14px] rounded-[1px]"
                  style={{
                    background:
                      v === 0
                        ? 'color-mix(in srgb, var(--foreground) 5%, transparent)'
                        : `color-mix(in srgb, var(--primary) ${intensity * 100}%, transparent)`,
                    outline: isToday && v > 0 ? '1px solid var(--primary)' : 'none',
                    outlineOffset: '0.5px',
                  }}
                />
              </TooltipTrigger>
              <TooltipContent className="text-[11px] font-mono leading-snug px-2 py-1">
                <div className="flex items-baseline gap-1.5">
                  <span className="text-foreground">{dateLabel}</span>
                  {isToday ? (
                    <span className="text-muted-foreground">today</span>
                  ) : (
                    <span className="text-muted-foreground">{daysAgo}d ago</span>
                  )}
                </div>
                <div className="text-muted-foreground">
                  {v.toLocaleString()} hit{v === 1 ? '' : 's'}
                </div>
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}

function SevTag({ severity }: { severity: SeverityKey }) {
  const meta = SEV_META[severity];
  if (!meta) return null;
  return (
    <div className="inline-flex items-center gap-1.5">
      <span className="w-[6px] h-[6px] rounded-full" style={{ background: meta.color }} />
      <span className="text-[11px] text-foreground capitalize">{meta.label}</span>
    </div>
  );
}

function StatusPill({ detectionStatus }: { detectionStatus: string }) {
  if (detectionStatus === 'live' || detectionStatus === 'alerting') {
    return (
      <div className="inline-flex items-center gap-1.5">
        <span className="w-[5px] h-[5px] rounded-full bg-[var(--success)]" />
        <span className="text-[11px] text-foreground capitalize">{detectionStatus}</span>
      </div>
    );
  }
  if (detectionStatus === 'staging') {
    return (
      <div className="inline-flex items-center gap-1.5">
        <span className="w-[5px] h-[5px] rounded-full bg-warning" />
        <span className="text-[11px] text-foreground">Staging</span>
      </div>
    );
  }
  if (detectionStatus === 'paused' || detectionStatus === 'disabled') {
    return (
      <div className="inline-flex items-center gap-1.5">
        <span className="w-[5px] h-[5px] rounded-full bg-muted-foreground/50" />
        <span className="text-[11px] text-muted-foreground capitalize">{detectionStatus}</span>
      </div>
    );
  }
  return <span className="text-[11px] text-muted-foreground capitalize">{detectionStatus}</span>;
}

function LogicLine({ n, t }: { n: number; t: string }) {
  const parts = highlightLogic(t);
  return (
    <div className="flex gap-3 leading-[1.55]">
      <span className="text-muted-foreground/60 select-none tabular-nums w-[18px] text-right shrink-0">
        {n}
      </span>
      <span>
        {parts.map((p, i) => {
          if (p.type === 'str') return <span key={i} style={{ color: 'var(--str)' }}>{p.v}</span>;
          if (p.type === 'kw') return <span key={i} className="text-primary">{p.v}</span>;
          if (p.type === 'cmd') return <span key={i} className="text-primary font-medium">{p.v}</span>;
          if (p.type === 'num') return <span key={i} className="text-warning">{p.v}</span>;
          if (p.type === 'op') return <span key={i} className="text-muted-foreground">{p.v}</span>;
          return <span key={i} className="text-foreground">{p.v}</span>;
        })}
      </span>
    </div>
  );
}

function RuleRowExpanded({ rule }: { rule: RuleView }) {
  const { data: matchesData } = useDetectionMatches(rule.id, { limit: 5 });
  const matches = matchesData?.matches || [];

  const logicLines = rule.query
    ? rule.query.split('\n').map((line, i) => ({ n: i + 1, t: line }))
    : [
        { n: 1, t: 'source_type="*" tag=auto' },
        { n: 2, t: '| stats count() as hits by entity' },
        { n: 3, t: '| where hits > threshold' },
      ];

  return (
    <div className="grid grid-cols-[1fr_380px] gap-3.5 px-12 pb-4 pt-1 @max-[1024px]:grid-cols-1">
      {/* Logic */}
      <div className="rounded-md border border-border overflow-hidden bg-[var(--panel)]">
        <div className="h-[28px] px-3 flex items-center gap-2 border-b border-border">
          <Terminal className="w-3 h-3 text-muted-foreground" strokeWidth={2} />
          <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
            Rule logic
          </span>
          <div className="flex-1" />
          <span className="font-mono text-[10px] text-muted-foreground/60">nPL</span>
        </div>
        <div className="p-3 font-mono text-[11.5px] overflow-x-auto max-h-[240px]">
          {logicLines.map((l) => (
            <LogicLine key={l.n} n={l.n} t={l.t} />
          ))}
        </div>
        <div className="px-3 pb-2.5 pt-1 flex items-center gap-1.5 border-t border-border">
          <Link
            // NAN-1791: a retro-hunt rule has no nPL query — edit it on its own
            // surface instead of the query editor.
            to={
              rule.kind === 'retro_hunt'
                ? `/rules/retro-hunt/${rule.id}`
                : `/rules/editor/${rule.id}`
            }
            className="h-6 px-2 rounded-md text-[11px] flex items-center gap-1.5 text-foreground hover:bg-foreground/5"
          >
            <Pencil className="w-3 h-3" strokeWidth={2} />
            Edit
          </Link>
          <button
            type="button"
            className="h-6 px-2 rounded-md text-[11px] flex items-center gap-1.5 text-foreground hover:bg-foreground/5"
            onClick={(e) => {
              e.stopPropagation();
              void navigator.clipboard?.writeText(rule.query || '');
            }}
            title="Copy query"
          >
            <Copy className="w-3 h-3" strokeWidth={2} />
            Copy
          </button>
          <div className="flex-1" />
          <span className="text-[10.5px] font-mono text-muted-foreground truncate">
            owner: {rule.author}
            {rule.tactic ? <> · {rule.tactic}</> : null}
            {rule.tech ? <> · <span className="text-foreground">{rule.tech}</span></> : null}
          </span>
        </div>
      </div>

      {/* Recent matches */}
      <div className="rounded-md border border-border overflow-hidden flex flex-col bg-[var(--panel)]">
        <div className="h-[28px] px-3 flex items-center gap-2 border-b border-border">
          <Clock className="w-3 h-3 text-muted-foreground" strokeWidth={2} />
          <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
            Recent matches
          </span>
          <div className="flex-1" />
          {matches.length > 0 && (
            <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
              {matches.length} shown · {rule.today.toLocaleString()} today
            </span>
          )}
        </div>
        {matches.length === 0 ? (
          <div className="p-6 flex flex-col items-center justify-center text-center gap-1.5">
            <Clock className="w-4 h-4 text-muted-foreground/60" strokeWidth={1.5} />
            <div className="text-[11.5px] text-foreground font-medium">No recent matches</div>
            <div className="text-[10.5px] text-muted-foreground">
              This rule may be tuned well — or quietly broken.
            </div>
          </div>
        ) : (
          <div className="flex flex-col">
            {matches.slice(0, 5).map((m, i) => (
              <Link
                key={i}
                to={`/rules/${rule.id}/matches`}
                className="px-3 py-2 border-b border-border/60 last:border-0 flex items-center gap-3 hover:bg-foreground/5 cursor-pointer group"
                onClick={(e) => e.stopPropagation()}
              >
                <span
                  className="w-[5px] h-[5px] rounded-full shrink-0"
                  style={{ background: SEV_META[(m.severity || 'low') as SeverityKey]?.color }}
                />
                <div className="font-mono text-[10.5px] text-foreground tabular-nums shrink-0">
                  {(m.detected_at || '').replace('T', ' ').slice(11, 19) || '—'}
                </div>
                <div className="text-[11.5px] text-foreground truncate flex-1 font-mono">
                  {m.severity || 'match'}
                </div>
                <div className="font-mono text-[10.5px] text-muted-foreground tabular-nums shrink-0">
                  {m.event_count} evt
                </div>
                <ChevronRight className="w-3 h-3 text-muted-foreground/60 group-hover:text-foreground shrink-0" />
              </Link>
            ))}
            {rule.today > 0 && (
              <Link
                to={`/rules/${rule.id}/matches`}
                className="h-7 px-3 text-[11px] text-primary hover:bg-foreground/5 text-left border-t border-border flex items-center"
                onClick={(e) => e.stopPropagation()}
              >
                See all {rule.today.toLocaleString()} matches →
              </Link>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

interface RuleRowProps {
  rule: RuleView;
  expanded: boolean;
  onToggle: () => void;
  selected: boolean;
  onSelect: () => void;
  onSetMode: (id: string, mode: 'staging' | 'live' | 'alerting' | 'paused') => void;
  onDelete: (id: string) => void;
}

export function RuleRow({ rule, expanded, onToggle, selected, onSelect, onSetMode, onDelete }: RuleRowProps) {
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const canEdit = hasPermission('detections:edit');
  const canPromote = hasPermission('detections:promote');
  const canDelete = hasPermission('detections:delete') || hasPermission('detections:edit');
  const sev = SEV_META[rule.severity];
  const isDisabled = rule.detectionStatus === 'paused';
  return (
    <>
      <tr
        className={cn(
          'group transition-colors border-b border-border relative',
          expanded ? 'bg-foreground/5' : 'hover:bg-foreground/5',
        )}
      >
        {/* Severity accent edge */}
        <td className="p-0 w-[3px]">
          <div
            className="h-8 w-[2px]"
            style={{ background: sev?.color, opacity: isDisabled ? 0.25 : 1 }}
          />
        </td>

        {/* Checkbox */}
        <td className="w-[28px] py-1.5 pl-1 pr-0">
          <Chk
            checked={selected}
            onChange={onSelect}
            onClick={(e) => e.stopPropagation()}
            ariaLabel={`Select ${rule.name}`}
          />
        </td>

        {/* Expand */}
        <td className="w-[22px] py-1.5 px-0">
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={expanded}
            aria-label={expanded ? 'Collapse rule details' : 'Expand rule details'}
            className={cn(
              'w-4 h-4 rounded flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5 transition-transform',
              expanded && 'rotate-90',
            )}
          >
            <ChevronRight className="w-3 h-3" strokeWidth={2} />
          </button>
        </td>

        {/* Today count — click opens matches page */}
        <td className="w-[70px] py-1.5 pr-2 font-mono text-[11.5px] tabular-nums text-right">
          {rule.today > 0 ? (
            <Link
              to={`/rules/${rule.id}/matches`}
              onClick={(e) => e.stopPropagation()}
              className="text-foreground font-medium hover:text-primary hover:underline underline-offset-2 cursor-pointer"
            >
              {rule.today.toLocaleString()}
            </Link>
          ) : (
            <span className="text-muted-foreground/60">—</span>
          )}
        </td>

        {/* Name + tactic */}
        <td className="py-1.5 pr-3 cursor-pointer" onClick={onToggle}>
          <div className="flex flex-col min-w-0">
            <div className="flex items-center gap-1.5 min-w-0">
              <Link
                to={`/rules/${rule.id}/matches`}
                onClick={(e) => e.stopPropagation()}
                className="font-mono text-[12px] text-foreground truncate hover:text-primary hover:underline underline-offset-2 w-fit max-w-full"
              >
                {rule.name}
              </Link>
              {/* NAN-1791: retro-hunt rules hunt newly-landed intel over history. */}
              {rule.kind === 'retro_hunt' && (
                <span
                  className="shrink-0 h-[15px] px-1 rounded border border-border text-[9.5px] font-mono uppercase tracking-wide text-muted-foreground leading-[13px]"
                  title="Auto retro-hunt: matches newly-published threat intel against historical logs"
                >
                  retro
                </span>
              )}
            </div>
            {(rule.tactic || rule.tech) && (
              <span className="font-mono text-[10px] text-muted-foreground truncate">
                {rule.tactic || '—'}
                {rule.tech ? ` · ${rule.tech}` : ''}
                <span className="hidden @max-[960px]:inline text-muted-foreground/60">
                  {' '}· {rule.mode}
                </span>
              </span>
            )}
          </div>
        </td>

        {/* Activity strip */}
        <td className="w-[180px] py-1.5 pr-3 @max-[820px]:hidden">
          <ActivityStrip data={rule.activity} />
        </td>

        {/* Last match */}
        <td className="w-[90px] py-1.5 pr-3 font-mono text-[11px] text-foreground tabular-nums @max-[1100px]:hidden">
          {formatLastMatch(rule.lastMatch)}
        </td>

        {/* Severity */}
        <td className="w-[92px] py-1.5 pr-3">
          <SevTag severity={rule.severity} />
        </td>

        {/* Mode */}
        <td className="w-[92px] py-1.5 pr-3 @max-[960px]:hidden">
          <span className="text-[11px] text-foreground capitalize">{rule.mode}</span>
        </td>

        {/* Status */}
        <td className="w-[82px] py-1.5 pr-3">
          <StatusPill detectionStatus={rule.detectionStatus} />
        </td>

        {/* Row actions */}
        <td className="w-[36px] py-1.5 pr-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label="Rule actions"
                className="w-6 h-6 rounded hover:bg-foreground/5 text-muted-foreground hover:text-foreground flex items-center justify-center"
                onClick={(e) => e.stopPropagation()}
              >
                <MoreVertical className="w-3.5 h-3.5" strokeWidth={2} />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-[180px]" onClick={(e) => e.stopPropagation()}>
              <DropdownMenuItem className="text-[11.5px] py-1 gap-2" onSelect={() => navigate(`/rules/${rule.id}/matches`)}>
                <ListFilter className="w-3.5 h-3.5" strokeWidth={2} />
                View matches
              </DropdownMenuItem>
              {canEdit && (
                <DropdownMenuItem className="text-[11.5px] py-1 gap-2" onSelect={() => navigate(`/rules/editor/${rule.id}`)}>
                  <Pencil className="w-3.5 h-3.5" strokeWidth={2} />
                  Edit rule
                </DropdownMenuItem>
              )}
              {canEdit && (
                <DropdownMenuItem className="text-[11.5px] py-1 gap-2" onSelect={() => navigate(`/rules/editor/new?duplicate=${rule.id}`)}>
                  <Copy className="w-3.5 h-3.5" strokeWidth={2} />
                  Duplicate
                </DropdownMenuItem>
              )}
              {canPromote && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuSub>
                    <DropdownMenuSubTrigger className="text-[11.5px] py-1 gap-2">
                      <Power className="w-3.5 h-3.5" strokeWidth={2} />
                      Set mode
                    </DropdownMenuSubTrigger>
                    <DropdownMenuSubContent className="w-36">
                      <ModeItem label="Staging" target="staging" current={rule.detectionStatus} onSelect={() => onSetMode(rule.id, 'staging')} />
                      <ModeItem label="Live" target="live" current={rule.detectionStatus} onSelect={() => onSetMode(rule.id, 'live')} />
                      <ModeItem label="Alerting" target="alerting" current={rule.detectionStatus} onSelect={() => onSetMode(rule.id, 'alerting')} />
                      <DropdownMenuSeparator />
                      <ModeItem label="Paused" target="paused" current={rule.detectionStatus} onSelect={() => onSetMode(rule.id, 'paused')} />
                    </DropdownMenuSubContent>
                  </DropdownMenuSub>
                </>
              )}
              {canDelete && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    className="text-[11.5px] py-1 gap-2 text-destructive focus:text-destructive focus:bg-destructive/10"
                    onSelect={() => onDelete(rule.id)}
                  >
                    <Trash2 className="w-3.5 h-3.5" strokeWidth={2} />
                    Delete
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-border bg-[var(--card-2)]">
          <td colSpan={11} className="p-0">
            <RuleRowExpanded rule={rule} />
          </td>
        </tr>
      )}
    </>
  );
}

function ModeItem({
  label,
  target,
  current,
  onSelect,
}: {
  label: string;
  target: string;
  current: string;
  onSelect: () => void;
}) {
  const active = current === target;
  return (
    <DropdownMenuItem className="text-[11.5px] py-1" onSelect={onSelect} disabled={active}>
      {label}
      {active && <CircleCheck className="w-3 h-3 ml-auto" strokeWidth={2} />}
    </DropdownMenuItem>
  );
}
