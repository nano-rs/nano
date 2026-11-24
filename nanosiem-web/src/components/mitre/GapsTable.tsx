// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5850: the Gaps tab. The same filtered technique set as the matrix, as
// a dense sortable work queue (design 4.5). Default order puts huntable
// techniques with findings first: a technique with findings and no rule is
// the best rule-idea input.

import { EnterpriseTerm } from '@/enterprise/components/glossary/EnterpriseTerm';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowDown, ArrowUp } from 'lucide-react';

import { cn } from '@/lib/utils';
import { type TechniqueCoverage, readinessOf } from './types';
import {
  type TechniqueLayers,
  classLabel,
  compareGapRows,
  telemetryLabel,
} from './layers';
import { ClassSwatch } from './Legend';
import { type CoverageActionPerms, draftRuleHref } from './TechniqueDetailSheet';

export interface GapRow {
  technique: TechniqueCoverage;
  facts: TechniqueLayers;
}

type SortKey = 'default' | 'technique' | 'tactic' | 'class' | 'live' | 'hunts' | 'last' | 'findings' | 'telemetry';

function missingSources(t: TechniqueCoverage, facts: TechniqueLayers): string {
  if (facts.t === 'active') return '';
  const inactive = (t.data_sources ?? []).filter((d) => readinessOf(d) !== 'active' && d.mapping_known !== false);
  const types = [...new Set(inactive.flatMap((d) => d.source_types ?? []))];
  if (types.length) return types.join(', ');
  return inactive.map((d) => d.name).join(', ');
}

function lastHunted(facts: TechniqueLayers, now: number): string {
  const at = facts.layer?.last_hunted_at;
  if (!at) return 'never';
  const ms = now - Date.parse(at);
  if (!Number.isFinite(ms)) return 'never';
  const hours = ms / 3_600_000;
  if (hours < 1) return `${Math.max(1, Math.round(ms / 60_000))}m`;
  if (hours < 48) return `${Math.round(hours)}h`;
  return `${Math.round(hours / 24)}d`;
}

interface GapsTableProps {
  rows: GapRow[];
  huntLayer: boolean;
  days: number;
  selectedId: string | null;
  /** Destination permissions; an action the viewer cannot take is not offered. */
  actionPerms: CoverageActionPerms;
  regressed?: ReadonlySet<string>;
  onOpenTechnique: (tacticId: string, techniqueId: string) => void;
}

const NO_REGRESSIONS: ReadonlySet<string> = new Set();

export function GapsTable({ rows, huntLayer, days, selectedId, actionPerms, regressed = NO_REGRESSIONS, onOpenTechnique }: GapsTableProps) {
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: 'default', desc: false });
  const now = Date.now();

  const sorted = useMemo(() => {
    const list = [...rows];
    const dir = sort.desc ? -1 : 1;
    const by = (fn: (r: GapRow) => number | string) => (a: GapRow, b: GapRow) => {
      const x = fn(a);
      const y = fn(b);
      return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * dir
        || a.technique.technique_id.localeCompare(b.technique.technique_id);
    };
    switch (sort.key) {
      case 'technique': return list.sort(by((r) => r.technique.technique_id));
      case 'tactic': return list.sort(by((r) => r.technique.tactic_ids[0] ?? ''));
      case 'class': return list.sort(by((r) => r.facts.cls));
      case 'live': return list.sort(by((r) => r.facts.live));
      case 'hunts': return list.sort(by((r) => r.facts.layer?.hunts_total ?? 0));
      case 'last': return list.sort(by((r) => (r.facts.layer?.last_hunted_at ? Date.parse(r.facts.layer.last_hunted_at) : 0)));
      case 'findings': return list.sort(by((r) => r.facts.findings));
      case 'telemetry': return list.sort(by((r) => r.facts.t));
      default: return list.sort(compareGapRows);
    }
  }, [rows, sort]);

  const header = (key: SortKey, label: string, className?: string) => (
    <th
      className={cn(
        'sticky top-0 z-[1] bg-background h-7 px-2 text-left font-medium text-[10.5px] uppercase tracking-wider text-muted-foreground border-b border-border whitespace-nowrap',
        className,
      )}
      aria-sort={sort.key === key ? (sort.desc ? 'descending' : 'ascending') : undefined}
    >
      <button
        type="button"
        className="inline-flex items-center gap-1 uppercase tracking-wider hover:text-foreground"
        onClick={() => setSort((s) => (s.key === key ? { key, desc: !s.desc } : { key, desc: key === 'findings' || key === 'live' || key === 'hunts' }))}
      >
        {label}
        {sort.key === key && (sort.desc ? <ArrowDown className="h-3 w-3" strokeWidth={1.5} /> : <ArrowUp className="h-3 w-3" strokeWidth={1.5} />)}
      </button>
    </th>
  );

  if (rows.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center text-[12px] text-muted-foreground" data-testid="coverage-gaps-empty">
        No gaps match these filters.
      </div>
    );
  }

  const td = 'h-[26px] px-2 border-b border-border whitespace-nowrap';
  return (
    <div className="flex-1 min-h-0 overflow-auto px-4 pb-4">
      <table className="w-full border-collapse text-[11.5px]" data-testid="coverage-gaps-table">
        <thead>
          <tr>
            {header('technique', 'Technique')}
            <th className="sticky top-0 z-[1] bg-background h-7 px-2 text-left font-medium text-[10.5px] uppercase tracking-wider text-muted-foreground border-b border-border">Name</th>
            {header('tactic', 'Tactic', 'hidden md:table-cell')}
            {header('class', 'Class')}
            {header('live', 'Live rules')}
            {huntLayer && header('hunts', 'Hunts', 'hidden lg:table-cell')}
            {huntLayer && header('last', 'Last hunted', 'hidden lg:table-cell')}
            {huntLayer && header('findings', `Findings ${days}d`)}
            {header('telemetry', 'Telemetry', 'hidden sm:table-cell')}
            <th className="sticky top-0 z-[1] bg-background h-7 px-2 text-left font-medium text-[10.5px] uppercase tracking-wider text-muted-foreground border-b border-border hidden 2xl:table-cell">Missing sources</th>
            <th className="sticky top-0 z-[1] bg-background h-7 px-2 border-b border-border"><span className="sr-only">Action</span></th>
          </tr>
        </thead>
        <tbody>
          {sorted.map(({ technique: t, facts }) => {
            const id = t.technique_id;
            const ready = huntLayer && (facts.layer?.rule_ideas.ready ?? 0) > 0;
            const open = () => onOpenTechnique(t.tactic_ids[0] ?? '', id);
            return (
              <tr
                key={id}
                data-testid={`coverage-gap-row-${id}`}
                data-class={facts.cls}
                className={cn('cursor-pointer hover:bg-card', selectedId === id && 'bg-card')}
                onClick={open}
              >
                {/* The row opens the panel on click; this button is the keyboard path. */}
                <td className={td}>
                  <button
                    type="button"
                    className="font-mono text-[10.5px] text-foreground hover:underline focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring"
                    aria-label={`Open ${id} ${t.technique_name}`}
                    data-testid={`coverage-gap-open-${id}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      open();
                    }}
                  >
                    {id}
                  </button>
                </td>
                <td className={td} title={t.technique_name}>
                  <span className="block max-w-[200px] truncate">{t.technique_name}</span>
                </td>
                <td className={cn(td, 'font-mono text-[10.5px] text-muted-foreground hidden md:table-cell')}>{t.tactic_ids.join(' ')}</td>
                <td className={td}>
                  <span className="inline-flex items-center gap-1.5 font-mono text-[10.5px]">
                    <ClassSwatch cls={facts.cls} className="w-2 h-2" />
                    {facts.noTelemetry ? 'rule, no telemetry' : classLabel(facts.cls, huntLayer).toLowerCase()}
                  </span>
                </td>
                <td className={cn(td, 'font-mono text-[10.5px] tabular-nums')}>{facts.live}</td>
                {huntLayer && <td className={cn(td, 'font-mono text-[10.5px] tabular-nums hidden lg:table-cell')}>{facts.layer?.hunts_total ?? 0}</td>}
                {huntLayer && <td className={cn(td, 'font-mono text-[10.5px] text-muted-foreground hidden lg:table-cell')}>{lastHunted(facts, now)}</td>}
                {huntLayer && <td className={cn(td, 'font-mono text-[10.5px] tabular-nums')}>{facts.findings}</td>}
                <td className={cn(td, 'font-mono text-[10.5px] text-muted-foreground hidden sm:table-cell')}>
                  {telemetryLabel(facts.t)}
                  {regressed.has(id) ? <span className="ml-1 text-rose-500"><EnterpriseTerm id="regressed">regressed</EnterpriseTerm></span> : null}
                </td>
                <td className={cn(td, 'font-mono text-[10.5px] text-muted-foreground hidden 2xl:table-cell')} title={missingSources(t, facts)}>
                  <span className="block max-w-[160px] truncate">{missingSources(t, facts)}</span>
                </td>
                <td className={cn(td, 'text-right')} onClick={(e) => e.stopPropagation()}>
                  {ready ? (
                    <Link
                      to={`/rules/ideas?technique=${encodeURIComponent(id)}`}
                      className="text-[11px] text-primary hover:underline"
                      data-testid={`coverage-gap-action-review_idea-${id}`}
                    >
                      Review <EnterpriseTerm id="rule-idea" nested>rule idea</EnterpriseTerm>
                    </Link>
                  ) : facts.noTelemetry ? (
                    actionPerms.viewSources
                      ? <Link to="/ingestion/log-sources" className="text-[11px] text-primary hover:underline">Log sources</Link>
                      : null
                  ) : facts.t === 'active' || facts.cls === 'hunted' ? (
                    actionPerms.createRule ? (
                      <Link to={draftRuleHref(id, t.tactic_ids)} className="text-[11px] text-primary hover:underline">
                        Draft rule
                      </Link>
                    ) : null
                  ) : actionPerms.onboard ? (
                    <Link to="/ingestion/log-sources/new" className="text-[11px] text-primary hover:underline">Onboard</Link>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
