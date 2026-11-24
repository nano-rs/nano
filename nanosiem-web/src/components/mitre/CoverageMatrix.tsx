// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-516 / NAN-5850 — Navigator-style coverage matrix.
// One column per tactic; one dense row per technique; sub-techniques expand
// inline under their parent. Each cell carries three layers (detection, hunt,
// telemetry) as a D/H/T strip; the fill follows the active view (design 4.2).
// The coverage unit stays the technique ID: a parent never inherits a child's
// state, it only shows a rollup hint.

import { memo, useCallback, useMemo, useState } from 'react';
import { ChevronRight } from 'lucide-react';

import { cn } from '@/lib/utils';
import type { Density, TacticCoverage, TechniqueCoverage } from './types';
import {
  type CoverageView,
  type TechniqueLayers,
  COVERAGE_CLASSES,
  COVERAGE_COLOR,
  cellFill,
  countClasses,
  telemetryLabel,
  viewDims,
} from './layers';
import { DetectionTick, HuntTick, TelemetryDot } from './Legend';

// MITRE Enterprise tactic order (kill chain). ATT&CK v19 adds TA0112 Defense
// Impairment next to TA0005 Stealth. Unknown tactics are appended.
export const TACTIC_ORDER = [
  'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0112',
  'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010', 'TA0040',
];

export function orderTactics(tactics: readonly TacticCoverage[]): TacticCoverage[] {
  const rank = (id: string) => {
    const i = TACTIC_ORDER.indexOf(id);
    return i === -1 ? TACTIC_ORDER.length : i;
  };
  return [...tactics].sort((a, b) => rank(a.tactic_id) - rank(b.tactic_id) || a.tactic_id.localeCompare(b.tactic_id));
}

/** D ticks (one per live rule, max 3; an outline for staging-only), H tick, T dot. */
export function LayerStrip({ facts, huntLayer }: { facts: TechniqueLayers; huntLayer: boolean }) {
  const ticks = Math.min(facts.live, 3);
  return (
    <span className="inline-flex items-center gap-[3px] shrink-0" aria-hidden="true">
      {Array.from({ length: ticks }, (_, i) => <DetectionTick key={i} />)}
      {ticks === 0 && facts.staging > 0 && <DetectionTick staging />}
      {huntLayer && facts.h === 'hunted' && <HuntTick />}
      {huntLayer && facts.h === 'scheduled' && <HuntTick scheduled />}
      <span className="ml-0.5 inline-flex"><TelemetryDot state={facts.t} /></span>
    </span>
  );
}

function cellTitle(t: TechniqueCoverage, f: TechniqueLayers, huntLayer: boolean, days: number): string {
  const lines = [
    `${t.technique_id} ${t.technique_name}`,
    `${f.live} live rule${f.live === 1 ? '' : 's'}${huntLayer ? ` · hunt: ${f.h}` : ''} · telemetry: ${telemetryLabel(f.t)}`,
  ];
  if (huntLayer) lines.push(`findings ${days}d: ${f.findings}`);
  if (f.noTelemetry) lines.push('Rule, no telemetry: the rule cannot fire');
  return lines.join('\n');
}

/** 1410 -> 1.4k, so the findings / sweeps hint never squeezes the name. */
function compact(n: number): string {
  if (n >= 10_000) return `${Math.round(n / 1000)}k`;
  if (n >= 1000) return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k`;
  return String(n);
}

const ROW_HEIGHT: Record<Density, string> = {
  compact: 'h-[22px]',
  default: 'h-[26px]',
  roomy: 'h-[32px]',
};

interface CellProps {
  tacticId: string;
  technique: TechniqueCoverage;
  facts: TechniqueLayers;
  view: CoverageView;
  dimmed: boolean;
  huntLayer: boolean;
  days: number;
  density: Density;
  showIds: boolean;
  selected: boolean;
  /** Recon saw this technique go from covered to blind since the last run. */
  regressed: boolean;
  sub?: boolean;
  /** Parent rows only: number of subs and the toggle key. */
  subCount?: number;
  subRollup?: string | null;
  expanded?: boolean;
  toggleKey?: string;
  onToggleExpand?: (key: string) => void;
  /** Single-tactic or roomy layout: room for the sweeps count. */
  wide?: boolean;
  onOpen: (tacticId: string, techniqueId: string) => void;
}

// One row: a wrapper carrying the fill, with two SIBLING buttons (the
// sub-technique chevron and the row itself), never a control nested inside a
// button. Memoized: only rows whose props change re-render on a keystroke or
// a selection.
const Cell = memo(function Cell({
  tacticId,
  technique,
  facts,
  view,
  dimmed,
  huntLayer,
  days,
  density,
  showIds,
  selected,
  regressed,
  sub = false,
  subCount = 0,
  subRollup,
  expanded = false,
  toggleKey,
  onToggleExpand,
  wide = false,
  onOpen,
}: CellProps) {
  const fill = cellFill(view, facts);
  const unmappedEdge = facts.cls === 'unmapped' && (view === 'both' || view === 'gaps');
  const sweeps = facts.layer?.sweeps_window ?? 0;
  const title = [
    cellTitle(technique, facts, huntLayer, days) + (huntLayer ? ` · sweeps ${sweeps}` : ''),
    regressed ? 'Regressed to blind since the last recon' : null,
    subRollup ?? null,
  ].filter(Boolean).join('\n');
  return (
    <div
      className={cn(
        'group relative flex w-full items-center border-b border-border last:border-b-0',
        ROW_HEIGHT[density],
        'hover:outline hover:outline-1 hover:-outline-offset-1 hover:outline-muted-foreground/60 hover:z-[1]',
        selected && 'outline outline-1 -outline-offset-1 outline-foreground z-[2]',
        (dimmed || viewDims(view, facts)) && 'opacity-25',
      )}
      style={{
        ...(fill.color
          ? { background: `color-mix(in srgb, ${fill.color} ${Math.round(fill.strength * 22)}%, transparent)` }
          : {}),
        // Unmapped: dashed left edge, no fill.
        ...(unmappedEdge ? { borderLeft: '1px dashed rgba(107, 114, 128, 0.6)' } : {}),
      }}
    >
      {fill.color && (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute left-0 top-0 bottom-0 w-[3px]"
          style={{ background: fill.color, opacity: fill.strength }}
        />
      )}
      {(facts.noTelemetry || regressed) && (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute left-0 right-0 top-0 h-px"
          style={{ background: COVERAGE_COLOR.warn }}
        />
      )}
      {subCount > 0 && toggleKey && (
        <button
          type="button"
          aria-expanded={expanded}
          aria-label={expanded ? `Collapse sub-techniques of ${technique.technique_id}` : `Expand ${subCount} sub-techniques of ${technique.technique_id}`}
          onClick={() => onToggleExpand?.(toggleKey)}
          className="ml-1 w-3.5 h-full flex items-center justify-center shrink-0 text-muted-foreground hover:text-foreground"
        >
          <ChevronRight className={cn('w-[9px] h-[9px] transition-transform', expanded && 'rotate-90')} strokeWidth={1.5} />
        </button>
      )}
      <button
        type="button"
        data-testid={`coverage-cell-${technique.technique_id}`}
        data-class={facts.cls}
        data-d={facts.d}
        data-h={facts.h}
        data-t={facts.t}
        data-warn={facts.noTelemetry ? 'rule_no_telemetry' : undefined}
        data-regressed={regressed ? 'true' : undefined}
        aria-pressed={selected}
        title={title}
        onClick={() => onOpen(tacticId, technique.technique_id)}
        className={cn(
          'flex h-full min-w-0 flex-1 items-center gap-1.5 text-left pr-1.5 focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring',
          subCount > 0 && toggleKey ? 'pl-0.5' : sub ? 'pl-[18px]' : 'pl-2',
        )}
      >
        {showIds && (
          <span className="font-mono text-[10.5px] text-foreground/70 shrink-0">{technique.technique_id}</span>
        )}
        <span className="text-[11px] truncate flex-1 min-w-0">{technique.technique_name}</span>
        {(facts.noTelemetry || regressed) && (
          <span className="font-mono text-[10px] shrink-0" style={{ color: COVERAGE_COLOR.warn }}>!</span>
        )}
        <LayerStrip facts={facts} huntLayer={huntLayer} />
        {/* findings·sweeps in the window; sweeps only on wide cells so the name keeps its room. */}
        {huntLayer && (facts.findings > 0 || sweeps > 0) && density !== 'compact' && (
          <span className="font-mono text-[9.5px] text-muted-foreground tabular-nums shrink-0">
            {compact(facts.findings)}{wide ? `·${compact(sweeps)}` : ''}
          </span>
        )}
      </button>
    </div>
  );
});

interface TacticStats {
  counts: ReturnType<typeof countClasses>;
  covered: number;
  total: number;
}

const TacticHeader = memo(function TacticHeader({ tactic, stats }: { tactic: TacticCoverage; stats: TacticStats }) {
  const { counts, covered, total } = stats;
  const denom = Math.max(total, 1);
  return (
    <div className="sticky top-0 z-10 border border-border rounded-t-[4px] bg-card px-[7px] py-[5px]">
      <div className="text-[11.5px] font-medium text-foreground truncate" title={tactic.tactic_name}>
        {tactic.tactic_name}
      </div>
      <div className="flex justify-between font-mono text-[10px] text-muted-foreground">
        <span>{tactic.tactic_id}</span>
        <span className="tabular-nums">{covered}/{total}</span>
      </div>
      <div className="flex h-[3px] mt-1 bg-border/60 overflow-hidden">
        {COVERAGE_CLASSES.filter((c) => c !== 'unmapped').map((c) => (
          <span
            key={c}
            style={{
              width: `${(counts[c] / denom) * 100}%`,
              background: COVERAGE_COLOR[c],
              opacity: c === 'blind' ? 0.6 : 1,
            }}
          />
        ))}
      </div>
    </div>
  );
});

interface CoverageMatrixProps {
  tactics: TacticCoverage[];
  techniques: TechniqueCoverage[];
  factsById: Map<string, TechniqueLayers>;
  view: CoverageView;
  /** Narrowing filter (mode, source, q, classes). Keep it stable across selections. */
  matches: (t: TechniqueCoverage) => boolean;
  /** True when any narrowing filter is set, so non-matching subs hide. */
  filtersActive: boolean;
  /** Gaps view dimming. */
  isDimmed: (f: TechniqueLayers) => boolean;
  tacticFilter: string | null;
  huntLayer: boolean;
  days: number;
  selectedId: string | null;
  /** Technique ids recon saw regress to blind (`recon.regressed_to_blind`). */
  regressed?: ReadonlySet<string>;
  density: Density;
  showIds: boolean;
  /** Sub-techniques open by default (the mockup's flat list); a parent's chevron flips its own state. */
  subsOpen?: boolean;
  onOpenTechnique: (tacticId: string, techniqueId: string) => void;
}

const NO_REGRESSIONS: ReadonlySet<string> = new Set();

export function CoverageMatrix({
  tactics,
  techniques,
  factsById,
  view,
  matches,
  filtersActive,
  isDimmed,
  tacticFilter,
  huntLayer,
  days,
  selectedId,
  regressed = NO_REGRESSIONS,
  density,
  showIds,
  subsOpen = true,
  onOpenTechnique,
}: CoverageMatrixProps) {
  // Parents whose chevron was flipped away from the `subsOpen` default.
  const [flipped, setFlipped] = useState<Set<string>>(new Set());

  const { byTactic, subsByParent, unitsByTactic } = useMemo(() => {
    const subsByParent = new Map<string, TechniqueCoverage[]>();
    const byTactic = new Map<string, TechniqueCoverage[]>();
    const unitsByTactic = new Map<string, TechniqueCoverage[]>();
    techniques.forEach((t) => {
      t.tactic_ids.forEach((tid) => {
        const units = unitsByTactic.get(tid) ?? [];
        units.push(t);
        unitsByTactic.set(tid, units);
      });
      if (t.is_subtechnique && t.parent_id) {
        const list = subsByParent.get(t.parent_id) ?? [];
        list.push(t);
        subsByParent.set(t.parent_id, list);
      } else if (!t.is_subtechnique) {
        t.tactic_ids.forEach((tid) => {
          const list = byTactic.get(tid) ?? [];
          list.push(t);
          byTactic.set(tid, list);
        });
      }
    });
    return { byTactic, subsByParent, unitsByTactic };
  }, [techniques]);

  const columns = useMemo(
    () => orderTactics(tactics).filter((t) => !tacticFilter || t.tactic_id === tacticFilter),
    [tactics, tacticFilter],
  );

  // Per-column header stats: only when the facts change, never per keystroke.
  const statsByTactic = useMemo(() => {
    const map = new Map<string, TacticStats>();
    unitsByTactic.forEach((units, tid) => {
      const facts = units.map((u) => factsById.get(u.technique_id)).filter((f): f is TechniqueLayers => Boolean(f));
      map.set(tid, { counts: countClasses(facts), covered: facts.filter((f) => f.live > 0).length, total: facts.length });
    });
    return map;
  }, [unitsByTactic, factsById]);

  // Visible groups per column: only when the filter or the data changes.
  const groupsByTactic = useMemo(() => {
    const map = new Map<string, { parent: TechniqueCoverage; parentMatches: boolean; allSubs: TechniqueCoverage[]; subs: TechniqueCoverage[]; rollup: string | null }[]>();
    columns.forEach((tactic) => {
      const groups = (byTactic.get(tactic.tactic_id) ?? [])
        .map((parent) => {
          const allSubs = (subsByParent.get(parent.technique_id) ?? [])
            .filter((sub) => sub.tactic_ids.includes(tactic.tactic_id));
          const parentMatches = matches(parent);
          const matchingSubs = allSubs.filter(matches);
          const huntedSubs = huntLayer
            ? allSubs.filter((sub) => factsById.get(sub.technique_id)?.h === 'hunted').length
            : 0;
          return {
            parent,
            parentMatches,
            allSubs,
            subs: filtersActive ? matchingSubs : allSubs,
            visible: parentMatches || matchingSubs.length > 0,
            rollup: huntLayer && allSubs.length > 0 ? `${huntedSubs} of ${allSubs.length} subs hunted` : null,
          };
        })
        .filter((g) => g.visible);
      map.set(tactic.tactic_id, groups);
    });
    return map;
  }, [columns, byTactic, subsByParent, matches, filtersActive, huntLayer, factsById]);

  const toggleExpand = useCallback((key: string) => {
    setFlipped((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const wide = Boolean(tacticFilter) || density === 'roomy';
  const colWidth = tacticFilter ? 'w-[420px]' : density === 'compact' ? 'w-[160px]' : density === 'roomy' ? 'w-[220px]' : 'w-[176px]';
  const emptyStats: TacticStats = { counts: countClasses([]), covered: 0, total: 0 };

  return (
    <div data-testid="mitre-coverage-matrix" className="flex-1 min-h-0 overflow-auto bg-background">
      <div className="flex items-start gap-1.5 px-4 pt-2.5 pb-4 min-w-max">
        {columns.map((tactic) => {
          const groups = groupsByTactic.get(tactic.tactic_id) ?? [];
          return (
            <div key={tactic.tactic_id} className={cn('flex flex-col', colWidth)} data-testid={`coverage-column-${tactic.tactic_id}`}>
              <TacticHeader tactic={tactic} stats={statsByTactic.get(tactic.tactic_id) ?? emptyStats} />
              <div className="border border-t-0 border-border rounded-b-[4px] overflow-hidden">
                {groups.length === 0 ? (
                  <div className="h-[26px] flex items-center px-2 text-[11px] text-muted-foreground">No techniques match</div>
                ) : (
                  groups.map(({ parent, parentMatches, subs, rollup }) => {
                    const key = `${tactic.tactic_id}/${parent.technique_id}`;
                    const facts = factsById.get(parent.technique_id);
                    if (!facts) return null;
                    const isOpen = subsOpen !== flipped.has(key) || (!parentMatches && subs.length > 0);
                    return (
                      <div key={key} className="border-b border-border last:border-b-0">
                        <Cell
                          tacticId={tactic.tactic_id}
                          technique={parent}
                          facts={facts}
                          view={view}
                          dimmed={!parentMatches || isDimmed(facts)}
                          huntLayer={huntLayer}
                          days={days}
                          density={density}
                          showIds={showIds}
                          selected={selectedId === parent.technique_id}
                          regressed={regressed.has(parent.technique_id)}
                          subCount={subs.length}
                          subRollup={rollup}
                          expanded={isOpen}
                          toggleKey={key}
                          onToggleExpand={toggleExpand}
                          wide={wide}
                          onOpen={onOpenTechnique}
                        />
                        {isOpen && subs.length > 0 && (
                          <div>
                            {subs.map((sub) => {
                              const subFacts = factsById.get(sub.technique_id);
                              if (!subFacts) return null;
                              return (
                                <Cell
                                  key={sub.technique_id}
                                  tacticId={tactic.tactic_id}
                                  technique={sub}
                                  facts={subFacts}
                                  view={view}
                                  dimmed={isDimmed(subFacts)}
                                  huntLayer={huntLayer}
                                  days={days}
                                  density={density}
                                  showIds={showIds}
                                  selected={selectedId === sub.technique_id}
                                  regressed={regressed.has(sub.technique_id)}
                                  sub
                                  wide={wide}
                                  onOpen={onOpenTechnique}
                                />
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
