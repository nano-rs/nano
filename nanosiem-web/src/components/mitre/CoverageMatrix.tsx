// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-516 — Navigator-style coverage matrix.
// Port of design-ref/shadcn/mitre-matrix.jsx. 14 fixed tactic columns;
// techniques flow vertically; cells colour-coded by tier; sub-techniques
// expand inline under the parent cell; cell click opens the drawer.

import { useMemo, useState } from 'react';
import { ChevronRight } from 'lucide-react';

import { cn } from '@/lib/utils';
import {
  type CoverageTier,
  type Density,
  type RedesignFilters,
  type TacticCoverage,
  type TechniqueCoverage,
  filterTechniqueGroup,
  statusOf,
  summarizeTechniqueCoverage,
  tierFor,
} from './types';

// MITRE Enterprise tactic order — kill-chain.
const TACTIC_ORDER = [
  'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005',
  'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010', 'TA0040',
];

const tierClasses = (tier: CoverageTier): string => {
  switch (tier) {
    case 'full':
      return 'bg-emerald-500/15 border-emerald-500/40 text-emerald-500 hover:bg-emerald-500/25';
    case 'partial':
      return 'bg-amber-500/15 border-amber-500/40 text-amber-500 hover:bg-amber-500/25';
    case 'hot-gap':
      return 'bg-rose-500/15 border-rose-500/40 text-rose-500 hover:bg-rose-500/25';
    case 'gap':
    default:
      return 'bg-card border-border text-muted-foreground hover:bg-secondary';
  }
};

interface TechCellProps {
  tactic: TacticCoverage;
  technique: TechniqueCoverage;
  subs: TechniqueCoverage[];
  density: Density;
  showIds: boolean;
  expanded: boolean;
  onToggleExpand: () => void;
  onOpen: (tacticId: string, techniqueId: string) => void;
}

function TechCell({
  tactic,
  technique,
  subs,
  density,
  showIds,
  expanded,
  onToggleExpand,
  onOpen,
}: TechCellProps) {
  const tier = tierFor(technique);
  const liveCount = (technique.rules || []).filter((r) => statusOf(r.mode) === 'live').length;
  const hasSubs = subs.length > 0;

  const heightCls = density === 'compact' ? 'min-h-[34px] py-1' : density === 'roomy' ? 'min-h-[54px] py-2' : 'min-h-[42px] py-1.5';
  const padCls = density === 'compact' ? 'px-1.5' : 'px-2';

  return (
    <div className="flex flex-col gap-0.5">
      <button
        type="button"
        onClick={() => onOpen(tactic.tactic_id, technique.technique_id)}
        className={cn(
          'group relative w-full text-left rounded-[5px] border transition-colors',
          heightCls,
          padCls,
          tierClasses(tier),
        )}
      >
        <div className="flex items-start gap-1.5">
          {hasSubs && (
            <span
              role="button"
              tabIndex={0}
              onClick={(e) => {
                e.stopPropagation();
                onToggleExpand();
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.stopPropagation();
                  e.preventDefault();
                  onToggleExpand();
                }
              }}
              className={cn(
                'mt-[1px] w-3.5 h-3.5 rounded-[3px] border flex items-center justify-center shrink-0',
                'border-current/30 bg-black/5 hover:bg-black/10 transition-transform',
                expanded && 'rotate-90',
              )}
            >
              <ChevronRight className="w-[8px] h-[8px]" />
            </span>
          )}
          <div className="flex-1 min-w-0">
            {showIds && (
              <div className="font-mono text-[9.5px] leading-tight opacity-70 truncate">{technique.technique_id}</div>
            )}
            <div className={cn('leading-tight break-words', density === 'compact' ? 'text-[11px]' : 'text-[11.5px]')}>
              {technique.technique_name}
            </div>
          </div>
          {liveCount > 0 && (
            <span className="shrink-0 font-mono text-[9.5px] h-[15px] min-w-[15px] px-1 rounded-[3px] bg-black/10 border border-current/20 flex items-center justify-center tabular-nums">
              {liveCount}
            </span>
          )}
          {tier === 'hot-gap' && (
            <span className="shrink-0 font-mono text-[9px] uppercase tracking-wider opacity-80">gap</span>
          )}
        </div>
      </button>

      {expanded && hasSubs && (
        <div className="ml-3 pl-2 border-l border-border flex flex-col gap-0.5">
          {subs.map((sub) => (
            <SubTechniqueCell
              key={sub.technique_id}
              tacticId={tactic.tactic_id}
              technique={sub}
              showIds={showIds}
              onOpen={onOpen}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface TacticHeaderProps {
  tactic: TacticCoverage;
  covered: number;
  total: number;
  pct: number;
}

function SubTechniqueCell({
  tacticId,
  technique,
  showIds,
  onOpen,
}: {
  tacticId: string;
  technique: TechniqueCoverage;
  showIds: boolean;
  onOpen: (tacticId: string, techniqueId: string) => void;
}) {
  const tier = tierFor(technique);
  const liveCount = (technique.rules || []).filter(
    (rule) => statusOf(rule.mode) === 'live',
  ).length;

  return (
    <button
      type="button"
      onClick={() => onOpen(tacticId, technique.technique_id)}
      className={cn(
        'text-left px-1.5 py-1 rounded-[4px] border transition-colors group',
        tierClasses(tier),
      )}
    >
      <div className="flex items-baseline gap-1.5">
        {showIds && (
          <span className="font-mono text-[9px] opacity-70">
            {technique.technique_id}
          </span>
        )}
        <span className="text-[10.5px] flex-1 leading-tight">
          {technique.technique_name}
        </span>
        {liveCount > 0 && (
          <span className="font-mono text-[9px] tabular-nums opacity-80">
            {liveCount}
          </span>
        )}
      </div>
    </button>
  );
}

function TacticHeader({ tactic, covered, total, pct }: TacticHeaderProps) {
  return (
    <div className="sticky top-0 z-10 bg-background border-b border-border pb-2 pt-2 px-1.5">
      <div className="flex items-baseline justify-between gap-2 mb-1">
        <div className="flex-1 min-w-0">
          <div className="text-[11.5px] font-semibold text-foreground tracking-[-0.01em] truncate">
            {tactic.tactic_name}
          </div>
          <div className="font-mono text-[9.5px] text-muted-foreground mt-px">{tactic.tactic_id}</div>
        </div>
        <div className="shrink-0 font-mono text-[10px] text-foreground/80 tabular-nums">
          {covered}/{total}
        </div>
      </div>
      <div className="h-1 rounded-full bg-border overflow-hidden">
        <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

interface CoverageMatrixProps {
  tactics: TacticCoverage[];
  techniques: TechniqueCoverage[];
  filters: RedesignFilters;
  density: Density;
  showIds: boolean;
  onOpenTechnique: (tacticId: string, techniqueId: string) => void;
}

export function CoverageMatrix({
  tactics,
  techniques,
  filters,
  density,
  showIds,
  onOpenTechnique,
}: CoverageMatrixProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Index techniques: parents per tactic + sub-technique groups by parent_id.
  const { byTactic, subsByParent } = useMemo(() => {
    const subsByParent = new Map<string, TechniqueCoverage[]>();
    techniques
      .filter((t) => t.is_subtechnique && t.parent_id)
      .forEach((t) => {
        const list = subsByParent.get(t.parent_id!) ?? [];
        list.push(t);
        subsByParent.set(t.parent_id!, list);
      });

    const byTactic = new Map<string, TechniqueCoverage[]>();
    techniques
      .filter((t) => !t.is_subtechnique)
      .forEach((t) => {
        t.tactic_ids.forEach((tid) => {
          const list = byTactic.get(tid) ?? [];
          list.push(t);
          byTactic.set(tid, list);
        });
      });

    return { byTactic, subsByParent };
  }, [techniques]);

  const tacticsOrdered = useMemo(() => {
    const byId = new Map(tactics.map((t) => [t.tactic_id, t]));
    return TACTIC_ORDER.map((id) => byId.get(id)).filter((t): t is TacticCoverage => Boolean(t));
  }, [tactics]);

  // Count parents and sub-techniques as independent units, matching the API.
  const statsByTactic = useMemo(() => {
    const map = new Map<string, ReturnType<typeof summarizeTechniqueCoverage>>();
    tacticsOrdered.forEach((tactic) => {
      const units = techniques.filter((technique) =>
        technique.tactic_ids.includes(tactic.tactic_id));
      map.set(tactic.tactic_id, summarizeTechniqueCoverage(units));
    });
    return map;
  }, [tacticsOrdered, techniques]);

  const colWidth = density === 'compact' ? 'w-[140px]' : 'w-[160px]';
  const colGap = density === 'compact' ? 'gap-1' : 'gap-1.5';

  const toggleExpand = (key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  return (
    <div className="flex-1 min-h-0 overflow-auto bg-background">
      <div className="flex gap-1 p-3 min-w-max">
        {tacticsOrdered.map((tactic) => {
          const tacticStats = statsByTactic.get(tactic.tactic_id)
            ?? summarizeTechniqueCoverage([]);
          const groups = (byTactic.get(tactic.tactic_id) ?? [])
            .map((parent) => {
              const tacticSubs = (subsByParent.get(parent.technique_id) ?? [])
                .filter((sub) => sub.tactic_ids.includes(tactic.tactic_id));
              return { parent, ...filterTechniqueGroup(parent, tacticSubs, filters) };
            })
            .filter((group) => group.visible);
          return (
            <div key={tactic.tactic_id} className={cn('flex flex-col', colGap, colWidth)}>
              <TacticHeader
                tactic={tactic}
                covered={tacticStats.covered}
                total={tacticStats.total}
                pct={tacticStats.percentage}
              />
              <div className={cn('flex flex-col px-0.5', colGap)}>
                {groups.length === 0 ? (
                  <div className="text-[10px] text-muted-foreground font-mono text-center py-3 opacity-50">—</div>
                ) : (
                  groups.map(({ parent, parentMatches, subs }) => {
                    const key = `${tactic.tactic_id}/${parent.technique_id}`;
                    return (
                      <TechCell
                        key={key}
                        tactic={tactic}
                        technique={parent}
                        subs={subs}
                        density={density}
                        showIds={showIds}
                        expanded={expanded.has(key) || (!parentMatches && subs.length > 0)}
                        onToggleExpand={() => toggleExpand(key)}
                        onOpen={onOpenTechnique}
                      />
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
