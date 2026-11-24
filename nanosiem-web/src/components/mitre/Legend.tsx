// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5850: one legend row under the filters. Each class swatch shows its
// count and toggles that class as a filter; the strip key explains the D/H/T
// marks every cell carries.

import { cn } from '@/lib/utils';
import {
  type ClassCounts,
  type CoverageClass,
  COVERAGE_CLASSES,
  COVERAGE_COLOR,
  classLabel,
} from './layers';
import { Term } from '@/components/ui/term';
import { EnterpriseTerm } from '@/enterprise/components/glossary/EnterpriseTerm';

const HUNT_ONLY: ReadonlySet<CoverageClass> = new Set(['both', 'hunted']);

export function ClassSwatch({ cls, className }: { cls: CoverageClass; className?: string }) {
  const color = cls === 'unmapped' ? null : COVERAGE_COLOR[cls];
  return (
    <span
      aria-hidden="true"
      className={cn(
        'inline-block w-2.5 h-2.5 rounded-[2px] shrink-0',
        !color && 'border border-dashed border-muted-foreground',
        className,
      )}
      style={color ? { background: color, opacity: cls === 'blind' ? 0.6 : 1 } : undefined}
    />
  );
}

interface LegendProps {
  counts: ClassCounts;
  huntLayer: boolean;
  selected: ReadonlySet<CoverageClass>;
  onToggle: (cls: CoverageClass) => void;
}

/**
 * NAN-5867: a coverage class label with its glossary definition. The hunt
 * classes are enterprise terms, so they go through the <EnterpriseTerm> slot
 * (plain text in the open edition).
 */
function ClassName({ cls, huntLayer }: { cls: CoverageClass; huntLayer: boolean }) {
  const label = classLabel(cls, huntLayer);
  switch (cls) {
    case 'both': return <EnterpriseTerm id="cov-both" nested>{label}</EnterpriseTerm>;
    case 'hunted': return <EnterpriseTerm id="cov-hunted" nested>{label}</EnterpriseTerm>;
    case 'huntable':
      return huntLayer
        ? <EnterpriseTerm id="cov-huntable" nested>{label}</EnterpriseTerm>
        : <Term id="cov-telemetry-no-rule" nested>{label}</Term>;
    case 'detected': return <Term id="cov-detected" nested>{label}</Term>;
    case 'blind': return <Term id="cov-blind" nested>{label}</Term>;
    case 'unmapped':
    default: return <Term id="cov-unmapped" nested>{label}</Term>;
  }
}

export function Legend({ counts, huntLayer, selected, onToggle }: LegendProps) {
  const classes = COVERAGE_CLASSES.filter((c) => huntLayer || !HUNT_ONLY.has(c));
  return (
    <div
      data-testid="coverage-legend"
      className="shrink-0 flex flex-wrap items-center gap-x-3.5 gap-y-1 px-4 py-1.5 border-b border-border font-mono text-[10.5px] text-foreground/80"
    >
      {classes.map((cls) => {
        const dim = selected.size > 0 && !selected.has(cls);
        return (
          <button
            key={cls}
            type="button"
            data-testid={`coverage-legend-${cls}`}
            aria-pressed={selected.has(cls)}
            onClick={() => onToggle(cls)}
            className={cn('inline-flex items-center gap-1.5 hover:text-foreground', dim && 'opacity-35')}
          >
            <ClassSwatch cls={cls} />
            <ClassName cls={cls} huntLayer={huntLayer} />
            <span className="text-muted-foreground tabular-nums">{counts[cls]}</span>
          </button>
        );
      })}
      <span className="inline-flex items-center gap-1.5" data-testid="coverage-legend-rule_no_telemetry">
        <span style={{ color: COVERAGE_COLOR.warn }}>!</span>
        <Term id="rule-no-telemetry">Rule, no telemetry</Term>
        <span className="text-muted-foreground tabular-nums">{counts.noTelemetry}</span>
      </span>
      <span className="ml-auto inline-flex flex-wrap items-center gap-2.5 text-muted-foreground">
        <span className="inline-flex items-center gap-1"><DetectionTick /> live rule</span>
        <span className="inline-flex items-center gap-1"><DetectionTick staging /> <Term id="mode-staging">staging</Term></span>
        {huntLayer && <span className="inline-flex items-center gap-1"><HuntTick /> hunted</span>}
        <span className="inline-flex items-center gap-1">
          <Term id="telemetry-state">telemetry</Term>
          <TelemetryDot state="active" /> active <TelemetryDot state="stale" /> stale <TelemetryDot state="missing" /> none
        </span>
      </span>
    </div>
  );
}

// ----------------------------------------------------------------------------
// D / H / T marks. Shared by matrix cells, the panel's sub-technique list and
// the legend key.
// ----------------------------------------------------------------------------

export function DetectionTick({ staging = false }: { staging?: boolean }) {
  return (
    <i
      aria-hidden="true"
      className="inline-block w-[3px] h-2.5 rounded-[1px]"
      style={staging
        ? { border: `1px solid ${COVERAGE_COLOR.detected}` }
        : { background: COVERAGE_COLOR.detected }}
    />
  );
}

export function HuntTick({ scheduled = false }: { scheduled?: boolean }) {
  return (
    <i
      aria-hidden="true"
      className="inline-block w-[5px] h-2.5 rounded-[1px]"
      style={scheduled
        ? { border: `1px solid ${COVERAGE_COLOR.hunted}` }
        : { background: COVERAGE_COLOR.hunted }}
    />
  );
}

export function TelemetryDot({ state }: { state: 'active' | 'stale' | 'missing' | 'unknown' | 'unmapped' }) {
  const style = state === 'active'
    ? { background: COVERAGE_COLOR.ok }
    : state === 'stale'
      ? { border: `1px solid ${COVERAGE_COLOR.huntable}` }
      : state === 'missing'
        ? { background: COVERAGE_COLOR.blind, opacity: 0.7 }
        : { border: '1px dashed currentColor', opacity: 0.6 };
  return <i aria-hidden="true" className="inline-block w-1.5 h-1.5 rounded-full" style={style} />;
}
