// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5850: the Telemetry tab. Open core: the ATT&CK data components the
// catalog asks for, with live readiness and how many techniques each one would
// unblind if it were onboarded (the same ranking recon's
// `blind_missing_source_types` computes). Enterprise renders the recon strip,
// census and bindings above it through `enterpriseSection`.

import { Term } from '@/components/ui/term';
import { type ReactNode, useMemo } from 'react';

import { type DataSourceReadiness, type TechniqueCoverage, readinessOf } from './types';
import type { TechniqueLayers } from './layers';
import { TelemetryDot } from './Legend';

export interface ComponentRow {
  id: string;
  name: string;
  readiness: DataSourceReadiness | 'unmapped' | 'missing';
  sourceTypes: string[];
  techniques: number;
  unblinded: number;
}

export interface SourceBacklogRow {
  sourceType: string;
  unblinded: number;
  components: string[];
}

const READINESS_RANK: Record<ComponentRow['readiness'], number> = {
  active: 0, stale: 1, unknown: 2, missing: 3, unmapped: 4,
};

/** Pure: aggregate data components and the onboarding backlog. */
export function summarizeTelemetry(
  techniques: readonly TechniqueCoverage[],
  factsById: Map<string, TechniqueLayers>,
): { components: ComponentRow[]; backlog: SourceBacklogRow[] } {
  const comps = new Map<string, ComponentRow & { blindSet: Set<string> }>();
  const backlog = new Map<string, { blind: Set<string>; components: Set<string> }>();

  techniques.forEach((t) => {
    const blind = factsById.get(t.technique_id)?.t !== 'active';
    (t.data_sources ?? []).forEach((d) => {
      const key = d.id || d.name;
      const readiness: ComponentRow['readiness'] = d.mapping_known === false
        ? 'unmapped'
        : readinessOf(d) === 'unknown' && d.configured === false
          ? 'missing'
          : readinessOf(d);
      const row = comps.get(key) ?? {
        id: key,
        name: d.name,
        readiness,
        sourceTypes: [],
        techniques: 0,
        unblinded: 0,
        blindSet: new Set<string>(),
      };
      if (READINESS_RANK[readiness] < READINESS_RANK[row.readiness]) row.readiness = readiness;
      (d.source_types ?? []).forEach((s) => {
        if (!row.sourceTypes.includes(s)) row.sourceTypes.push(s);
      });
      row.techniques += 1;
      if (blind && d.mapping_known !== false) {
        row.blindSet.add(t.technique_id);
        (d.source_types ?? []).forEach((s) => {
          const b = backlog.get(s) ?? { blind: new Set<string>(), components: new Set<string>() };
          b.blind.add(t.technique_id);
          b.components.add(d.name);
          backlog.set(s, b);
        });
      }
      comps.set(key, row);
    });
  });

  const components = [...comps.values()]
    .map(({ blindSet, ...row }) => ({ ...row, unblinded: blindSet.size, sourceTypes: row.sourceTypes.sort() }))
    .sort((a, b) => b.unblinded - a.unblinded || b.techniques - a.techniques || a.name.localeCompare(b.name));
  const backlogRows = [...backlog.entries()]
    .map(([sourceType, b]) => ({ sourceType, unblinded: b.blind.size, components: [...b.components].sort() }))
    .sort((a, b) => b.unblinded - a.unblinded || a.sourceType.localeCompare(b.sourceType));
  return { components, backlog: backlogRows };
}

const TH = 'sticky top-0 bg-background h-7 px-2 text-left font-medium text-[10.5px] uppercase tracking-wider text-muted-foreground border-b border-border whitespace-nowrap';
const TD = 'h-[26px] px-2 border-b border-border whitespace-nowrap';

function readinessText(r: ComponentRow['readiness']): string {
  switch (r) {
    case 'active': return 'active';
    case 'stale': return 'stale';
    case 'missing': return 'not configured';
    case 'unmapped': return 'no nano mapping';
    default: return 'health unknown';
  }
}

interface TelemetryTabProps {
  techniques: TechniqueCoverage[];
  factsById: Map<string, TechniqueLayers>;
  enterpriseSection?: ReactNode;
  onSourceFilter?: (sourceType: string) => void;
}

export function TelemetryTab({ techniques, factsById, enterpriseSection, onSourceFilter }: TelemetryTabProps) {
  const { components, backlog } = useMemo(
    () => summarizeTelemetry(techniques, factsById),
    [techniques, factsById],
  );

  return (
    <div className="flex-1 min-h-0 overflow-auto px-4 pb-4" data-testid="coverage-telemetry">
      {enterpriseSection}

      <section className="mt-3">
        <div className="py-1.5 text-[11px] text-muted-foreground">
          Onboarding backlog: log sources to add, ranked by how many techniques each would let you see
        </div>
        {backlog.length === 0 ? (
          <div className="text-[11.5px] text-muted-foreground" data-testid="coverage-telemetry-backlog-empty">
            Nothing to onboard: data is already coming in for every data component nano can map to a source, or this server doesn&apos;t report source types yet.
          </div>
        ) : (
          <table className="w-full border-collapse text-[11.5px]" data-testid="coverage-telemetry-backlog">
            <thead>
              <tr>
                <th className={TH}>Source type</th>
                <th className={TH}><Term id="techniques-unblinded">Techniques unblinded</Term></th>
                <th className={TH}>Data components</th>
              </tr>
            </thead>
            <tbody>
              {backlog.slice(0, 25).map((row) => (
                <tr key={row.sourceType} className="hover:bg-card">
                  <td className={`${TD} font-mono text-[10.5px]`}>
                    {onSourceFilter ? (
                      <button type="button" className="hover:underline" onClick={() => onSourceFilter(row.sourceType)}>
                        {row.sourceType}
                      </button>
                    ) : row.sourceType}
                  </td>
                  <td className={`${TD} font-mono text-[10.5px] tabular-nums`}>{row.unblinded}</td>
                  <td className={`${TD} max-w-[520px] truncate`} title={row.components.join(', ')}>{row.components.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="mt-4">
        <div className="py-1.5 text-[11px] text-muted-foreground">
          Required <Term id="data-component">data components</Term> <span className="font-mono text-[10.5px]">{components.length}</span>
        </div>
        <table className="w-full border-collapse text-[11.5px]" data-testid="coverage-telemetry-components">
          <thead>
            <tr>
              <th className={TH}>Data component</th>
              <th className={TH}><Term id="telemetry-state">Readiness</Term></th>
              <th className={`${TH} hidden md:table-cell`}>Source types</th>
              <th className={TH}>Techniques</th>
              <th className={TH}>Unblinded if onboarded</th>
            </tr>
          </thead>
          <tbody>
            {components.map((row) => (
              <tr key={row.id} className="hover:bg-card">
                <td className={TD}>{row.name}</td>
                <td className={TD}>
                  <span className="inline-flex items-center gap-1.5 font-mono text-[10.5px]">
                    <TelemetryDot state={row.readiness} />
                    {readinessText(row.readiness)}
                  </span>
                </td>
                <td className={`${TD} font-mono text-[10.5px] text-muted-foreground max-w-[280px] truncate hidden md:table-cell`}>
                  {row.sourceTypes.join(', ') || '-'}
                </td>
                <td className={`${TD} font-mono text-[10.5px] tabular-nums`}>{row.techniques}</td>
                <td className={`${TD} font-mono text-[10.5px] tabular-nums`}>{row.readiness === 'active' ? '-' : row.unblinded}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
