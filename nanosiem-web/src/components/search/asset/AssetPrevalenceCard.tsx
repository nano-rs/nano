// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import type { TimeRange } from '@/lib/api/types';
import {
  PrevalenceScatterPlot,
  type PrevalenceScatterData,
  type PrevalenceScatterPoint,
} from '@/components/prevalence/PrevalenceScatterPlot';

interface AssetPrevalenceCardProps {
  identifierField: string;
  identifierValue: string;
  identities: Record<string, unknown>[];
  timeRange: TimeRange | undefined;
  /** When focus mode is on, show the "focus mode" stamp in the header. */
  focus: boolean;
  /** Drill into the asset's events for a clicked artifact (hash/domain). */
  onArtifactClick?: (artifact: string, artifactType: 'hash' | 'domain') => void;
}

const DEFAULT_MAX_HOSTS = 100;

export function AssetPrevalenceCard({
  identifierField,
  identifierValue,
  identities,
  timeRange,
  focus,
  onArtifactClick,
}: AssetPrevalenceCardProps) {
  const [data, setData] = useState<PrevalenceScatterData | null>(null);
  const [loading, setLoading] = useState(false);
  const [maxHostCount, setMaxHostCount] = useState(DEFAULT_MAX_HOSTS);

  useEffect(() => {
    if (!timeRange) return;
    let cancelled = false;
    setLoading(true);
    api
      .getAssetArtifacts({
        identifier_field: identifierField,
        identifier_value: identifierValue,
        identities,
        time_range: timeRange,
        max_host_count: maxHostCount,
      })
      .then((resp) => {
        if (cancelled) return;
        const hashMap = new Map<string, { host: number; isRare: boolean; score: number; firstSeen: Date }>();
        for (const p of resp.hash_prevalence) {
          hashMap.set(p.artifact.toLowerCase(), {
            host: p.host_count,
            isRare: p.is_rare,
            score: p.prevalence_score,
            firstSeen: new Date(p.first_seen),
          });
        }
        const domainMap = new Map<string, { host: number; isRare: boolean; score: number; firstSeen: Date }>();
        for (const p of resp.domain_prevalence) {
          domainMap.set(p.artifact.toLowerCase(), {
            host: p.host_count,
            isRare: p.is_rare,
            score: p.prevalence_score,
            firstSeen: new Date(p.first_seen),
          });
        }

        const toPoint = (
          type: 'hash' | 'domain',
          occs: typeof resp.hashes,
          map: typeof hashMap
        ): PrevalenceScatterPoint[] =>
          occs.map((o) => {
            const meta = map.get(o.artifact.toLowerCase());
            const ts = new Date(o.timestamp);
            return {
              artifact: o.artifact,
              artifactType: type,
              hostCount: meta?.host ?? 0,
              firstSeen: ts,
              lastSeen: ts,
              totalOccurrences: 1,
              isRare: meta?.isRare ?? false,
              prevalenceScore: meta?.score ?? 0,
              envFirstSeen: meta?.firstSeen ?? ts,
            };
          });

        const allHostCounts = [
          ...resp.hash_prevalence.map((p) => p.host_count),
          ...resp.domain_prevalence.map((p) => p.host_count),
        ];

        setData({
          hashPoints: toPoint('hash', resp.hashes, hashMap),
          domainPoints: toPoint('domain', resp.domains, domainMap),
          rarityThreshold: resp.rarity_threshold,
          maxArtifactHostCount: allHostCounts.length ? Math.max(...allHostCounts) : undefined,
          totalUnfilteredArtifacts:
            resp.hash_prevalence.length + resp.domain_prevalence.length || undefined,
        });
      })
      .catch(() => {
        if (cancelled) return;
        setData({ hashPoints: [], domainPoints: [], rarityThreshold: 0 });
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [identifierField, identifierValue, identities, timeRange, maxHostCount]);

  const rareCount =
    (data?.hashPoints.filter((p) => p.isRare).length ?? 0) +
    (data?.domainPoints.filter((p) => p.isRare).length ?? 0);

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border flex items-baseline gap-2">
        <span className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 font-semibold">
          Prevalence
        </span>
        <span className="text-[11px] text-muted-foreground/70">
          indicators observed on{' '}
          <span className="font-mono text-foreground">{identifierValue}</span>
        </span>
        <span className="flex-1" />
        {rareCount > 0 && (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold text-primary bg-primary/10 border border-primary/25">
            <span className="tabular-nums">{rareCount}</span> rare
          </span>
        )}
        {focus && (
          <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground/60">
            focus mode
          </span>
        )}
      </div>
      <div className="px-3 py-3">
        {data ? (
          <PrevalenceScatterPlot
            data={data}
            height={220}
            loading={loading}
            timeRange={timeRange}
            defaultMaxHostCount={DEFAULT_MAX_HOSTS}
            onMaxHostCountChange={setMaxHostCount}
            onArtifactClick={onArtifactClick ? (artifact, artifactType) => onArtifactClick(artifact, artifactType) : undefined}
          />
        ) : loading ? (
          <div className="h-[180px] flex items-center justify-center text-[11.5px] text-muted-foreground/70 font-mono">
            Loading prevalence…
          </div>
        ) : (
          <div className="h-[120px] flex items-center justify-center text-[11.5px] text-muted-foreground/70 font-mono">
            No prevalence data for this entity
          </div>
        )}
      </div>
    </div>
  );
}
