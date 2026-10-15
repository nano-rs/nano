// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import type { AssetArtifactsResponse, ProductViewProgress, TimeRange } from '@/lib/api/types';
import { fetchProgressive, progressLabel, rarityWaitLabel } from './progressive';
import { parseTimestampAsUTC } from '@/lib/parse-timestamp-utc';
import {
  PrevalenceScatterPlot,
  type PrevalenceScatterData,
  type PrevalenceScatterPoint,
  type PrevalenceSource,
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
  /**
   * NAN-3094: false until the event stream's first page has answered, so the
   * page never has two lake reads in flight. Defaults to true.
   */
  enabled?: boolean;
}

const DEFAULT_MAX_HOSTS = 100;

export function AssetPrevalenceCard({
  identifierField,
  identifierValue,
  identities,
  timeRange,
  focus,
  onArtifactClick,
  enabled = true,
}: AssetPrevalenceCardProps) {
  const [data, setData] = useState<PrevalenceScatterData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [totalArtifacts, setTotalArtifacts] = useState<number | null>(null);
  const [maxHostCount, setMaxHostCount] = useState(DEFAULT_MAX_HOSTS);
  const [progress, setProgress] = useState<ProductViewProgress | null>(null);

  useEffect(() => {
    if (!timeRange) return;
    let cancelled = false;
    const controller = new AbortController();
    const signal = controller.signal;
    if (!enabled) {
      setLoading(true);
      return;
    }
    setLoading(true);
    setError(null);
    const apply = (resp: AssetArtifactsResponse) => {
        if (cancelled) return;
        setProgress(resp.progress ?? null);
        interface ArtifactMeta {
          host: number;
          isRare: boolean;
          score: number;
          // REAL env-wide first-seen only. `p.first_seen` is the in-window
          // minimum — keying "new to env" off it stamped long-known artifacts
          // as novel whenever their first in-window hit was recent.
          envFirstSeen?: Date;
          prevalenceSource?: PrevalenceSource;
          inWindowHosts?: number;
        }
        const toMeta = (p: (typeof resp.hash_prevalence)[number]): ArtifactMeta => ({
          host: p.host_count,
          isRare: p.is_rare,
          score: p.prevalence_score,
          envFirstSeen: p.env_first_seen ? parseTimestampAsUTC(p.env_first_seen) : undefined,
          prevalenceSource: p.prevalence_source,
          inWindowHosts: p.in_window_hosts,
        });
        const hashMap = new Map<string, ArtifactMeta>();
        for (const p of resp.hash_prevalence) hashMap.set(p.artifact.toLowerCase(), toMeta(p));
        const domainMap = new Map<string, ArtifactMeta>();
        for (const p of resp.domain_prevalence) domainMap.set(p.artifact.toLowerCase(), toMeta(p));

        const toPoint = (
          type: 'hash' | 'domain',
          occs: typeof resp.hashes,
          map: typeof hashMap
        ): PrevalenceScatterPoint[] =>
          occs
            // No usable timestamp = no X position. Previously these landed at
            // "now" via the parse fallback and rendered as fresh sightings.
            .filter((o) => !Number.isNaN(parseTimestampAsUTC(o.timestamp).getTime()))
            .map((o) => {
            const meta = map.get(o.artifact.toLowerCase());
            // Lake timestamps can arrive zone-naive; never local-parse them.
            const ts = parseTimestampAsUTC(o.timestamp);
            return {
              artifact: o.artifact,
              artifactType: type,
              hostCount: meta?.host ?? 0,
              firstSeen: ts,
              lastSeen: ts,
              totalOccurrences: 1,
              isRare: meta?.isRare ?? false,
              prevalenceScore: meta?.score ?? 0,
              // NAN-1699: no event-time fallback — novelty must key off a REAL
              // env-first-seen, not the occurrence time.
              envFirstSeen: meta?.envFirstSeen,
              // Baseline vs in-window provenance, same treatment as the Rarity
              // chart: hollow "lower bound" dots instead of silently dropping
              // the information the backend already computed.
              prevalenceSource:
                meta?.prevalenceSource ?? ((meta?.host ?? 0) > 0 ? 'baseline' : 'none'),
              inWindowHosts: meta?.inWindowHosts,
              baselineHostCount:
                meta?.prevalenceSource === 'in-window' ? undefined : meta?.host,
            };
          });

        const allHostCounts = [
          ...resp.hash_prevalence.map((p) => p.host_count),
          ...resp.domain_prevalence.map((p) => p.host_count),
        ];

        const total =
          resp.total_artifacts ?? (resp.hash_prevalence.length + resp.domain_prevalence.length);
        setTruncated(resp.artifacts_truncated ?? false);
        setTotalArtifacts(total || null);
        setData({
          hashPoints: toPoint('hash', resp.hashes, hashMap),
          domainPoints: toPoint('domain', resp.domains, domainMap),
          rarityThreshold: resp.rarity_threshold,
          maxArtifactHostCount: allHostCounts.length ? Math.max(...allHostCounts) : undefined,
          totalUnfilteredArtifacts: total || undefined,
        });
    };
    // NAN-3094: the lean summary is read from the page's shared snapshot and
    // may answer before it is final; render each answer and poll.
    fetchProgressive(
      () => api.getAssetArtifacts({
        identifier_field: identifierField,
        identifier_value: identifierValue,
        identities,
        time_range: timeRange,
        max_host_count: maxHostCount,
      }, { signal }),
      apply,
      () => !cancelled,
      false,
      signal,
    )
      .then(apply)
      .catch((err) => {
        if (cancelled) return;
        // A failed call (429 rate limit, timeout, ...) is NOT "no rare
        // artifacts" — surface it instead of rendering the empty state.
        setError(err instanceof Error ? err.message : 'Failed to load prevalence data');
        setData(null);
        setTruncated(false);
        setTotalArtifacts(null);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [identifierField, identifierValue, identities, timeRange, maxHostCount, enabled]);

  const rareCount =
    (data?.hashPoints.filter((p) => p.isRare).length ?? 0) +
    (data?.domainPoints.filter((p) => p.isRare).length ?? 0);
  const pointCount = (data?.hashPoints.length ?? 0) + (data?.domainPoints.length ?? 0);
  // NAN-3252: while the view is incomplete (or before its first answer), say
  // what Rarity is waiting on; partial dots render as they arrive.
  const waiting = error
    ? null
    : (rarityWaitLabel(progress) ?? (loading && !data ? 'reading events…' : null));
  const noteLabel = progressLabel(progress, timeRange?.start);

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
        {truncated && totalArtifacts != null && (
          <span
            className="text-[10px] font-mono text-amber-500/90"
            title="The summary returns the 50 most recent artifacts per class; this asset touched more."
          >
            top 50/class of {totalArtifacts} artifacts
          </span>
        )}
        {rareCount > 0 && (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold text-primary bg-primary/10 border border-primary/25">
            <span className="tabular-nums">{rareCount}</span> rare
          </span>
        )}
        {waiting ? (
          <span
            data-testid="asset-prevalence-refining"
            className="inline-flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground/60"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground/60 animate-pulse" />
            {waiting}
          </span>
        ) : (
          noteLabel && (
            <span className="text-[10px] font-mono text-muted-foreground/60">{noteLabel}</span>
          )
        )}
        {focus && (
          <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground/60">
            focus mode
          </span>
        )}
      </div>
      <div className="px-3 py-3">
        {error ? (
          <div className="h-[120px] flex flex-col items-center justify-center gap-1 text-[11.5px] font-mono">
            <span className="text-destructive">Prevalence unavailable: {error}</span>
            <span className="text-muted-foreground/70">
              This is a load failure, not an empty result — retry or narrow the window.
            </span>
          </div>
        ) : data && (pointCount > 0 || !waiting) ? (
          <PrevalenceScatterPlot
            data={data}
            height={220}
            loading={loading && !waiting}
            timeRange={timeRange}
            defaultMaxHostCount={DEFAULT_MAX_HOSTS}
            onMaxHostCountChange={setMaxHostCount}
            onArtifactClick={onArtifactClick ? (artifact, artifactType) => onArtifactClick(artifact, artifactType) : undefined}
          />
        ) : waiting || loading ? (
          <div className="h-[180px] flex items-center justify-center text-[11.5px] text-muted-foreground/70 font-mono">
            {waiting === 'reading events…' || !waiting
              ? 'Rarity: reading this asset’s events…'
              : 'Rarity: no artifacts yet — refining host counts…'}
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
