// SPDX-License-Identifier: AGPL-3.0-or-later
// The one on-demand enrichment surface. Mounted once in the app shell; any
// "Enrich" action (search value menu, prevalence, case entities, pivt
// `@enrich`) dispatches ENRICH_ARTIFACT_EVENT and this sheet:
// - always searches every IOC source the tenant has enabled (its own IOC
//   lists/feeds plus its enabled baseline feeds such as ThreatFox and Tor
//   exit nodes) through POST /api/threat-intel/indicator-lookup (NAN-3881);
// - adds external provider results (POST /api/threat-intel/lookup) only when
//   the tenant has the agent-enrichment add-on. "No external provider" shows
//   only when the tenant has no indicator source enabled at all.
// Renders nothing outside hosted-shared tenants.

import { useEffect, useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Info, ScanSearch } from 'lucide-react';
import { api } from '@/lib/api';
import { DetailSheet } from '@/components/ui/detail-sheet';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { ENRICH_ARTIFACT_EVENT, type EnrichArtifactDetail } from './enrich-event';
import { ThreatIntelResults, VerdictChip } from './ThreatIntelResults';
import { IndicatorResults } from './IndicatorResults';
import { originLabel } from './format';
import { useEnrichEnabled, useIndicatorSetsEnabled, useThreatIntelEnabled, useThreatIntelKey } from './use-threat-intel';

export function EnrichSheetHost() {
  const enabled = useEnrichEnabled();
  const [target, setTarget] = useState<EnrichArtifactDetail | null>(null);
  useEffect(() => {
    if (!enabled) return;
    const onEnrich = (e: Event) => {
      const detail = (e as CustomEvent<EnrichArtifactDetail>).detail;
      if (detail?.artifact?.trim()) setTarget({ ...detail, artifact: detail.artifact.trim() });
    };
    window.addEventListener(ENRICH_ARTIFACT_EVENT, onEnrich);
    return () => window.removeEventListener(ENRICH_ARTIFACT_EVENT, onEnrich);
  }, [enabled]);
  if (!enabled || !target) return null;
  return <EnrichSheet target={target} onClose={() => setTarget(null)} />;
}

function SectionLabel({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-1 flex h-5 items-center justify-between font-mono text-[10.5px] uppercase tracking-wide text-muted-foreground">
      <span>{children}</span>
      {right}
    </div>
  );
}

function AboutTooltip({ sets, external }: { sets: boolean; external: boolean }) {
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            aria-label="About these results"
            data-testid="ti-about"
            className="inline-flex h-5 w-5 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground"
          >
            <Info className="h-3.5 w-3.5" strokeWidth={1.5} />
          </button>
        </TooltipTrigger>
        <TooltipContent side="bottom" align="end" sideOffset={6} collisionPadding={8} className="max-w-[300px] text-[11px]">
          {sets &&
            "Indicator sets are your tenant's IOC lists plus the baseline feeds it has enabled (ThreatFox, Tor exit nodes…), searched in place: the same sources ingest matches against."}
          {external &&
            ' External results come from your tenant\'s configured providers and are cached per provider. Each external lookup is audited.'}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

export function EnrichSheet({ target, onClose }: { target: EnrichArtifactDetail; onClose: () => void }) {
  const root = useThreatIntelKey();
  const external = useThreatIntelEnabled();
  const sets = useIndicatorSetsEnabled();
  const client = useQueryClient();
  const origin = target.origin ?? 'analyst';
  const indicatorKey = [...root, 'indicators', target.artifactType ?? 'auto', target.artifact];
  const indicators = useQuery({
    queryKey: indicatorKey,
    queryFn: () => api.threatIntel.lookupIndicators({ artifact: target.artifact, artifact_type: target.artifactType }),
    enabled: sets,
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
  const queryKey = [...root, 'lookup', target.artifactType ?? 'auto', target.artifact, origin];
  const request = (force_refresh: boolean) =>
    api.threatIntel.lookup({ artifact: target.artifact, artifact_type: target.artifactType, origin, force_refresh });
  const lookup = useQuery({
    queryKey,
    queryFn: () => request(false),
    enabled: external,
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
  const refresh = useMutation({
    mutationFn: () => request(true),
    onSuccess: (fresh) => client.setQueryData(queryKey, fresh),
  });

  const data = lookup.data;
  const iocs = indicators.data;
  const matchCount = iocs?.sources.reduce((n, s) => n + s.matches.length, 0) ?? 0;
  const busy = indicators.isFetching || lookup.isFetching || refresh.isPending;
  const externalError = (lookup.error ?? refresh.error)?.message;
  // NAN-3881: "no provider" is only news when nothing else was searched,
  // never while the tenant's IOC lists / baseline feeds are enabled.
  const noIndicatorSources = !sets || (iocs != null && iocs.source_count === 0);
  return (
    <DetailSheet
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      size="sm"
      breadcrumb={['Threat intel', iocs?.artifact_type ?? data?.artifact_type ?? target.artifactType ?? 'artifact']}
      icon={<ScanSearch className="h-4 w-4" strokeWidth={1.5} />}
      title={<span className="font-mono text-[13px]">{target.artifact}</span>}
      meta={
        <span className="flex flex-wrap items-center gap-2" data-testid="ti-origin">
          <span>{originLabel(origin)}</span>
          {matchCount > 0 && (
            <>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums text-destructive" data-testid="ti-ioc-count">
                {matchCount === 1 ? '1 indicator match' : `${matchCount} indicator matches`}
              </span>
            </>
          )}
          {data?.verdict && (
            <>
              <span aria-hidden="true">·</span>
              <VerdictChip verdict={data.verdict} />
              {data.score != null && <span className="tabular-nums">max {data.score}/100</span>}
            </>
          )}
        </span>
      }
      actions={
        <span className="flex items-center gap-1">
          <Button
            size="sm"
            variant="outline"
            className="h-6 px-2 text-[11px]"
            disabled={busy}
            onClick={() => {
              if (sets) void indicators.refetch();
              if (external) refresh.mutate();
            }}
          >
            Refresh
          </Button>
        </span>
      }
    >
      {sets && (
      <section data-testid="ti-indicators">
        <SectionLabel
          right={
            <span className="flex items-center gap-1 normal-case tracking-normal">
              {iocs?.source_count != null && iocs.source_count > 0 && (
                <span className="tabular-nums" title={iocs.source_names?.join(', ')}>
                  {iocs.source_count} source{iocs.source_count === 1 ? '' : 's'}
                </span>
              )}
              {/* In the body, not the header actions: the sheet autofocuses
                  its first header control, and a focused tooltip trigger
                  would pop the tooltip open. */}
              <AboutTooltip sets external={external} />
            </span>
          }
        >
          Indicator sets
        </SectionLabel>
        {indicators.isPending ? (
          <div role="status" className="flex items-center gap-2 py-2 text-[12px] text-muted-foreground">
            <LoadingIcon className="h-3.5 w-3.5" /> Searching indicator sets…
          </div>
        ) : indicators.isError ? (
          <p role="alert" className="text-[12px] text-destructive">
            {indicators.error?.message || 'Indicator search failed'}
          </p>
        ) : iocs ? (
          <IndicatorResults response={iocs} />
        ) : null}
      </section>
      )}

      {external && (
        <section className={sets ? 'mt-3' : undefined} data-testid="ti-external">
          {lookup.isPending ? (
            <div role="status" className="flex items-center gap-2 py-2 text-[12px] text-muted-foreground">
              <LoadingIcon className="h-3.5 w-3.5" /> Querying providers…
            </div>
          ) : externalError ? (
            <p data-testid="ti-external-error" className="text-[11px] text-muted-foreground">
              External providers: <span className="text-amber-600 dark:text-amber-400">{externalError}</span>
            </p>
          ) : data?.availability === 'available' ? (
            <>
              <SectionLabel right={sets ? undefined : <AboutTooltip sets={false} external />}>External providers</SectionLabel>
              <ThreatIntelResults response={data} />
            </>
          ) : data && (data.availability !== 'no_provider_configured' || noIndicatorSources) ? (
            <ThreatIntelResults response={data} />
          ) : null}
        </section>
      )}
    </DetailSheet>
  );
}
