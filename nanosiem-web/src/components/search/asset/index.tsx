// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useState } from 'react';
import { api } from '@/lib/api';
import { useAssetDossier } from '@/hooks/use-api';
import type {
  EntityContextResponse,
  TimeRange,
} from '@/lib/api/types';
import { AssetTopStrip } from './AssetTopStrip';
import { AssetIdentityHeader } from './AssetIdentityHeader';
import { AssetActivityTimeline } from './AssetActivityTimeline';
import { AlertsCard } from './sections/AlertsCard';
import { ProcessesCard } from './sections/ProcessesCard';
import { NetworkCard } from './sections/NetworkCard';
import { AuthCard } from './sections/AuthCard';
import { FilesCard } from './sections/FilesCard';
import { DnsCard } from './sections/DnsCard';
import { AssetPrevalenceCard } from './AssetPrevalenceCard';
import { AssetStream } from './AssetStream';
import { formatTimestampHMS } from './helpers';

// ---------------------------------------------------------------------------
// Types (mirrors the shape SearchResults passes today)
// ---------------------------------------------------------------------------

interface AssetIdentityRecord {
  ip?: string | null;
  hostname?: string | null;
  mac?: string | null;
  user?: string | null;
}

interface AssetProfile {
  primary_identifier: { field: string; value: string } | null;
  identities: AssetIdentityRecord[];
  first_seen: string | null;
  last_seen: string | null;
}

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

export interface AssetViewProps {
  results: SearchResult[];
  onDrilldown?: (filters: Record<string, unknown>) => void;
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  prevalenceFilter?: {
    artifacts: string[];
    filterType: 'include' | 'rare';
    timestamp?: number;
  } | null;
  timeRange?: TimeRange;
  onFetchLog?: (id: string, timestamp: Date) => Promise<Record<string, unknown> | null>;
  /** Current visible-fields count for the Fields restore pill (22 in the mockup) */
  fieldsCollapsedCount?: number;
  /** Callback to expand the Fields panel */
  onExpandFields?: () => void;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

export function AssetView({ results, timeRange, fieldsCollapsedCount, onExpandFields, onDrilldown }: AssetViewProps) {
  // Pull the asset profile out of the first result (set by `| asset` command)
  const assetProfile = useMemo<AssetProfile | null>(() => {
    if (!results.length) return null;
    const fields = results[0]?.fields;
    if (fields?._display_type === 'asset' && fields?._asset_profile) {
      return fields._asset_profile as AssetProfile;
    }
    return null;
  }, [results]);

  const primary = assetProfile?.primary_identifier;
  const identifierField = primary?.field ?? '';
  const identifierValue = primary?.value ?? '';
  const identities = useMemo(
    () => (assetProfile?.identities ?? []) as unknown as Record<string, unknown>[],
    [assetProfile]
  );

  const kind: 'host' | 'user' =
    identifierField === 'user' || identifierField === 'src_user' ? 'user' : 'host';

  // Focus mode — persisted in localStorage, mirrors the mockup
  const [focus, setFocus] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('nano-asset-focus') === '1';
  });
  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem('nano-asset-focus', focus ? '1' : '0');
    }
  }, [focus]);

  // Dossier aggregate fetch
  const dossierRequest = useMemo(() => {
    if (!identifierField || !identifierValue || !timeRange) return null;
    return {
      identifier_field: identifierField,
      identifier_value: identifierValue,
      identities,
      time_range: timeRange,
    };
  }, [identifierField, identifierValue, identities, timeRange]);
  const { data: dossier, loading: dossierLoading } = useAssetDossier(dossierRequest);

  // Entity context (risk + alerts + cases) fetched in parallel from nanosiem-api
  const [entityContext, setEntityContext] = useState<EntityContextResponse | null>(null);
  useEffect(() => {
    if (!identifierField || !identifierValue) return;
    const entityType = mapFieldToEntityType(identifierField);
    const idValues: string[] = [];
    for (const id of identities) {
      const ip = (id.ip as string) ?? '';
      const hostname = (id.hostname as string) ?? '';
      const user = (id.user as string) ?? '';
      if (ip && !idValues.includes(ip)) idValues.push(ip);
      if (hostname && !idValues.includes(hostname)) idValues.push(hostname);
      if (user && !idValues.includes(user)) idValues.push(user);
    }

    api
      .getEntityContext(entityType, identifierValue, idValues.length ? idValues : undefined)
      .then(setEntityContext)
      .catch(() => {
        /* context is supplementary — fail silently */
      });
  }, [identifierField, identifierValue, identities]);

  if (!primary) {
    return (
      <div className="p-8 text-center text-[12px] text-muted-foreground/70 font-mono">
        Asset view requires an | asset command with a resolved identifier.
      </div>
    );
  }

  const kindLabel = kind === 'host' ? 'host dossier' : 'user dossier';
  const spanLabel = labelForRange(timeRange);
  const lastObservationLabel = dossier?.identity.last_seen_in_range
    ? formatTimestampHMS(dossier.identity.last_seen_in_range)
    : undefined;
  const resolvedSourcesLabel = dossier?.identity.log_sources.length
    ? `identity resolved from ${dossier.identity.log_sources.length} sources`
    : undefined;

  return (
    <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
      <AssetTopStrip
        entityField={identifierField}
        entityValue={identifierValue}
        kindLabel={kindLabel}
        fieldsCount={fieldsCollapsedCount}
        onExpandFields={onExpandFields}
        focus={focus}
        onToggleFocus={() => setFocus((f) => !f)}
        resolvedSourcesLabel={resolvedSourcesLabel}
        lastObservationLabel={lastObservationLabel}
      />

      <div className="flex-1 min-w-0 overflow-y-auto overflow-x-hidden">
        <div className="px-4 py-4 space-y-4 min-w-0">
          {!focus && (
            <>
              <AssetIdentityHeader
                kind={kind}
                entityValue={identifierValue}
                entityField={identifierField}
                onInvestigate={onDrilldown}
                identity={
                  dossier?.identity ?? {
                    hostname: null,
                    ip: null,
                    mac: null,
                    user: null,
                    vendor_product: null,
                    first_seen_in_range: null,
                    last_seen_in_range: null,
                    log_sources: [],
                    domain: null,
                  }
                }
                risk={entityContext?.risk ?? null}
                tags={[]}
              />

              {dossier && (
                <AssetActivityTimeline
                  timeline={dossier.timeline}
                  spanLabel={spanLabel}
                />
              )}

              <div className="grid grid-cols-2 gap-3">
                <AlertsCard
                  alerts={entityContext?.alerts ?? []}
                  total={entityContext?.alert_count}
                />
                {dossier && <ProcessesCard processes={dossier.processes} />}
                {dossier && <NetworkCard network={dossier.network} />}
                {dossier && <AuthCard auth={dossier.auth} />}
                {dossier && <FilesCard files={dossier.files} />}
                {dossier && <DnsCard dns={dossier.dns} />}
              </div>
            </>
          )}

          <AssetPrevalenceCard
            identifierField={identifierField}
            identifierValue={identifierValue}
            identities={identities}
            timeRange={timeRange}
            focus={focus}
          />

          <AssetStream
            identifierField={identifierField}
            identifierValue={identifierValue}
            identities={identities}
            timeRange={timeRange}
          />

          {dossierLoading && !dossier && (
            <div className="text-[11px] text-muted-foreground/70 font-mono">
              Loading dossier…
            </div>
          )}

          <div className="h-6" />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapFieldToEntityType(field: string): string {
  const map: Record<string, string> = {
    src_ip: 'ip',
    dest_ip: 'ip',
    src_host: 'host',
    dest_host: 'host',
    user: 'user',
    src_user: 'user',
    dest_user: 'user',
  };
  return map[field] ?? field;
}

function labelForRange(tr: TimeRange | undefined): string {
  if (!tr) return 'selected range';
  const start = new Date(tr.start).getTime();
  const end = new Date(tr.end).getTime();
  const hours = Math.max(1, Math.round((end - start) / 3_600_000));
  if (hours <= 1) return 'last hour';
  if (hours < 24) return `last ${hours}h`;
  const days = Math.round(hours / 24);
  if (days === 1) return 'last 24h';
  return `last ${days}d`;
}
