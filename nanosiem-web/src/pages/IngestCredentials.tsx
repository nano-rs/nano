// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Log Sources → Credentials. Hosted-shared tenants: per-source ingest
 * credentials (NAN-2593). Dedicated / open core: named, revocable per-sender
 * HEC / HTTP ingest tokens plus the install token (NAN-3770), and OCSF bucket
 * drop source status (NAN-3807).
 * Route: /ingestion/log-sources/credentials.
 */

import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Plus, RefreshCw } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { Button } from '@/components/ui/button';
import { IngestCredentialsTable } from '@/components/add-data/IngestCredentialsTable';
import { IngestTokensPanel } from '@/components/add-data/IngestTokensPanel';
import { LandingSourcesPanel } from '@/components/add-data/LandingSourcesPanel';
import { LogSourcesPageHeader, LogSourcesPageShell } from '@/components/add-data/LogSourcesPageShell';
import { TenzirOnlyNote } from '@/components/add-data/TenzirOnlyNote';
import { useAuth } from '@/contexts/AuthContext';
import { useIngestGate } from '@/hooks/use-capabilities';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useSharedTenant } from '@/hooks/use-shared-tenant';
import { api } from '@/lib/api';
import { describeIngestCredentialError } from '@/lib/ingest-credential-errors';
import { INGEST_CREDENTIALS_QUERY_KEY, INGEST_ENDPOINT_QUERY_KEY } from '@/lib/add-data-sources';
import { INGEST_TOKENS_QUERY_KEY } from '@/lib/api/ingest-tokens';
import { LANDING_SOURCES_QUERY_KEY } from '@/lib/api/landing-sources';

export function IngestCredentials() {
  useDocumentTitle('Ingest credentials');
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const shared = useSharedTenant();
  const { user, hasPermission } = useAuth();
  const queryClient = useQueryClient();
  const canAdd = hasPermission('log_sources:create');
  // NAN-3844: no Vector on an `install.sh --tenzir` install, so HEC / HTTP
  // ingest tokens have nothing to authenticate; the bucket drop leads.
  const { tenzirOnly, unknown: ingestUnknown } = useIngestGate();

  const list = useQuery({
    queryKey: INGEST_CREDENTIALS_QUERY_KEY,
    queryFn: () => api.listIngestCredentials(),
    enabled: shared,
    // Pending requests move without a user action; keep the list fresh while open.
    refetchInterval: (q) => (q.state.data?.requests.some((r) => r.state === 'pending') ? 5000 : false),
  });
  const endpoint = useQuery({
    queryKey: INGEST_ENDPOINT_QUERY_KEY,
    queryFn: () => api.getIngestEndpoint(),
    enabled: shared,
    staleTime: 60 * 1000,
  });

  const credentials = list.data?.credentials ?? [];
  const requests = list.data?.requests ?? [];
  const active = credentials.filter((c) => c.state === 'active').length;
  const revoked = credentials.length - active;
  const pending = requests.filter((r) => r.state === 'pending').length;

  // NAN-3250: normal document flow inside the app scroller, no fill-height
  // column with an inner min-h-0 scroll box (same fix as NAN-3248).
  return (
    <LogSourcesPageShell active="credentials" testId="ingest-credentials-page" tabs={shared}>
      <LogSourcesPageHeader
        icon={KeyRound}
        title="Ingest credentials"
        actions={<>
          <Button
            variant="outline"
            size="sm"
            className="h-7 gap-1.5 text-[11.5px]"
            onClick={() => {
              if (shared) {
                void list.refetch();
                return;
              }
              if (!tenzirOnly && !ingestUnknown) void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY });
              void queryClient.invalidateQueries({ queryKey: LANDING_SOURCES_QUERY_KEY });
            }}
          >
            <RefreshCw className="w-3 h-3" strokeWidth={1.5} /> Refresh
          </Button>
          {shared && canAdd && (
            <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={() => navigate('/ingestion/log-sources/wizard')}>
              <Plus className="w-3 h-3" strokeWidth={1.5} /> Add data
            </Button>
          )}
        </>}
        meta={shared ? <>
          <span>{active} active</span>
          <span>{revoked} revoked</span>
          <span>{pending} pending</span>
          {endpoint.data && <span className="truncate">endpoint {endpoint.data.hostname}</span>}
        </> : undefined}
      />

      <div className="overflow-x-auto px-5 py-4" data-testid="ingest-credentials-region">
        {!shared ? (
          ingestUnknown ? (
            <div className="flex items-center justify-center py-12" aria-busy="true" data-testid="ingest-mode-pending">
              <LoadingIcon className="w-5 h-5 text-muted-foreground" />
            </div>
          ) : tenzirOnly ? (
            <div className="space-y-6">
              <LandingSourcesPanel />
              <section className="space-y-2" data-testid="ingest-tokens-disabled">
                <h2 className="text-[12.5px] font-medium text-foreground">HEC / HTTP ingest tokens</h2>
                <TenzirOnlyNote />
              </section>
            </div>
          ) : (
            <div className="space-y-6">
              <IngestTokensPanel />
              <LandingSourcesPanel />
            </div>
          )
        ) : list.isLoading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingIcon className="w-5 h-5 text-muted-foreground" />
          </div>
        ) : list.error ? (
          <div className="text-[12px] text-red-500" role="alert">
            {describeIngestCredentialError(list.error).detail}
          </div>
        ) : (
          <IngestCredentialsTable
            credentials={credentials}
            requests={requests}
            currentUserId={user?.id}
            initialRevokeId={searchParams.get('revoke')}
          />
        )}
      </div>
    </LogSourcesPageShell>
  );
}

export default IngestCredentials;
