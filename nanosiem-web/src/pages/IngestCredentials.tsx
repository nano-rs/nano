// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Log Sources → Credentials (main's NAN-2593 page; NAN-4922 on the ClickHouse
 * product). Named, revocable per-source HEC / HTTP / OTLP ingest tokens plus
 * the install token (NAN-4907): the token decides the source.
 * Route: /ingestion/log-sources/credentials (the old /ingestion/ingest-tokens redirects here).
 *
 * Main's hosted-shared credential table (sealed platform credentials) and the
 * Tenzir bucket-drop panel are lake-only and not part of this product.
 *
 * NAN-4941: the push listener configurations (HTTP, Vector, OTLP, HEC routing
 * profiles) that used to sit on the Source Configs page live here too, next
 * to the tokens those listeners accept.
 */

import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Plus, RefreshCw } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { IngestTokensPanel } from '@/components/add-data/IngestTokensPanel';
import { LogSourcesPageHeader, LogSourcesPageShell } from '@/components/add-data/LogSourcesPageShell';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { api } from '@/lib/api';
import { ADD_DATA_PATH, INGEST_ENDPOINT_QUERY_KEY } from '@/lib/add-data-sources';
import { INGEST_TOKENS_QUERY_KEY } from '@/lib/api/ingest-tokens';
import { LISTENER_CONFIG_TYPES } from '@/lib/ingestion-paths';
import { SourceConfigsPanel } from '@/components/source-configs/SourceConfigsPanel';

export function IngestCredentials() {
  useDocumentTitle('Ingest credentials');
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();
  const canAdd = hasPermission('log_sources:create');
  const canTokens = hasPermission('log_sources:view');
  const tokens = useQuery({ queryKey: INGEST_TOKENS_QUERY_KEY, queryFn: () => api.ingestTokens.list(), enabled: canTokens });
  const endpoint = useQuery({ queryKey: INGEST_ENDPOINT_QUERY_KEY, queryFn: () => api.getIngestEndpoint(), staleTime: 60 * 1000, retry: 1, enabled: canTokens });
  const list = tokens.data?.tokens ?? [];
  const active = list.filter((t) => t.state === 'active').length;
  const unbound = list.filter((t) => t.state === 'unbound').length;
  const revoked = list.filter((t) => t.state === 'revoked').length;

  return (
    <LogSourcesPageShell active="credentials" testId="ingest-credentials-page">
      <LogSourcesPageHeader
        icon={KeyRound}
        title="Ingest credentials"
        actions={<>
          <Button
            variant="outline"
            size="sm"
            className="h-7 gap-1.5 text-[11.5px]"
            onClick={() => {
              void queryClient.invalidateQueries({ queryKey: INGEST_TOKENS_QUERY_KEY });
              void queryClient.invalidateQueries({ queryKey: INGEST_ENDPOINT_QUERY_KEY });
            }}
          >
            <RefreshCw className="w-3 h-3" strokeWidth={1.5} /> Refresh
          </Button>
          {canAdd && (
            <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={() => navigate(ADD_DATA_PATH)}>
              <Plus className="w-3 h-3" strokeWidth={1.5} /> Add source
            </Button>
          )}
        </>}
        meta={tokens.isSuccess ? <>
          <span>{active} active</span>
          <span>{unbound} unbound</span>
          <span>{revoked} revoked</span>
          <span>install token {tokens.data?.install_token.state.replace(/_/g, ' ')}</span>
          {endpoint.data && <span className="truncate">endpoint {endpoint.data.hostname}</span>}
        </> : undefined}
      />

      <div className="overflow-x-auto px-5 py-4 space-y-4" data-testid="ingest-credentials-region">
        {canTokens && <IngestTokensPanel />}
        {hasPermission('source_configs:view') && (
          <SourceConfigsPanel
            types={LISTENER_CONFIG_TYPES}
            title="Push listeners"
            description="Routing profiles over Vector's HTTP, Vector, OTLP and HEC listeners. Most sources never need one: a token already decides the source. Add one to route by a field instead."
            addLabel="Add listener"
            testId="push-listeners"
          />
        )}
      </div>
    </LogSourcesPageShell>
  );
}

export default IngestCredentials;
