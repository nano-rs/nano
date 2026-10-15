// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Log Sources → Cloud pull (hosted-shared tenants, NAN-3596 / NAN-3288).
 * Route: /ingestion/log-sources/cloud-pull. Also reached from the Marketplace
 * "Cloud pull" card. nano reads the tenant's SQS queue (and the S3 objects it
 * announces) with a role the tenant creates, or its Pub/Sub subscription as
 * the tenant's nano service account (NAN-3598), or its Azure event hub as the
 * tenant's own Entra app via a federated credential (NAN-3604); no keys or
 * secrets are exchanged.
 */

import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { ChevronRight, CloudDownload, Plus, RefreshCw } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { Button } from '@/components/ui/button';
import { LogSourcesTabs } from '@/components/add-data/LogSourcesTabs';
import { CloudPullAzureForm } from '@/components/cloud-pull/CloudPullAzureForm';
import { CloudPullAzureSetup } from '@/components/cloud-pull/CloudPullAzureSetup';
import { CloudPullForm } from '@/components/cloud-pull/CloudPullForm';
import { CloudPullGcpForm } from '@/components/cloud-pull/CloudPullGcpForm';
import { CloudPullGcpSetup } from '@/components/cloud-pull/CloudPullGcpSetup';
import { CloudPullSetup } from '@/components/cloud-pull/CloudPullSetup';
import { CloudPullTable } from '@/components/cloud-pull/CloudPullTable';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useSharedTenant } from '@/hooks/use-shared-tenant';
import { useToast } from '@/hooks/use-toast';
import {
  isPullNotEnabled,
  useCreatePullSource,
  usePullSourceAwsSetup,
  usePullSourceAzureSetup,
  usePullSourceGcpSetup,
  usePullSources,
} from '@/hooks/use-pull-sources';
import { usePipeInputSummary } from '@/hooks/use-pipe-inputs';
import { api, ApiClientError } from '@/lib/api';
import { pipelinesForSlug } from '@/lib/api/pipelines';
import { PULL_SETUP_UNAVAILABLE, type CreatePullSourceRequest } from '@/lib/api/pull-sources';
import { azureCreateError, gcpSubscriptionProblem, type PullParser } from '@/lib/cloud-pull';
import { addDataSources, INGEST_ENDPOINT_QUERY_KEY, issuableSlugs } from '@/lib/add-data-sources';
import { cn } from '@/lib/utils';

type Provider = 'aws' | 'gcp' | 'azure';

const PROVIDERS: { id: Provider; label: string; setup: string }[] = [
  { id: 'aws', label: 'AWS S3 + SQS', setup: 'AWS setup' },
  { id: 'gcp', label: 'GCP Pub/Sub', setup: 'GCP setup' },
  { id: 'azure', label: 'Azure Event Hubs', setup: 'Azure setup' },
];

function ProviderToggle({ value, disabled, onChange }: { value: Provider; disabled?: boolean; onChange: (value: Provider) => void }) {
  return (
    <div role="radiogroup" aria-label="Cloud provider" className="inline-flex h-7 rounded-md border border-border overflow-hidden" data-testid="cloud-pull-provider-toggle">
      {PROVIDERS.map((p, i) => (
        <button
          key={p.id}
          type="button"
          role="radio"
          aria-checked={value === p.id}
          disabled={disabled}
          onClick={() => onChange(p.id)}
          className={cn(
            'px-2.5 font-mono text-[11px] disabled:opacity-50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-primary',
            i > 0 && 'border-l border-border',
            value === p.id ? 'bg-accent text-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-accent/50',
          )}
        >
          {p.label}
        </button>
      ))}
    </div>
  );
}

/** The setup panel's subscription, once it validates and has settled for 300 ms. */
function useSettledSubscription(value: string): string | undefined {
  const [settled, setSettled] = useState<string | undefined>(undefined);
  useEffect(() => {
    const trimmed = value.trim();
    const next = trimmed && !gcpSubscriptionProblem(trimmed) ? trimmed : undefined;
    const timer = setTimeout(() => setSettled(next), next ? 300 : 0);
    return () => clearTimeout(timer);
  }, [value]);
  return settled;
}

/** The setup's ack-deadline bounds when well-formed; otherwise the form keeps the server's documented 10-600. */
function ackBounds(b: { min: number; max: number } | undefined): { min: number; max: number } | undefined {
  return b && Number.isInteger(b.min) && Number.isInteger(b.max) && b.min > 0 && b.min <= b.max ? b : undefined;
}

export function CloudPull() {
  useDocumentTitle('Cloud pull');
  const shared = useSharedTenant();
  const { hasPermission } = useAuth();
  const canAdd = hasPermission('log_sources:create');
  const { toast } = useToast();

  const list = usePullSources({ enabled: shared, poll: true });
  // NAN-3621: each pull source links back to the pipeline whose lane it feeds.
  const pipeLanes = usePipeInputSummary({ enabled: shared });
  const notEnabled = isPullNotEnabled(list.error);
  // NAN-3661: the Log Source Delivery panel deep-links `?provider=gcp` to open the setup that fixes an error.
  const [searchParams] = useSearchParams();
  const [provider, setProvider] = useState<Provider>(() => {
    const requested = searchParams.get('provider');
    return PROVIDERS.some((p) => p.id === requested) ? (requested as Provider) : 'aws';
  });
  const providerInfo = PROVIDERS.find((p) => p.id === provider) ?? PROVIDERS[0];
  // Asked only once the list proves the tenant is admitted, and only for the selected provider.
  const awsSetup = usePullSourceAwsSetup({ enabled: shared && list.isSuccess && provider === 'aws' });
  const gcpSetup = usePullSourceGcpSetup({ enabled: shared && list.isSuccess && provider === 'gcp' });
  const [gcpSubscription, setGcpSubscription] = useState('');
  const settledSubscription = useSettledSubscription(gcpSubscription);
  const gcpFilled = usePullSourceGcpSetup({
    enabled: shared && list.isSuccess && provider === 'gcp' && !!settledSubscription,
    subscription: settledSubscription,
  });
  const azureSetup = usePullSourceAzureSetup({ enabled: shared && list.isSuccess && provider === 'azure' });
  const setup = provider === 'aws' ? awsSetup : provider === 'gcp' ? gcpSetup : azureSetup;
  const setupNotEnabled = isPullNotEnabled(setup.error);
  // A refused subscription (400, e.g. a nano-owned project) keeps the placeholder commands.
  const filledActive = !!settledSubscription && settledSubscription === gcpSubscription.trim();
  const gcpSetupData = (filledActive && gcpFilled.data) || gcpSetup.data;
  const gcpSubscriptionError = filledActive && gcpFilled.error instanceof ApiClientError && gcpFilled.error.status === 400
    ? gcpFilled.error.message
    : null;
  const create = useCreatePullSource();

  const [adding, setAdding] = useState(false);
  const [setupOpen, setSetupOpen] = useState<boolean | null>(null);

  // Lanes: the slugs enrolled on the tenant's parser cell (same source list as Add data).
  // Also read for the table (NAN-3657 / NAN-3658: which parser each source feeds, and whether it is deployed).
  const endpoint = useQuery({
    queryKey: INGEST_ENDPOINT_QUERY_KEY,
    queryFn: () => api.getIngestEndpoint(),
    enabled: shared && (adding || list.isSuccess),
    staleTime: 60 * 1000,
  });
  const registry = useQuery({
    queryKey: ['add-data', 'log-sources'],
    queryFn: () => api.listLogSources(),
    enabled: shared && (adding || list.isSuccess),
    staleTime: 30 * 1000,
  });
  const parsers = useMemo(
    () => (endpoint.isSuccess ? addDataSources(endpoint.data, registry.data) : null),
    [endpoint.isSuccess, endpoint.data, registry.data],
  );
  const lanes = useMemo(
    () => (parsers ? issuableSlugs(parsers.filter((s) => s.enrolled).map((s) => s.slug)) : null),
    [parsers],
  );
  const parserFor = (slug: string): PullParser => {
    const name = parsers?.find((p) => p.slug === slug)?.logSource?.name;
    return { name, deployed: lanes ? lanes.includes(slug) : null };
  };

  const sources = list.data ?? [];
  const count = (pred: (s: (typeof sources)[number]) => boolean) => sources.filter(pred).length;
  const active = count((s) => s.state === 'active');
  const pending = count((s) => s.state === 'pending_verification' || s.state === 'pending_bundle');
  const failed = count((s) => s.state === 'failed');
  const paused = count((s) => s.state === 'paused');
  const showSetup = setupOpen ?? (list.isSuccess && sources.length === 0);
  const disabled = notEnabled || setupNotEnabled;

  const cancelAdd = () => { setAdding(false); create.reset(); };
  const submit = (request: CreatePullSourceRequest) => create.mutate(request, {
    onSuccess: (created) => {
      setAdding(false);
      create.reset();
      toast({
        title: 'Pull source added',
        description: created.provider === 'gcp_pubsub'
          ? `${created.name} is verifying: nano checks that it can read the subscription.`
          : created.provider === 'azure_event_hubs'
            ? `${created.name} is verifying: nano signs in as your app and checks the hub and checkpoint container.`
            : `${created.name} is verifying: nano assumes the role and reads the queue.`,
      });
    },
  });

  return (
    <div className="flex flex-col min-h-full -m-3 bg-background" data-testid="cloud-pull-page">
      {shared && <LogSourcesTabs active="cloud-pull" />}
      <div className="shrink-0 border-b border-border px-5 py-3">
        <div className="flex items-center gap-2.5">
          <CloudDownload className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} />
          <h1 className="text-[16px] font-semibold tracking-[-0.01em] text-foreground">Cloud pull</h1>
          <span className="flex-1" />
          <Button variant="outline" size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={() => void list.refetch()} disabled={!shared || disabled}>
            <RefreshCw className="w-3 h-3" strokeWidth={1.5} /> Refresh
          </Button>
          {canAdd && shared && !disabled && (
            <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={() => setAdding(true)} disabled={adding}>
              <Plus className="w-3 h-3" strokeWidth={1.5} /> Add source
            </Button>
          )}
        </div>
        <div className="flex items-center gap-4 mt-1.5 font-mono text-[10.5px] text-muted-foreground tabular-nums">
          <span data-testid="cloud-pull-provider-label">{providerInfo.label}</span>
          {!disabled && list.isSuccess && (
            <>
              <span>{active} active</span>
              <span>{pending} pending</span>
              <span>{paused} paused</span>
              <span className={cn(failed > 0 && 'text-red-500')}>{failed} failed</span>
            </>
          )}
        </div>
      </div>

      <div className="overflow-x-auto px-5 py-4 space-y-4" data-testid="cloud-pull-region">
        {/* Outside the gate below so a provider whose setup is refused can be switched away from. */}
        {shared && list.isSuccess && !notEnabled && (
          <ProviderToggle value={provider} disabled={create.isPending} onChange={(next) => { setProvider(next); create.reset(); }} />
        )}
        {!shared ? (
          <div className="text-[12px] text-muted-foreground">
            Cloud pull runs on hosted deployments. This deployment reads cloud queues through Source Configs.
          </div>
        ) : disabled ? (
          <div className="text-[12px] text-muted-foreground" data-testid="cloud-pull-not-enabled">
            Cloud pull is not enabled for this tenant.
          </div>
        ) : list.isLoading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingIcon className="w-5 h-5 text-muted-foreground" />
          </div>
        ) : list.error ? (
          <div className="text-[12px] text-red-500" role="alert">Could not load pull sources: {list.error.message}</div>
        ) : (
          <>
            <section>
              <button
                type="button"
                aria-expanded={showSetup}
                onClick={() => setSetupOpen(!showSetup)}
                className="flex items-center gap-1.5 h-7 font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground hover:text-foreground"
              >
                <ChevronRight className={cn('w-3 h-3 transition-transform', showSetup && 'rotate-90')} strokeWidth={1.5} />
                {providerInfo.setup}
              </button>
              {showSetup && (
                <div className="mt-1.5">
                  {setup.isLoading ? (
                    <LoadingIcon className="w-4 h-4 text-muted-foreground" />
                  ) : provider === 'aws' && awsSetup.data ? (
                    <CloudPullSetup setup={awsSetup.data} />
                  ) : provider === 'azure' && azureSetup.data ? (
                    <CloudPullAzureSetup setup={azureSetup.data} />
                  ) : provider === 'gcp' && gcpSetupData ? (
                    <CloudPullGcpSetup
                      setup={gcpSetupData}
                      subscription={gcpSubscription}
                      onSubscriptionChange={setGcpSubscription}
                      subscriptionError={gcpSubscriptionError}
                    />
                  ) : (
                    <div className="text-[11.5px] text-muted-foreground" role="status">
                      {setup.error instanceof ApiClientError && setup.error.code === PULL_SETUP_UNAVAILABLE
                        ? 'Setup details are unavailable right now. Existing sources keep running; try again shortly.'
                        : `Could not load setup details${setup.error ? `: ${setup.error.message}` : ''}`}
                    </div>
                  )}
                </div>
              )}
            </section>
            {adding && provider === 'aws' && (
              <CloudPullForm
                lanes={lanes}
                busy={create.isPending}
                serverError={create.error?.message ?? null}
                onCancel={cancelAdd}
                onSubmit={submit}
              />
            )}
            {adding && provider === 'gcp' && (
              <CloudPullGcpForm
                lanes={lanes}
                busy={create.isPending}
                serverError={create.error?.message ?? null}
                initialSubscription={gcpSubscription.trim()}
                ackBounds={ackBounds(gcpSetupData?.ack_deadline_secs)}
                defaultSourceSlug={gcpSetupData?.default_source_slug || undefined}
                onCancel={cancelAdd}
                onSubmit={submit}
              />
            )}
            {adding && provider === 'azure' && (
              <CloudPullAzureForm
                lanes={lanes}
                busy={create.isPending}
                serverError={azureCreateError(create.error)}
                onServerErrorClear={() => create.reset()}
                onCancel={cancelAdd}
                onSubmit={submit}
              />
            )}
            <CloudPullTable sources={sources} parserFor={parserFor} pipelineFor={(slug) => pipelinesForSlug(pipeLanes.data ?? undefined, slug)[0]} />
          </>
        )}
      </div>
    </div>
  );
}

export default CloudPull;
