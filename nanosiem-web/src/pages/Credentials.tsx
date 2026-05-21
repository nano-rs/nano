// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  Eye,
  EyeOff,
  History,
  KeyRound,
  Loader2,
  Lock,
  Plug,
  Plus,
  Radio,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Undo2,
} from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
} from '@/components/ui/sheet';
import { VisuallyHidden } from '@radix-ui/react-visually-hidden';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type {
  AwsS3Credentials,
  CloudCredential,
  CloudCredentialVersion,
  CreateCloudCredentialRequest,
  CredentialEnvironment,
  GcpPubSubCredentials,
  KafkaCredentials,
  RotateCredentialRequest,
  SourceConfiguration,
  UpdateCloudCredentialRequest,
} from '@/lib/api';
import { cn } from '@/lib/utils';

type Provider = 'aws_s3' | 'gcp_pubsub' | 'kafka';
type ProviderFilter = 'all' | Provider;
type EnvironmentFilter = 'all' | CredentialEnvironment;
type InspectorTab = 'overview' | 'versions' | 'usage' | 'danger';
type Health = 'healthy' | 'expires-soon' | 'expired' | 'unknown';

// Pre-fill profiles for the three biggest cloud Kafka offerings.
// Selecting a preset sets mechanism + TLS + username placeholder so users don't
// have to hunt through the cloud vendor's docs for the right combination.
// "self_hosted" leaves everything blank for full manual control.
type KafkaPresetId = 'confluent' | 'event_hubs' | 'msk_scram' | 'self_hosted';
interface KafkaPreset {
  id: KafkaPresetId;
  label: string;
  mechanism: 'PLAIN' | 'SCRAM-SHA-256' | 'SCRAM-SHA-512' | '_none';
  tls: boolean;
  usernamePlaceholder: string;
  passwordPlaceholder: string;
  hint: string;
}
const KAFKA_PRESETS: KafkaPreset[] = [
  {
    id: 'confluent',
    label: 'Confluent Cloud',
    mechanism: 'PLAIN',
    tls: true,
    usernamePlaceholder: 'API key (e.g. ABCDEF1234567890)',
    passwordPlaceholder: 'API secret',
    hint: 'PLAIN over SASL_SSL with your Confluent API key as username.',
  },
  {
    id: 'event_hubs',
    label: 'Azure Event Hubs',
    mechanism: 'PLAIN',
    tls: true,
    usernamePlaceholder: '$ConnectionString',
    passwordPlaceholder: 'Endpoint=sb://…;SharedAccessKeyName=…;SharedAccessKey=…',
    hint: 'Username is the literal $ConnectionString; password is the Event Hub SAS connection string.',
  },
  {
    id: 'msk_scram',
    label: 'AWS MSK (SCRAM)',
    mechanism: 'SCRAM-SHA-512',
    tls: true,
    usernamePlaceholder: 'msk-scram-user',
    passwordPlaceholder: 'SCRAM password from AWS Secrets Manager',
    hint: 'SCRAM-SHA-512 over SASL_SSL. MSK IAM auth is not yet supported — use SCRAM at MSK cluster creation.',
  },
  {
    id: 'self_hosted',
    label: 'Self-hosted / other',
    mechanism: '_none',
    tls: false,
    usernamePlaceholder: 'logs-consumer',
    passwordPlaceholder: '',
    hint: 'Configure mechanism + TLS manually. Leave SASL as None for unauthenticated brokers.',
  },
];
const KAFKA_PRESET_BY_ID: Record<KafkaPresetId, KafkaPreset> = Object.fromEntries(
  KAFKA_PRESETS.map((p) => [p.id, p]),
) as Record<KafkaPresetId, KafkaPreset>;

interface HealthBadge {
  label: string;
  dot: string;
  text: string;
  bg: string;
}

const HEALTH_BADGES: Record<Health, HealthBadge> = {
  healthy: {
    label: 'Healthy',
    dot: 'bg-emerald-500',
    text: 'text-emerald-500',
    bg: 'bg-emerald-500/12',
  },
  'expires-soon': {
    label: 'Expires soon',
    dot: 'bg-amber-500',
    text: 'text-amber-600 dark:text-amber-400',
    bg: 'bg-amber-500/12',
  },
  expired: {
    label: 'Expired',
    dot: 'bg-red-500',
    text: 'text-red-500',
    bg: 'bg-red-500/12',
  },
  unknown: {
    label: 'Unknown',
    dot: 'bg-foreground/30',
    text: 'text-muted-foreground',
    bg: 'bg-foreground/[0.05]',
  },
};

const ENV_BADGE: Record<CredentialEnvironment, string> = {
  prod: 'bg-primary/15 text-primary',
  staging: 'bg-foreground/[0.06] text-foreground/80',
  dev: 'bg-foreground/[0.04] text-muted-foreground',
};

const MS_PER_DAY = 86_400_000;

function deriveHealth(expiresAt: string | null | undefined): Health {
  if (!expiresAt) return 'unknown';
  const ts = new Date(expiresAt).getTime();
  if (!Number.isFinite(ts)) return 'unknown';
  const diffDays = Math.floor((ts - Date.now()) / MS_PER_DAY);
  if (diffDays < 0) return 'expired';
  if (diffDays <= 30) return 'expires-soon';
  return 'healthy';
}

function daysUntil(expiresAt: string | null | undefined): number | null {
  if (!expiresAt) return null;
  const ts = new Date(expiresAt).getTime();
  if (!Number.isFinite(ts)) return null;
  return Math.floor((ts - Date.now()) / MS_PER_DAY);
}

/** ISO timestamp → `YYYY-MM-DD` for `<input type="date">`. */
function isoToDateInput(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(0, 10);
}

/** `YYYY-MM-DD` → midnight-UTC ISO timestamp the backend can parse. */
function dateInputToIso(date: string): string | undefined {
  if (!date) return undefined;
  return `${date}T00:00:00Z`;
}

interface ProviderSpec {
  value: Provider;
  label: string;
  short: string;
  icon: React.ComponentType<{ className?: string }>;
  iconClass: string;
  description: string;
}

const PROVIDERS: ProviderSpec[] = [
  {
    value: 'aws_s3',
    label: 'AWS S3',
    short: 'AWS',
    icon: Cloud,
    iconClass: 'text-orange-400',
    description: 'Access key + secret for reading CloudTrail, ALB, VPC Flow from S3.',
  },
  {
    value: 'gcp_pubsub',
    label: 'GCP Pub/Sub',
    short: 'GCP',
    icon: Server,
    iconClass: 'text-sky-400',
    description: 'Service account JSON for pulling from subscriptions.',
  },
  {
    value: 'kafka',
    label: 'Kafka',
    short: 'Kafka',
    icon: Radio,
    iconClass: 'text-emerald-400',
    description: 'Bootstrap servers + SASL credentials for topic subscription.',
  },
];

const PROVIDER_BY_VALUE = new Map(PROVIDERS.map((p) => [p.value, p]));

const providerSpec = (value: string): ProviderSpec =>
  PROVIDER_BY_VALUE.get(value as Provider) ?? {
    value: value as Provider,
    label: value,
    short: value,
    icon: KeyRound,
    iconClass: 'text-muted-foreground',
    description: '',
  };

const formatRelative = (iso: string): string => {
  const ts = new Date(iso).getTime();
  if (!Number.isFinite(ts)) return '—';
  const diff = Date.now() - ts;
  const mins = Math.round(diff / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.round(months / 12)}y ago`;
};

const formatUtc = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().slice(0, 16).replace('T', ' ');
};

export function Credentials() {
  useDocumentTitle('Credentials');

  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { hasPermission } = useAuth();

  const canCreate = hasPermission('credentials:create');
  const canEdit = hasPermission('credentials:edit');
  const canDelete = hasPermission('credentials:delete');
  const canRotate = hasPermission('credentials:rotate');

  const params = useParams<{ id?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();

  const [searchQuery, setSearchQuery] = useState('');
  const [providerFilter, setProviderFilter] = useState<ProviderFilter>('all');
  const [envFilter, setEnvFilter] = useState<EnvironmentFilter>('all');
  const [openId, setOpenId] = useState<string | null>(() => params.id ?? searchParams.get('cred'));
  const [addOpen, setAddOpen] = useState<boolean>(() => searchParams.has('add'));
  const [addProvider, setAddProvider] = useState<Provider>(() => {
    const fromQuery = searchParams.get('add');
    if (fromQuery && PROVIDER_BY_VALUE.has(fromQuery as Provider)) return fromQuery as Provider;
    return 'aws_s3';
  });
  const [rotateForId, setRotateForId] = useState<string | null>(null);

  // Open inspector when navigating from a deep-link `/ingestion/credentials/:id`
  // (legacy detail route — redirected here in App.tsx).
  useEffect(() => {
    if (params.id) {
      setOpenId(params.id);
      navigate('/ingestion/credentials', { replace: true });
    }
  }, [params.id, navigate]);

  // Strip the `?add=` / `?cred=` params after we've consumed them so reload
  // doesn't trap the user in an open modal/drawer.
  useEffect(() => {
    if (searchParams.has('add') || searchParams.has('cred')) {
      const next = new URLSearchParams(searchParams);
      next.delete('add');
      next.delete('cred');
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const { data: credentials = [], isLoading, refetch } = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.listCredentials().then((r) => r.credentials),
  });

  const { data: sourceConfigs = [] } = useQuery({
    queryKey: ['sourceConfigs'],
    queryFn: () => api.listSourceConfigs(),
  });

  const usageByCredential = useMemo(() => {
    const map = new Map<string, SourceConfiguration[]>();
    for (const config of sourceConfigs) {
      if (!config.credential_id) continue;
      const list = map.get(config.credential_id) ?? [];
      list.push(config);
      map.set(config.credential_id, list);
    }
    return map;
  }, [sourceConfigs]);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return credentials.filter((c) => {
      if (providerFilter !== 'all' && c.provider !== providerFilter) return false;
      if (envFilter !== 'all' && c.environment !== envFilter) return false;
      if (!q) return true;
      const hay = [
        c.name,
        c.description ?? '',
        c.region ?? '',
        c.environment ?? '',
        providerSpec(c.provider).label,
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }, [credentials, searchQuery, providerFilter, envFilter]);

  const stats = useMemo(() => {
    const inUse = credentials.reduce(
      (acc, c) => acc + (usageByCredential.get(c.id)?.length ?? 0),
      0,
    );
    let expiresSoon = 0;
    let expired = 0;
    for (const c of credentials) {
      const h = deriveHealth(c.expires_at);
      if (h === 'expires-soon') expiresSoon += 1;
      if (h === 'expired') expired += 1;
    }
    return { total: credentials.length, inUse, expiresSoon, expired };
  }, [credentials, usageByCredential]);

  const opened = openId ? credentials.find((c) => c.id === openId) ?? null : null;

  // If the open id no longer matches any credential (e.g. just deleted), close
  // the drawer so we don't leave an empty rail.
  useEffect(() => {
    if (openId && !isLoading && credentials.length > 0 && !opened) {
      setOpenId(null);
    }
  }, [openId, opened, credentials.length, isLoading]);

  const createMutation = useMutation({
    mutationFn: (request: CreateCloudCredentialRequest) => api.createCredential(request),
    onSuccess: (cred) => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      toast({
        title: 'Credential created',
        description: `${cred.name} has been saved securely.`,
      });
      setAddOpen(false);
      setOpenId(cred.id);
    },
    onError: (error) => {
      toast({
        title: 'Failed to create credential',
        description: error instanceof Error ? error.message : String(error),
        variant: 'destructive',
      });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateCloudCredentialRequest }) =>
      api.updateCredential(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      toast({ title: 'Credential updated' });
    },
    onError: (error) => {
      toast({
        title: 'Failed to update credential',
        description: error instanceof Error ? error.message : String(error),
        variant: 'destructive',
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteCredential(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      toast({ title: 'Credential deleted' });
      if (openId === id) setOpenId(null);
    },
    onError: (error) => {
      toast({
        title: 'Failed to delete credential',
        description: error instanceof Error ? error.message : String(error),
        variant: 'destructive',
      });
    },
  });

  const rotateMutation = useMutation({
    mutationFn: ({ id, request }: { id: string; request: RotateCredentialRequest }) =>
      api.rotateCredential(id, request),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      queryClient.invalidateQueries({
        queryKey: ['credentialVersions', response.credential.id],
      });
      toast({
        title: 'Credential rotated',
        description: `${response.credential.name} is now on v${response.version.version_number}.`,
      });
      setRotateForId(null);
    },
    onError: (error) => {
      toast({
        title: 'Failed to rotate credential',
        description: error instanceof Error ? error.message : String(error),
        variant: 'destructive',
      });
    },
  });

  const rollbackMutation = useMutation({
    mutationFn: ({ id, version }: { id: string; version: number }) =>
      api.rollbackCredential(id, { version }),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      queryClient.invalidateQueries({
        queryKey: ['credentialVersions', response.credential.id],
      });
      toast({
        title: 'Credential rolled back',
        description: `${response.credential.name} is now on v${response.version.version_number}.`,
      });
    },
    onError: (error) => {
      toast({
        title: 'Failed to roll back credential',
        description: error instanceof Error ? error.message : String(error),
        variant: 'destructive',
      });
    },
  });

  const rotateTarget = rotateForId ? credentials.find((c) => c.id === rotateForId) ?? null : null;

  return (
    <div className="-m-3 flex h-[calc(100%+1.5rem)] min-h-0 flex-col overflow-hidden [contain:layout]">
      <HeroStrip stats={stats} />

      <Toolbar
        query={searchQuery}
        onQueryChange={setSearchQuery}
        provider={providerFilter}
        onProviderChange={setProviderFilter}
        env={envFilter}
        onEnvChange={setEnvFilter}
        resultsCount={filtered.length}
        totalCount={credentials.length}
        onRefresh={refetch}
        canCreate={canCreate}
        onAdd={() => setAddOpen(true)}
      />

      <div className="flex-1 min-h-0 overflow-auto">
        {isLoading ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : credentials.length === 0 ? (
          <EmptyState
            canCreate={canCreate}
            onPick={(p) => {
              setAddProvider(p);
              setAddOpen(true);
            }}
          />
        ) : filtered.length === 0 ? (
          <NoResults
            query={searchQuery}
            onReset={() => {
              setSearchQuery('');
              setProviderFilter('all');
              setEnvFilter('all');
            }}
          />
        ) : (
          <CredentialsTable
            rows={filtered}
            activeId={openId}
            usageByCredential={usageByCredential}
            onOpen={setOpenId}
          />
        )}
      </div>

      {/* Inspector — non-modal so the table behind stays interactive (matches mockup intent). */}
      <Sheet
        modal={false}
        open={!!opened}
        onOpenChange={(next) => {
          if (!next) setOpenId(null);
        }}
      >
        <SheetContent
          side="right"
          className="w-[480px] sm:max-w-[480px] gap-0 p-0 bg-card border-l border-border text-foreground flex flex-col"
          onInteractOutside={(e) => e.preventDefault()}
          onPointerDownOutside={(e) => e.preventDefault()}
        >
          <VisuallyHidden>
            <SheetTitle>{opened?.name ?? 'Credential'}</SheetTitle>
            <SheetDescription>
              View and edit credential details, usage, and danger-zone actions.
            </SheetDescription>
          </VisuallyHidden>
          {opened && (
            <Inspector
              cred={opened}
              usage={usageByCredential.get(opened.id) ?? []}
              canEdit={canEdit}
              canDelete={canDelete}
              canRotate={canRotate}
              onUpdate={(data) => updateMutation.mutate({ id: opened.id, data })}
              updating={updateMutation.isPending}
              onDelete={() => deleteMutation.mutate(opened.id)}
              deleting={deleteMutation.isPending}
              onRotate={() => setRotateForId(opened.id)}
              onRollback={(version) =>
                rollbackMutation.mutate({ id: opened.id, version })
              }
              rollingBack={rollbackMutation.isPending}
            />
          )}
        </SheetContent>
      </Sheet>

      {/* Add credential — modal Sheet; matches NAN-529 AddSourceSheet pattern. */}
      <Sheet open={addOpen} onOpenChange={setAddOpen}>
        <SheetContent
          side="right"
          className="w-[560px] sm:max-w-[560px] gap-0 p-0 bg-card border-l border-border text-foreground flex flex-col"
        >
          <VisuallyHidden>
            <SheetTitle>Add credential</SheetTitle>
            <SheetDescription>
              Encrypted with AES-256-GCM before storage. Secret values are never returned in plain
              text.
            </SheetDescription>
          </VisuallyHidden>
          <AddCredentialForm
            key={addOpen ? `open-${addProvider}` : 'closed'}
            initialProvider={addProvider}
            submitting={createMutation.isPending}
            onCancel={() => setAddOpen(false)}
            onSubmit={(req) => createMutation.mutate(req)}
          />
        </SheetContent>
      </Sheet>

      {/* Rotate credential — modal Sheet, only shows the secret fields for the
          credential's provider. New version becomes active on success. */}
      <Sheet
        open={!!rotateTarget}
        onOpenChange={(next) => {
          if (!next) setRotateForId(null);
        }}
      >
        <SheetContent
          side="right"
          className="w-[520px] sm:max-w-[520px] gap-0 p-0 bg-card border-l border-border text-foreground flex flex-col"
        >
          <VisuallyHidden>
            <SheetTitle>Rotate credential{rotateTarget ? ` — ${rotateTarget.name}` : ''}</SheetTitle>
            <SheetDescription>
              Replace the secret material. The previous version stays retained for rollback.
            </SheetDescription>
          </VisuallyHidden>
          {rotateTarget && (
            <RotateCredentialForm
              cred={rotateTarget}
              submitting={rotateMutation.isPending}
              onCancel={() => setRotateForId(null)}
              onSubmit={(req) =>
                rotateMutation.mutate({ id: rotateTarget.id, request: req })
              }
            />
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

// ----- Hero strip -----

interface HeroStats {
  total: number;
  inUse: number;
  expiresSoon: number;
  expired: number;
}

function HeroStrip({ stats }: { stats: HeroStats }) {
  return (
    <div className="shrink-0 border-b border-border bg-card/40 px-5 py-4 flex items-start gap-4">
      <div className="w-[38px] h-[38px] rounded-lg border border-border bg-card flex items-center justify-center shrink-0">
        <KeyRound className="w-[18px] h-[18px] text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground">
            Credentials
          </div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-px whitespace-nowrap">
            Ingestion vault
          </span>
        </div>
        <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[740px]">
          Encrypted secrets for pull-based ingestion. Source configs reference them at deploy time —
          secrets are encrypted with AES-256-GCM and never appear in logs, exports, or API responses.
        </div>
      </div>
      <div className="hidden md:flex items-center gap-4 shrink-0">
        <HeroStat value={stats.total} label="Credentials" />
        <div className="w-px h-8 bg-border" />
        <HeroStat value={stats.inUse} label="In use" />
        <div className="w-px h-8 bg-border" />
        <HeroStat
          value={stats.expiresSoon}
          label="Expiring < 30d"
          tone={stats.expiresSoon > 0 ? 'warn' : undefined}
        />
        <div className="w-px h-8 bg-border" />
        <HeroStat
          value={stats.expired}
          label="Expired"
          tone={stats.expired > 0 ? 'danger' : undefined}
        />
      </div>
    </div>
  );
}

function HeroStat({
  value,
  label,
  tone,
}: {
  value: number | string;
  label: string;
  tone?: 'warn' | 'danger';
}) {
  return (
    <div className="flex flex-col items-end">
      <div
        className={cn(
          'font-mono text-[14px] tabular-nums',
          tone === 'warn'
            ? 'text-amber-600 dark:text-amber-400'
            : tone === 'danger'
              ? 'text-red-500'
              : 'text-foreground',
        )}
      >
        {value}
      </div>
      <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
        {label}
      </div>
    </div>
  );
}

// ----- Toolbar -----

function Toolbar({
  query,
  onQueryChange,
  provider,
  onProviderChange,
  env,
  onEnvChange,
  resultsCount,
  totalCount,
  onRefresh,
  canCreate,
  onAdd,
}: {
  query: string;
  onQueryChange: (v: string) => void;
  provider: ProviderFilter;
  onProviderChange: (id: ProviderFilter) => void;
  env: EnvironmentFilter;
  onEnvChange: (id: EnvironmentFilter) => void;
  resultsCount: number;
  totalCount: number;
  onRefresh: () => void;
  canCreate: boolean;
  onAdd: () => void;
}) {
  const providerTabs: Array<{ id: ProviderFilter; label: string }> = [
    { id: 'all', label: 'All' },
    ...PROVIDERS.map((p) => ({ id: p.value as ProviderFilter, label: p.label })),
  ];
  const envTabs: Array<{ id: EnvironmentFilter; label: string }> = [
    { id: 'all', label: 'All envs' },
    { id: 'prod', label: 'prod' },
    { id: 'staging', label: 'staging' },
    { id: 'dev', label: 'dev' },
  ];
  return (
    <div className="shrink-0 flex items-center gap-2 px-4 py-2.5 border-b border-border bg-card/40 flex-wrap">
      <div className="relative">
        <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
        <Input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search name, description, region…"
          className="h-8 pl-8 w-[300px] text-[12px] bg-card"
        />
      </div>
      <SegmentedTabs
        value={provider}
        onChange={onProviderChange}
        options={providerTabs}
      />
      <SegmentedTabs
        value={env}
        onChange={onEnvChange}
        options={envTabs}
        mono
      />
      <div className="flex-1" />
      <span className="font-mono text-[10.5px] tabular-nums text-muted-foreground">
        {resultsCount}
        {resultsCount !== totalCount && <span className="text-muted-foreground/60"> / {totalCount}</span>}
      </span>
      <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={onRefresh}>
        <RefreshCw className="w-3.5 h-3.5" />
      </Button>
      {canCreate && (
        <Button size="sm" className="h-8 gap-1.5" onClick={onAdd}>
          <Plus className="w-3.5 h-3.5" />
          Add credential
        </Button>
      )}
    </div>
  );
}

function SegmentedTabs<T extends string>({
  value,
  onChange,
  options,
  mono,
}: {
  value: T;
  onChange: (id: T) => void;
  options: Array<{ id: T; label: string }>;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center gap-0.5 bg-card rounded-md p-0.5 border border-border">
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          onClick={() => onChange(o.id)}
          className={cn(
            'h-[26px] px-2.5 rounded-[4px] text-[11px] font-medium transition-colors whitespace-nowrap',
            mono && 'font-mono text-[10.5px] uppercase tracking-wider',
            value === o.id
              ? 'bg-primary/15 text-primary'
              : 'text-foreground/80 hover:text-foreground hover:bg-foreground/5',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

// ----- Table -----

function CredentialsTable({
  rows,
  activeId,
  usageByCredential,
  onOpen,
}: {
  rows: CloudCredential[];
  activeId: string | null;
  usageByCredential: Map<string, SourceConfiguration[]>;
  onOpen: (id: string) => void;
}) {
  return (
    <div className="@container/table">
      <table className="w-full text-[12px]">
        <thead>
          <tr className="border-b border-border bg-card/40">
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground pl-4 py-2">
              Credential
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[140px] @max-[780px]/table:hidden">
              Provider
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[80px] @max-[900px]/table:hidden">
              Env
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[110px] @max-[1000px]/table:hidden">
              Region
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[120px]">
              Used by
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[150px] @max-[1200px]/table:hidden">
              Rotates
            </th>
            <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground py-2 w-[110px] pr-4 @max-[1100px]/table:hidden">
              Last used
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((cred) => (
            <CredentialRow
              key={cred.id}
              cred={cred}
              active={cred.id === activeId}
              usageCount={usageByCredential.get(cred.id)?.length ?? 0}
              onOpen={() => onOpen(cred.id)}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CredentialRow({
  cred,
  active,
  usageCount,
  onOpen,
}: {
  cred: CloudCredential;
  active: boolean;
  usageCount: number;
  onOpen: () => void;
}) {
  const spec = providerSpec(cred.provider);
  const Icon = spec.icon;
  const health = deriveHealth(cred.expires_at);
  const healthBadge = HEALTH_BADGES[health];
  return (
    <tr
      className={cn(
        'border-b border-border cursor-pointer group hover:bg-foreground/[0.03]',
        active && 'bg-foreground/[0.05]',
      )}
      onClick={onOpen}
    >
      <td className="pl-4 py-3 align-top">
        <div className="flex items-start gap-3 min-w-0">
          <div className="w-8 h-8 rounded-md border border-border bg-foreground/[0.03] flex items-center justify-center shrink-0 mt-0.5">
            <Icon className={cn('w-[14px] h-[14px]', spec.iconClass)} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[12.5px] font-medium text-foreground truncate group-hover:text-primary transition-colors">
                {cred.name}
              </span>
              {health !== 'unknown' && (
                <span
                  className={cn(
                    'inline-flex items-center gap-1 h-[16px] px-1 rounded-[3px] text-[9.5px] font-semibold uppercase tracking-wider',
                    healthBadge.bg,
                    healthBadge.text,
                  )}
                >
                  <span className={cn('w-[5px] h-[5px] rounded-full', healthBadge.dot)} />
                  {healthBadge.label}
                </span>
              )}
              <span className="font-mono text-[9.5px] text-muted-foreground">
                v{cred.active_version}
              </span>
              <span className="hidden @max-[780px]/table:inline-flex items-center gap-1 h-[15px] px-1 rounded-[3px] border border-border bg-foreground/[0.03]">
                <Icon className={cn('w-[8px] h-[8px]', spec.iconClass)} />
                <span className="text-[9.5px] font-mono uppercase tracking-wider text-foreground/80">
                  {spec.short}
                </span>
              </span>
              {cred.environment && (
                <span
                  className={cn(
                    'hidden @max-[900px]/table:inline-flex items-center h-[15px] px-1 rounded-[3px] text-[9.5px] font-mono uppercase tracking-wider',
                    ENV_BADGE[cred.environment],
                  )}
                >
                  {cred.environment}
                </span>
              )}
            </div>
            {cred.description && (
              <div className="text-[11px] text-muted-foreground line-clamp-2 mt-0.5 leading-relaxed max-w-[520px]">
                {cred.description}
              </div>
            )}
          </div>
        </div>
      </td>

      <td className="py-3 align-top @max-[780px]/table:hidden">
        <span className="inline-flex items-center gap-1.5 h-[22px] px-1.5 rounded-[4px] border border-border bg-foreground/[0.03]">
          <Icon className={cn('w-3 h-3', spec.iconClass)} />
          <span className="text-[10.5px] font-mono text-foreground/80">{spec.label}</span>
        </span>
      </td>

      <td className="py-3 align-top @max-[900px]/table:hidden">
        {cred.environment ? (
          <span
            className={cn(
              'inline-flex items-center h-[20px] px-1.5 rounded-[3px] text-[10.5px] font-mono uppercase tracking-wider',
              ENV_BADGE[cred.environment],
            )}
          >
            {cred.environment}
          </span>
        ) : (
          <span className="text-[11px] text-muted-foreground/60">—</span>
        )}
      </td>

      <td className="py-3 align-top @max-[1000px]/table:hidden">
        <span className="font-mono text-[11px] text-muted-foreground">{cred.region || '—'}</span>
      </td>

      <td className="py-3 align-top">
        {usageCount === 0 ? (
          <span className="text-[11px] text-muted-foreground/70">Unused</span>
        ) : (
          <span className="inline-flex items-center gap-1 h-[22px] px-1.5 rounded-[4px] bg-foreground/[0.03] border border-border text-[10.5px] text-foreground/80">
            <Plug className="w-3 h-3" />
            {usageCount} config{usageCount > 1 ? 's' : ''}
          </span>
        )}
      </td>

      <td className="py-3 align-top @max-[1200px]/table:hidden">
        <RotatesCell expiresAt={cred.expires_at} />
      </td>

      <td className="pr-4 py-3 align-top @max-[1100px]/table:hidden">
        <LastUsedCell value={cred.last_used_at} />
      </td>
    </tr>
  );
}

function RotatesCell({ expiresAt }: { expiresAt: string | null | undefined }) {
  if (!expiresAt) return <span className="text-[11px] text-muted-foreground/60">—</span>;
  const days = daysUntil(expiresAt);
  const date = isoToDateInput(expiresAt);
  if (days === null) return <span className="text-[11px] text-muted-foreground/60">—</span>;
  if (days < 0) {
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-red-500">
        <AlertTriangle className="w-3 h-3" />
        expired · {Math.abs(days)}d ago
      </span>
    );
  }
  if (days <= 7) {
    return (
      <span className="text-[11px] text-red-500">
        {days}d · <span className="font-mono text-muted-foreground">{date}</span>
      </span>
    );
  }
  if (days <= 30) {
    return (
      <span className="text-[11px] text-amber-600 dark:text-amber-400">
        {days}d · <span className="font-mono text-muted-foreground">{date}</span>
      </span>
    );
  }
  return (
    <span className="text-[11px] text-muted-foreground">
      in {days}d · <span className="font-mono text-muted-foreground/80">{date}</span>
    </span>
  );
}

function LastUsedCell({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-[11px] text-muted-foreground/60">—</span>;
  return (
    <div className="flex flex-col">
      <span className="text-[11px] text-foreground/80">{formatRelative(value)}</span>
      <span className="font-mono text-[10px] text-muted-foreground">{formatUtc(value)}</span>
    </div>
  );
}

// ----- Empty state -----

function EmptyState({ canCreate, onPick }: { canCreate: boolean; onPick: (p: Provider) => void }) {
  return (
    <div className="flex items-center justify-center py-16 px-4">
      <div className="w-full max-w-[680px] text-center">
        <div className="w-[52px] h-[52px] mx-auto rounded-xl border border-border bg-card flex items-center justify-center mb-4">
          <KeyRound className="w-[22px] h-[22px] text-muted-foreground" />
        </div>
        <div className="text-[14px] font-semibold text-foreground">Vault is empty</div>
        <div className="text-[11.5px] text-muted-foreground mt-1 max-w-[460px] mx-auto leading-relaxed">
          Add credentials for pull-based ingestion. Source configs reference them by ID; secrets
          are encrypted at rest and never returned in plain text.
        </div>

        {canCreate && (
          <div className="mt-6 grid grid-cols-3 gap-2.5">
            {PROVIDERS.map((p) => {
              const Icon = p.icon;
              return (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => onPick(p.value)}
                  className="group text-left p-3 rounded-md border border-border bg-card hover:border-primary/40 hover:bg-foreground/[0.03] transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <div className="w-7 h-7 rounded-md border border-border bg-foreground/[0.03] flex items-center justify-center">
                      <Icon className={cn('w-[14px] h-[14px]', p.iconClass)} />
                    </div>
                    <div className="text-[12.5px] font-medium text-foreground group-hover:text-primary transition-colors">
                      {p.label}
                    </div>
                  </div>
                  <div className="text-[10.5px] text-muted-foreground mt-2 leading-relaxed">
                    {p.description}
                  </div>
                  <div className="mt-2.5 text-[10px] font-mono text-muted-foreground/80 flex items-center gap-1 group-hover:text-primary transition-colors">
                    <Plus className="w-[10px] h-[10px]" />
                    Add credential
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function NoResults({ query, onReset }: { query: string; onReset: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      <Search className="w-8 h-8 text-muted-foreground/50 mb-3" />
      <div className="text-[12.5px] font-medium text-foreground">
        {query ? `No credentials match "${query}"` : 'No credentials match the filter'}
      </div>
      <button
        type="button"
        onClick={onReset}
        className="text-[11px] text-primary hover:underline mt-2"
      >
        Clear filters
      </button>
    </div>
  );
}

// ----- Inspector drawer -----

function Inspector({
  cred,
  usage,
  canEdit,
  canDelete,
  canRotate,
  onUpdate,
  updating,
  onDelete,
  deleting,
  onRotate,
  onRollback,
  rollingBack,
}: {
  cred: CloudCredential;
  usage: SourceConfiguration[];
  canEdit: boolean;
  canDelete: boolean;
  canRotate: boolean;
  onUpdate: (data: UpdateCloudCredentialRequest) => void;
  updating: boolean;
  onDelete: () => void;
  deleting: boolean;
  onRotate: () => void;
  onRollback: (version: number) => void;
  rollingBack: boolean;
}) {
  const [tab, setTab] = useState<InspectorTab>('overview');
  const spec = providerSpec(cred.provider);
  const Icon = spec.icon;
  const health = deriveHealth(cred.expires_at);
  const healthBadge = HEALTH_BADGES[health];

  useEffect(() => {
    setTab('overview');
  }, [cred.id]);

  return (
    <>
      <div className="px-5 pt-4 pb-3 shrink-0 border-b border-border bg-card/40">
        <div className="flex items-start gap-2.5 pr-8">
          <div className="w-9 h-9 rounded-md border border-border bg-card flex items-center justify-center shrink-0">
            <Icon className={cn('w-4 h-4', spec.iconClass)} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
              {health !== 'unknown' && (
                <span
                  className={cn(
                    'inline-flex items-center gap-1 h-[16px] px-1 rounded-[3px] text-[9.5px] font-semibold uppercase tracking-wider',
                    healthBadge.bg,
                    healthBadge.text,
                  )}
                >
                  <span className={cn('w-[5px] h-[5px] rounded-full', healthBadge.dot)} />
                  {healthBadge.label}
                </span>
              )}
              <span className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
                {spec.label} · v{cred.active_version}
              </span>
              {cred.environment && (
                <span
                  className={cn(
                    'inline-flex items-center h-[15px] px-1 rounded-[3px] text-[9.5px] font-mono uppercase tracking-wider',
                    ENV_BADGE[cred.environment],
                  )}
                >
                  {cred.environment}
                </span>
              )}
            </div>
            <div className="text-[14px] font-semibold text-foreground leading-tight truncate">
              {cred.name}
            </div>
            <div className="text-[10.5px] font-mono text-muted-foreground mt-0.5 truncate">
              {cred.id}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-0.5 mt-3 -mb-3.5">
          {(
            [
              { id: 'overview', label: 'Overview' },
              { id: 'versions', label: 'Versions' },
              { id: 'usage', label: `Used by · ${usage.length}` },
              { id: 'danger', label: 'Danger' },
            ] as Array<{ id: InspectorTab; label: string }>
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={cn(
                'px-2.5 h-[28px] text-[11.5px] border-b-[1.5px] transition-colors font-medium',
                tab === t.id
                  ? 'border-primary text-foreground'
                  : 'border-transparent text-muted-foreground hover:text-foreground/80',
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-auto">
        {tab === 'overview' && (
          <OverviewTab cred={cred} canEdit={canEdit} updating={updating} onUpdate={onUpdate} />
        )}
        {tab === 'versions' && (
          <VersionsTab
            credentialId={cred.id}
            activeVersion={cred.active_version}
            canRotate={canRotate}
            onRollback={onRollback}
            rollingBack={rollingBack}
          />
        )}
        {tab === 'usage' && <UsageTab usage={usage} />}
        {tab === 'danger' && (
          <DangerTab
            cred={cred}
            usage={usage}
            canDelete={canDelete}
            deleting={deleting}
            onDelete={onDelete}
          />
        )}
      </div>

      {canRotate && (
        <div className="px-4 py-2.5 border-t border-border shrink-0 flex items-center gap-2 bg-card/40">
          <span className="text-[10.5px] text-muted-foreground flex-1 truncate">
            {cred.expires_at ? `Rotates ${isoToDateInput(cred.expires_at)}` : 'No rotation deadline set'}
            {cred.last_used_at ? ` · last used ${formatRelative(cred.last_used_at)}` : ''}
          </span>
          <Button size="sm" variant="outline" className="h-7 text-[11px] gap-1.5" onClick={onRotate}>
            <RotateCcw className="w-3 h-3" />
            Rotate
          </Button>
        </div>
      )}
    </>
  );
}

function OverviewTab({
  cred,
  canEdit,
  updating,
  onUpdate,
}: {
  cred: CloudCredential;
  canEdit: boolean;
  updating: boolean;
  onUpdate: (data: UpdateCloudCredentialRequest) => void;
}) {
  const spec = providerSpec(cred.provider);
  const [name, setName] = useState(cred.name);
  const [description, setDescription] = useState(cred.description ?? '');
  const [region, setRegion] = useState(cred.region ?? '');
  const [environment, setEnvironment] = useState<CredentialEnvironment | ''>(
    (cred.environment as CredentialEnvironment) ?? '',
  );
  const [expiresAt, setExpiresAt] = useState(isoToDateInput(cred.expires_at));

  // Reset local edit state when switching to a different credential. Only
  // depend on cred.id so a background refetch (e.g. after an unrelated
  // mutation invalidates the query) doesn't silently wipe the user's
  // mid-edit text by re-syncing from the new server snapshot.
  useEffect(() => {
    setName(cred.name);
    setDescription(cred.description ?? '');
    setRegion(cred.region ?? '');
    setEnvironment((cred.environment as CredentialEnvironment) ?? '');
    setExpiresAt(isoToDateInput(cred.expires_at));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cred.id]);

  const dirty =
    name !== cred.name ||
    (description ?? '') !== (cred.description ?? '') ||
    (region ?? '') !== (cred.region ?? '') ||
    (environment || '') !== (cred.environment ?? '') ||
    expiresAt !== isoToDateInput(cred.expires_at);

  const valid = name.trim().length > 0;

  const save = () => {
    if (!dirty || !valid) return;
    const data: UpdateCloudCredentialRequest = {};
    if (name !== cred.name) data.name = name.trim();
    if ((description ?? '') !== (cred.description ?? '')) {
      data.description = description.trim() || undefined;
    }
    if ((region ?? '') !== (cred.region ?? '')) {
      data.region = region.trim() || undefined;
    }
    if ((environment || '') !== (cred.environment ?? '')) {
      data.environment = environment || undefined;
    }
    if (expiresAt !== isoToDateInput(cred.expires_at)) {
      data.expires_at = dateInputToIso(expiresAt);
    }
    onUpdate(data);
  };

  const reset = () => {
    setName(cred.name);
    setDescription(cred.description ?? '');
    setRegion(cred.region ?? '');
    setEnvironment((cred.environment as CredentialEnvironment) ?? '');
    setExpiresAt(isoToDateInput(cred.expires_at));
  };

  return (
    <div className="p-4 space-y-4">
      <div>
        <SectionLabel>Metadata</SectionLabel>
        <div className="grid grid-cols-2 gap-px rounded-md overflow-hidden border border-border bg-border">
          <MetaCell label="Provider" value={spec.label} />
          <MetaCell label="Active version" value={`v${cred.active_version}`} mono />
          <MetaCell label="Region" value={cred.region || '—'} mono />
          <MetaCell label="Environment" value={cred.environment || '—'} mono />
          <MetaCell
            label="Last used"
            value={cred.last_used_at ? formatRelative(cred.last_used_at) : '—'}
          />
          <MetaCell
            label="Expires"
            value={cred.expires_at ? isoToDateInput(cred.expires_at) : '—'}
            mono
            tone={
              deriveHealth(cred.expires_at) === 'expired'
                ? 'danger'
                : deriveHealth(cred.expires_at) === 'expires-soon'
                  ? 'warn'
                  : undefined
            }
          />
          <MetaCell label="Created" value={formatUtc(cred.created_at)} mono />
          <MetaCell label="Updated" value={formatUtc(cred.updated_at)} mono />
        </div>
      </div>

      <div>
        <SectionLabel>Details</SectionLabel>
        <div className="space-y-2.5">
          <FieldRow label="Name" required>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={!canEdit || updating}
              className="h-8 text-[12px] bg-card"
            />
          </FieldRow>
          <FieldRow label="Description">
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={!canEdit || updating}
              rows={2}
              placeholder="What this credential is used for…"
              className="text-[12px] bg-card resize-y min-h-[60px]"
            />
          </FieldRow>
          <div className="grid grid-cols-2 gap-2.5">
            <FieldRow label="Environment">
              <select
                value={environment}
                onChange={(e) => setEnvironment(e.target.value as CredentialEnvironment | '')}
                disabled={!canEdit || updating}
                className="h-8 w-full rounded-md border border-border bg-card px-2.5 text-[12px] text-foreground outline-none focus:border-primary/60 font-mono uppercase"
              >
                <option value="">—</option>
                <option value="prod">prod</option>
                <option value="staging">staging</option>
                <option value="dev">dev</option>
              </select>
            </FieldRow>
            <FieldRow label="Expires at">
              <Input
                type="date"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                disabled={!canEdit || updating}
                className="h-8 text-[12px] bg-card font-mono"
              />
            </FieldRow>
          </div>
          {cred.provider === 'aws_s3' && (
            <FieldRow label="Region">
              <Input
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                disabled={!canEdit || updating}
                placeholder="us-east-1"
                className="h-8 text-[12px] bg-card font-mono"
              />
            </FieldRow>
          )}
        </div>
        {canEdit && dirty && (
          <div className="flex items-center gap-2 mt-3">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-[11px]"
              onClick={reset}
              disabled={updating}
            >
              Discard
            </Button>
            <div className="flex-1" />
            <Button
              size="sm"
              className="h-7 text-[11px]"
              onClick={save}
              disabled={!valid || updating}
            >
              {updating && <Loader2 className="w-3 h-3 mr-1.5 animate-spin" />}
              Save changes
            </Button>
          </div>
        )}
      </div>

      <div className="rounded-md border border-border bg-foreground/[0.02] px-3 py-2.5 text-[11px] text-muted-foreground leading-relaxed flex items-start gap-2">
        <Lock className="w-3 h-3 mt-0.5 shrink-0" />
        <span>
          Secret values are encrypted with AES-256-GCM at rest and never returned by the API. To
          replace the secret material, use <strong className="text-foreground">Rotate</strong> in
          the footer below — it preserves the prior version for rollback.
        </span>
      </div>
    </div>
  );
}

// ----- Versions tab -----

function VersionsTab({
  credentialId,
  activeVersion,
  canRotate,
  onRollback,
  rollingBack,
}: {
  credentialId: string;
  activeVersion: number;
  canRotate: boolean;
  onRollback: (version: number) => void;
  rollingBack: boolean;
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['credentialVersions', credentialId],
    queryFn: () => api.listCredentialVersions(credentialId),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (error) {
    return (
      <div className="p-4 text-[12px] text-red-500">
        Failed to load versions — {String(error)}
      </div>
    );
  }
  const versions = data?.versions ?? [];
  if (versions.length === 0) {
    return (
      <div className="p-4 text-[12px] text-muted-foreground text-center">
        No version history yet.
      </div>
    );
  }
  return (
    <div className="p-4 space-y-3">
      <div>
        <SectionLabel>Version history</SectionLabel>
        <div className="text-[11px] text-muted-foreground leading-relaxed">
          Every rotation creates a new version with its own encrypted secret. Roll back to a prior
          version to swap source configs over to its secret material at the next deploy.
        </div>
      </div>

      <div className="relative pl-4 space-y-3">
        <span className="absolute left-[5px] top-1.5 bottom-1.5 w-px bg-border" />
        {versions.map((v) => (
          <VersionRow
            key={v.id}
            version={v}
            activeVersion={activeVersion}
            canRotate={canRotate}
            onRollback={() => onRollback(v.version_number)}
            rollingBack={rollingBack}
          />
        ))}
      </div>
    </div>
  );
}

function VersionRow({
  version,
  activeVersion,
  canRotate,
  onRollback,
  rollingBack,
}: {
  version: CloudCredentialVersion;
  activeVersion: number;
  canRotate: boolean;
  onRollback: () => void;
  rollingBack: boolean;
}) {
  const isActive = version.is_active || version.version_number === activeVersion;
  return (
    <div className="relative">
      <span
        className={cn(
          'absolute -left-4 top-1.5 w-[11px] h-[11px] rounded-full border-2',
          isActive ? 'bg-primary border-primary' : 'bg-card border-border',
        )}
      />
      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
        <span className="font-mono text-[12.5px] text-foreground">v{version.version_number}</span>
        {isActive && (
          <span className="inline-flex items-center gap-1 h-[16px] px-1.5 rounded-[3px] bg-primary/15 text-primary text-[9.5px] font-semibold uppercase tracking-wider">
            <CheckCircle2 className="w-[9px] h-[9px]" />
            Active
          </span>
        )}
        {version.reverted_from_version != null && (
          <span className="inline-flex items-center gap-1 h-[16px] px-1.5 rounded-[3px] bg-foreground/[0.06] text-foreground/80 text-[9.5px] font-semibold uppercase tracking-wider">
            <Undo2 className="w-[9px] h-[9px]" />
            from v{version.reverted_from_version}
          </span>
        )}
      </div>
      <div className="text-[10.5px] font-mono text-muted-foreground">
        {formatUtc(version.created_at)} · {formatRelative(version.created_at)}
      </div>
      {version.note && (
        <div className="text-[11.5px] text-foreground/80 mt-1">{version.note}</div>
      )}
      {!isActive && canRotate && (
        <button
          type="button"
          onClick={onRollback}
          disabled={rollingBack}
          className="text-[10.5px] text-muted-foreground hover:text-primary transition-colors mt-1 inline-flex items-center gap-1 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {rollingBack ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <Undo2 className="w-3 h-3" />
          )}
          Rollback to v{version.version_number}
        </button>
      )}
    </div>
  );
}

function UsageTab({ usage }: { usage: SourceConfiguration[] }) {
  if (usage.length === 0) {
    return (
      <div className="p-4 text-center">
        <Plug className="w-6 h-6 text-muted-foreground/60 mx-auto mb-2" />
        <div className="text-[12px] text-foreground/80">
          No source configs reference this credential yet.
        </div>
        <div className="text-[10.5px] text-muted-foreground mt-1">
          Safe to delete — or attach it from{' '}
          <Link to="/ingestion/source-configurations" className="text-primary hover:underline">
            Source configs
          </Link>
          .
        </div>
      </div>
    );
  }
  return (
    <div className="p-4 space-y-3">
      <div>
        <SectionLabel>Source configs using this credential</SectionLabel>
        <div className="text-[11px] text-muted-foreground leading-relaxed">
          Deleting this credential will break {usage.length} config{usage.length > 1 ? 's' : ''}{' '}
          on next deploy.
        </div>
      </div>
      <div className="rounded-md border border-border divide-y divide-border bg-card">
        {usage.map((config) => (
          <Link
            key={config.id}
            to={`/ingestion/source-configurations/${config.id}`}
            className="flex items-center gap-3 px-3 py-2.5 hover:bg-foreground/[0.03] transition-colors group"
          >
            <div className="w-7 h-7 rounded-md border border-border bg-foreground/[0.03] flex items-center justify-center shrink-0">
              <Plug className="w-3 h-3 text-muted-foreground" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-[12px] text-foreground group-hover:text-primary transition-colors truncate">
                {config.name}
              </div>
              <div className="text-[10.5px] font-mono text-muted-foreground mt-0.5 truncate">
                {config.config_type} · {config.id}
              </div>
            </div>
            <span
              className={cn(
                'inline-flex items-center h-[18px] px-1.5 rounded-[3px] text-[9.5px] font-semibold uppercase tracking-wider',
                config.deployed
                  ? 'bg-emerald-500/15 text-emerald-500'
                  : 'bg-foreground/[0.05] text-foreground/70',
              )}
            >
              {config.deployed ? 'deployed' : 'ready'}
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}

function DangerTab({
  cred,
  usage,
  canDelete,
  deleting,
  onDelete,
}: {
  cred: CloudCredential;
  usage: SourceConfiguration[];
  canDelete: boolean;
  deleting: boolean;
  onDelete: () => void;
}) {
  const [confirm, setConfirm] = useState('');
  const matches = confirm === cred.name;
  const usedCount = usage.length;

  return (
    <div className="p-4 space-y-4">
      <div className="rounded-md border border-red-500/30 bg-red-500/[0.04] px-3 py-3">
        <div className="text-[12.5px] font-medium text-red-500 mb-1">Delete credential</div>
        <div className="text-[11px] text-muted-foreground leading-relaxed mb-2.5">
          Permanently remove this credential. This cannot be undone.
          {usedCount > 0 && (
            <>
              {' '}
              <strong className="text-red-500">
                {usedCount} source config{usedCount > 1 ? 's' : ''} will break on next deploy.
              </strong>
            </>
          )}
        </div>
        <div className="text-[10.5px] text-muted-foreground mb-1 font-mono">
          Type <span className="text-foreground">{cred.name}</span> to confirm
        </div>
        <Input
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder={cred.name}
          disabled={!canDelete || deleting}
          className="h-8 text-[12px] bg-card font-mono mb-2"
        />
        <Button
          size="sm"
          className={cn(
            'h-8 text-[11.5px] w-full',
            matches
              ? 'bg-red-600 hover:bg-red-700 text-white'
              : 'bg-foreground/5 text-muted-foreground cursor-not-allowed hover:bg-foreground/5',
          )}
          disabled={!canDelete || !matches || deleting}
          onClick={onDelete}
        >
          {deleting && <Loader2 className="w-3 h-3 mr-1.5 animate-spin" />}
          Delete permanently
        </Button>
      </div>
    </div>
  );
}

// ----- Add credential dialog -----

function AddCredentialForm({
  initialProvider,
  submitting,
  onCancel,
  onSubmit,
}: {
  initialProvider: Provider;
  submitting: boolean;
  onCancel: () => void;
  onSubmit: (req: CreateCloudCredentialRequest) => void;
}) {
  const [provider, setProvider] = useState<Provider>(initialProvider);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [region, setRegion] = useState('us-east-1');
  const [environment, setEnvironment] = useState<CredentialEnvironment | ''>('prod');
  const [expiresAt, setExpiresAt] = useState('');

  // AWS S3
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');
  const [showAwsSecret, setShowAwsSecret] = useState(false);

  // GCP Pub/Sub
  const [credentialsJson, setCredentialsJson] = useState('');

  // Kafka
  const [saslMechanism, setSaslMechanism] = useState<string>('_none');
  const [saslUsername, setSaslUsername] = useState('');
  const [saslPassword, setSaslPassword] = useState('');
  const [tlsEnabled, setTlsEnabled] = useState(false);
  const [tlsCaCert, setTlsCaCert] = useState('');
  const [showKafkaPassword, setShowKafkaPassword] = useState(false);
  const [kafkaPreset, setKafkaPreset] = useState<KafkaPresetId | null>(null);

  const spec = providerSpec(provider);

  const isValid = (() => {
    if (!name.trim()) return false;
    if (provider === 'aws_s3') {
      return accessKeyId.trim() !== '' && secretAccessKey.trim() !== '';
    }
    if (provider === 'gcp_pubsub') return credentialsJson.trim() !== '';
    if (provider === 'kafka') {
      if (saslMechanism && saslMechanism !== '_none') {
        return saslUsername.trim() !== '' && saslPassword.trim() !== '';
      }
      return true;
    }
    return false;
  })();

  const buildPayload = (): CreateCloudCredentialRequest => {
    let credentials: AwsS3Credentials | GcpPubSubCredentials | KafkaCredentials;
    switch (provider) {
      case 'aws_s3':
        credentials = {
          access_key_id: accessKeyId.trim(),
          secret_access_key: secretAccessKey,
        };
        break;
      case 'gcp_pubsub':
        credentials = { credentials_json: credentialsJson };
        break;
      case 'kafka':
        credentials = {
          sasl_mechanism:
            saslMechanism && saslMechanism !== '_none'
              ? (saslMechanism as 'PLAIN' | 'SCRAM-SHA-256' | 'SCRAM-SHA-512')
              : undefined,
          sasl_username: saslUsername.trim() || undefined,
          sasl_password: saslPassword || undefined,
          tls_enabled: tlsEnabled || undefined,
          tls_ca_cert: tlsEnabled && tlsCaCert.trim() ? tlsCaCert : undefined,
        };
        break;
    }
    return {
      name: name.trim(),
      provider,
      description: description.trim() || undefined,
      region: provider === 'aws_s3' ? region.trim() || undefined : undefined,
      environment: environment || undefined,
      expires_at: dateInputToIso(expiresAt),
      credentials,
    };
  };

  const applyKafkaPreset = (id: KafkaPresetId) => {
    const preset = KAFKA_PRESET_BY_ID[id];
    setKafkaPreset(id);
    setSaslMechanism(preset.mechanism);
    setTlsEnabled(preset.tls);
    // Don't overwrite user-typed values when switching presets — only seed the
    // mechanism/TLS toggle. Placeholder hints already steer the rest.
  };

  return (
    <>
      <div className="border-b border-border px-5 py-4 bg-card/40 flex items-start gap-2.5 pr-12 shrink-0">
        <div className="w-7 h-7 rounded-md border border-border bg-card flex items-center justify-center shrink-0">
          <KeyRound className="w-[14px] h-[14px] text-muted-foreground" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[14px] font-semibold text-foreground leading-tight">
            Add credential
          </div>
          <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mt-0.5">
            Encrypted with AES-256-GCM before storage
          </div>
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-auto px-5 py-4 space-y-4">
        <div>
          <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Provider
          </Label>
          <div className="mt-1.5 grid grid-cols-3 gap-1.5">
            {PROVIDERS.map((p) => {
              const Icon = p.icon;
              const active = provider === p.value;
              return (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => setProvider(p.value)}
                  className={cn(
                    'flex items-center gap-2 h-9 px-2.5 rounded-md border text-left transition-colors',
                    active
                      ? 'border-primary/60 bg-primary/8 text-foreground'
                      : 'border-border bg-card hover:border-border/80 text-foreground/80',
                  )}
                >
                  <div className="w-6 h-6 rounded border border-border bg-foreground/[0.03] flex items-center justify-center shrink-0">
                    <Icon className={cn('w-[11px] h-[11px]', p.iconClass)} />
                  </div>
                  <span className="text-[12px] font-medium">{p.label}</span>
                </button>
              );
            })}
          </div>
          <div className="text-[10.5px] text-muted-foreground mt-1.5">{spec.description}</div>
        </div>

        <FieldRow label="Name" required>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., AWS Prod — CloudTrail"
            className="h-8 text-[12px] bg-card"
            autoFocus
          />
        </FieldRow>

        <FieldRow label="Description">
          <Textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            placeholder="Optional — what this credential is used for"
            className="text-[12px] bg-card resize-y min-h-[60px]"
          />
        </FieldRow>

        <div className="grid grid-cols-2 gap-2.5">
          <FieldRow label="Environment">
            <select
              value={environment}
              onChange={(e) => setEnvironment(e.target.value as CredentialEnvironment | '')}
              className="h-8 w-full rounded-md border border-border bg-card px-2.5 text-[12px] text-foreground outline-none focus:border-primary/60 font-mono uppercase"
            >
              <option value="">—</option>
              <option value="prod">prod</option>
              <option value="staging">staging</option>
              <option value="dev">dev</option>
            </select>
          </FieldRow>
          <FieldRow label="Expires at">
            <Input
              type="date"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              className="h-8 text-[12px] bg-card font-mono"
            />
          </FieldRow>
        </div>

        <div className="rounded-md border border-border bg-card px-3 py-3">
          <div className="flex items-center gap-1.5 text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-2.5">
            <Lock className="w-3 h-3" />
            {spec.label} credentials
          </div>

          {provider === 'aws_s3' && (
            <div className="space-y-2.5">
              <FieldRow label="Region" required>
                <Input
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  placeholder="us-east-1"
                  className="h-8 text-[12px] bg-card font-mono"
                />
              </FieldRow>
              <FieldRow label="Access key ID" required>
                <Input
                  value={accessKeyId}
                  onChange={(e) => setAccessKeyId(e.target.value)}
                  placeholder="AKIA…"
                  className="h-8 text-[12px] bg-card font-mono"
                />
              </FieldRow>
              <FieldRow label="Secret access key" required secret>
                <SecretInput
                  value={secretAccessKey}
                  onChange={setSecretAccessKey}
                  reveal={showAwsSecret}
                  onToggleReveal={() => setShowAwsSecret((v) => !v)}
                />
              </FieldRow>
            </div>
          )}

          {provider === 'gcp_pubsub' && (
            <FieldRow label="Service account JSON" required secret>
              <Textarea
                value={credentialsJson}
                onChange={(e) => setCredentialsJson(e.target.value)}
                rows={6}
                placeholder='{"type": "service_account", …}'
                className="text-[11.5px] font-mono bg-card resize-y min-h-[140px]"
              />
            </FieldRow>
          )}

          {provider === 'kafka' && (
            <div className="space-y-2.5">
              <FieldRow label="Quick start">
                <div className="flex flex-wrap gap-1.5">
                  {KAFKA_PRESETS.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => applyKafkaPreset(p.id)}
                      className={cn(
                        'h-7 rounded-md border px-2.5 text-[11.5px] font-mono transition-colors',
                        kafkaPreset === p.id
                          ? 'border-primary/60 bg-primary/10 text-foreground'
                          : 'border-border bg-card hover:bg-foreground/[0.04] text-foreground/80',
                      )}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </FieldRow>
              {kafkaPreset && (
                <div className="rounded-md border border-border bg-foreground/[0.02] px-2.5 py-1.5 text-[11px] text-muted-foreground leading-relaxed">
                  {KAFKA_PRESET_BY_ID[kafkaPreset].hint}
                </div>
              )}
              <FieldRow label="SASL mechanism">
                <select
                  value={saslMechanism}
                  onChange={(e) => {
                    setSaslMechanism(e.target.value);
                    setKafkaPreset(null);
                  }}
                  className="h-8 w-full rounded-md border border-border bg-card px-2.5 text-[12px] text-foreground outline-none focus:border-primary/60 font-mono"
                >
                  <option value="_none">None (unauthenticated)</option>
                  <option value="PLAIN">PLAIN</option>
                  <option value="SCRAM-SHA-256">SCRAM-SHA-256</option>
                  <option value="SCRAM-SHA-512">SCRAM-SHA-512</option>
                </select>
              </FieldRow>
              {saslMechanism && saslMechanism !== '_none' && (
                <>
                  <FieldRow label="Username" required>
                    <Input
                      value={saslUsername}
                      onChange={(e) => setSaslUsername(e.target.value)}
                      placeholder={
                        kafkaPreset
                          ? KAFKA_PRESET_BY_ID[kafkaPreset].usernamePlaceholder
                          : 'logs-consumer'
                      }
                      className="h-8 text-[12px] bg-card font-mono"
                    />
                  </FieldRow>
                  <FieldRow label="Password" required secret>
                    <SecretInput
                      value={saslPassword}
                      onChange={setSaslPassword}
                      reveal={showKafkaPassword}
                      onToggleReveal={() => setShowKafkaPassword((v) => !v)}
                      placeholder={
                        kafkaPreset ? KAFKA_PRESET_BY_ID[kafkaPreset].passwordPlaceholder : undefined
                      }
                    />
                  </FieldRow>
                </>
              )}
              <label className="flex items-center gap-2 text-[11.5px] text-foreground/80 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={tlsEnabled}
                  onChange={(e) => {
                    setTlsEnabled(e.target.checked);
                    setKafkaPreset(null);
                  }}
                  className="rounded border-border"
                />
                Enable TLS/SSL
              </label>
              {tlsEnabled && (
                <FieldRow label="CA certificate (PEM, optional)">
                  <Textarea
                    value={tlsCaCert}
                    onChange={(e) => setTlsCaCert(e.target.value)}
                    rows={4}
                    placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}
                    className="text-[11.5px] font-mono bg-card resize-y min-h-[96px]"
                  />
                </FieldRow>
              )}
            </div>
          )}
        </div>

        <div className="rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2.5 text-[11px] text-amber-700 dark:text-amber-300 leading-relaxed flex items-start gap-2">
          <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
          <span>
            Secret values can&rsquo;t be viewed again after creation. To rotate, delete and re-add
            the credential.
          </span>
        </div>
      </div>

      <div className="border-t border-border px-5 py-3 flex items-center gap-2 bg-card/40 shrink-0">
        <Button variant="ghost" size="sm" className="h-8 text-[11.5px]" onClick={onCancel}>
          Cancel
        </Button>
        <div className="flex-1" />
        <Button
          size="sm"
          className="h-8 text-[11.5px] gap-1.5"
          disabled={!isValid || submitting}
          onClick={() => onSubmit(buildPayload())}
        >
          {submitting && <Loader2 className="w-3 h-3 animate-spin" />}
          <KeyRound className="w-3 h-3" />
          Create credential
        </Button>
      </div>
    </>
  );
}

// ----- Rotate credential form -----

function RotateCredentialForm({
  cred,
  submitting,
  onCancel,
  onSubmit,
}: {
  cred: CloudCredential;
  submitting: boolean;
  onCancel: () => void;
  onSubmit: (req: RotateCredentialRequest) => void;
}) {
  const spec = providerSpec(cred.provider);
  const Icon = spec.icon;
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');
  const [showAwsSecret, setShowAwsSecret] = useState(false);
  const [credentialsJson, setCredentialsJson] = useState('');
  const [saslMechanism, setSaslMechanism] = useState<string>('_none');
  const [saslUsername, setSaslUsername] = useState('');
  const [saslPassword, setSaslPassword] = useState('');
  const [tlsEnabled, setTlsEnabled] = useState(false);
  const [tlsCaCert, setTlsCaCert] = useState('');
  const [showKafkaPassword, setShowKafkaPassword] = useState(false);
  const [note, setNote] = useState('');

  const isValid = (() => {
    if (cred.provider === 'aws_s3') {
      return accessKeyId.trim() !== '' && secretAccessKey.trim() !== '';
    }
    if (cred.provider === 'gcp_pubsub') return credentialsJson.trim() !== '';
    if (cred.provider === 'kafka') {
      if (saslMechanism && saslMechanism !== '_none') {
        return saslUsername.trim() !== '' && saslPassword.trim() !== '';
      }
      return true;
    }
    return false;
  })();

  const buildPayload = (): RotateCredentialRequest => {
    let credentials: AwsS3Credentials | GcpPubSubCredentials | KafkaCredentials;
    switch (cred.provider) {
      case 'aws_s3':
        credentials = {
          access_key_id: accessKeyId.trim(),
          secret_access_key: secretAccessKey,
        };
        break;
      case 'gcp_pubsub':
        credentials = { credentials_json: credentialsJson };
        break;
      case 'kafka':
        credentials = {
          sasl_mechanism:
            saslMechanism && saslMechanism !== '_none'
              ? (saslMechanism as 'PLAIN' | 'SCRAM-SHA-256' | 'SCRAM-SHA-512')
              : undefined,
          sasl_username: saslUsername.trim() || undefined,
          sasl_password: saslPassword || undefined,
          tls_enabled: tlsEnabled || undefined,
          tls_ca_cert: tlsEnabled && tlsCaCert.trim() ? tlsCaCert : undefined,
        };
        break;
    }
    return {
      credentials,
      note: note.trim() || undefined,
    };
  };

  return (
    <>
      <div className="border-b border-border px-5 py-4 bg-card/40 flex items-start gap-2.5 pr-12 shrink-0">
        <div className="w-7 h-7 rounded-md border border-border bg-card flex items-center justify-center shrink-0">
          <RotateCcw className="w-[14px] h-[14px] text-muted-foreground" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[14px] font-semibold text-foreground leading-tight truncate">
            Rotate — {cred.name}
          </div>
          <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mt-0.5">
            Currently active: v{cred.active_version} → next: v{cred.active_version + 1}
          </div>
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-auto px-5 py-4 space-y-4">
        <div className="rounded-md border border-border bg-foreground/[0.02] px-3 py-2.5 text-[11px] text-muted-foreground leading-relaxed flex items-start gap-2">
          <History className="w-3 h-3 mt-0.5 shrink-0" />
          <span>
            Paste the new secret material. The previous version stays retained for rollback at any
            time. Source configs pick up the new secret on their next deploy.
          </span>
        </div>

        <div className="rounded-md border border-border bg-card px-3 py-3">
          <div className="flex items-center gap-1.5 text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-2.5">
            <Icon className={cn('w-3 h-3', spec.iconClass)} />
            New {spec.label} secrets
          </div>

          {cred.provider === 'aws_s3' && (
            <div className="space-y-2.5">
              <FieldRow label="Access key ID" required>
                <Input
                  value={accessKeyId}
                  onChange={(e) => setAccessKeyId(e.target.value)}
                  placeholder="AKIA…"
                  className="h-8 text-[12px] bg-card font-mono"
                  autoFocus
                />
              </FieldRow>
              <FieldRow label="Secret access key" required secret>
                <SecretInput
                  value={secretAccessKey}
                  onChange={setSecretAccessKey}
                  reveal={showAwsSecret}
                  onToggleReveal={() => setShowAwsSecret((v) => !v)}
                />
              </FieldRow>
            </div>
          )}

          {cred.provider === 'gcp_pubsub' && (
            <FieldRow label="Service account JSON" required secret>
              <Textarea
                value={credentialsJson}
                onChange={(e) => setCredentialsJson(e.target.value)}
                rows={6}
                placeholder='{"type": "service_account", …}'
                className="text-[11.5px] font-mono bg-card resize-y min-h-[140px]"
                autoFocus
              />
            </FieldRow>
          )}

          {cred.provider === 'kafka' && (
            <div className="space-y-2.5">
              <FieldRow label="SASL mechanism">
                <select
                  value={saslMechanism}
                  onChange={(e) => setSaslMechanism(e.target.value)}
                  className="h-8 w-full rounded-md border border-border bg-card px-2.5 text-[12px] text-foreground outline-none focus:border-primary/60 font-mono"
                >
                  <option value="_none">None (unauthenticated)</option>
                  <option value="PLAIN">PLAIN</option>
                  <option value="SCRAM-SHA-256">SCRAM-SHA-256</option>
                  <option value="SCRAM-SHA-512">SCRAM-SHA-512</option>
                </select>
              </FieldRow>
              {saslMechanism && saslMechanism !== '_none' && (
                <>
                  <FieldRow label="Username" required>
                    <Input
                      value={saslUsername}
                      onChange={(e) => setSaslUsername(e.target.value)}
                      placeholder="logs-consumer"
                      className="h-8 text-[12px] bg-card"
                    />
                  </FieldRow>
                  <FieldRow label="Password" required secret>
                    <SecretInput
                      value={saslPassword}
                      onChange={setSaslPassword}
                      reveal={showKafkaPassword}
                      onToggleReveal={() => setShowKafkaPassword((v) => !v)}
                    />
                  </FieldRow>
                </>
              )}
              <label className="flex items-center gap-2 text-[11.5px] text-foreground/80 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={tlsEnabled}
                  onChange={(e) => setTlsEnabled(e.target.checked)}
                  className="rounded border-border"
                />
                Enable TLS/SSL
              </label>
              {tlsEnabled && (
                <FieldRow label="CA certificate (PEM, optional)">
                  <Textarea
                    value={tlsCaCert}
                    onChange={(e) => setTlsCaCert(e.target.value)}
                    rows={4}
                    placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}
                    className="text-[11.5px] font-mono bg-card resize-y min-h-[96px]"
                  />
                </FieldRow>
              )}
            </div>
          )}
        </div>

        <FieldRow label="Rotation note">
          <Input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Optional — e.g. quarterly rotation, suspected leak"
            className="h-8 text-[12px] bg-card"
          />
        </FieldRow>

        <div className="rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2.5 text-[11px] text-amber-700 dark:text-amber-300 leading-relaxed flex items-start gap-2">
          <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
          <span>
            Source configs using this credential will pick up the new secret on their{' '}
            <strong>next deploy</strong>. Previous versions stay retained for rollback.
          </span>
        </div>
      </div>

      <div className="border-t border-border px-5 py-3 flex items-center gap-2 bg-card/40 shrink-0">
        <Button variant="ghost" size="sm" className="h-8 text-[11.5px]" onClick={onCancel}>
          Cancel
        </Button>
        <div className="flex-1" />
        <Button
          size="sm"
          className="h-8 text-[11.5px] gap-1.5"
          disabled={!isValid || submitting}
          onClick={() => onSubmit(buildPayload())}
        >
          {submitting && <Loader2 className="w-3 h-3 animate-spin" />}
          <RotateCcw className="w-3 h-3" />
          Rotate &amp; activate v{cred.active_version + 1}
        </Button>
      </div>
    </>
  );
}

// ----- Shared field bits -----

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-1.5">
      {children}
    </div>
  );
}

function MetaCell({
  label,
  value,
  mono,
  tone,
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: 'warn' | 'danger';
}) {
  return (
    <div className="bg-card px-3 py-2">
      <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
        {label}
      </div>
      <div
        className={cn(
          'text-[11.5px] mt-0.5',
          mono && 'font-mono',
          tone === 'warn'
            ? 'text-amber-600 dark:text-amber-400'
            : tone === 'danger'
              ? 'text-red-500'
              : 'text-foreground',
        )}
      >
        {value}
      </div>
    </div>
  );
}

function FieldRow({
  label,
  required,
  secret,
  children,
}: {
  label: string;
  required?: boolean;
  secret?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-1 flex items-center gap-1.5">
        <span>{label}</span>
        {required && <span className="text-red-500">*</span>}
        {secret && <Lock className="w-[9px] h-[9px] ml-auto" />}
      </div>
      {children}
    </label>
  );
}

function SecretInput({
  value,
  onChange,
  reveal,
  onToggleReveal,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  reveal: boolean;
  onToggleReveal: () => void;
  placeholder?: string;
}) {
  return (
    <div className="relative">
      <Input
        type={reveal ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={cn(
          'h-8 text-[12px] bg-card font-mono pr-9',
          !reveal && value && 'tracking-widest',
        )}
      />
      <button
        type="button"
        onClick={onToggleReveal}
        className="absolute right-1 top-1/2 -translate-y-1/2 w-7 h-7 rounded flex items-center justify-center text-muted-foreground hover:text-foreground"
        aria-label={reveal ? 'Hide secret' : 'Show secret'}
      >
        {reveal ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
      </button>
    </div>
  );
}
