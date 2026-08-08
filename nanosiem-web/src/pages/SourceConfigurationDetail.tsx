// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowUpRight,
  Box,
  Check,
  CircleAlert,
  Cloud,
  Copy,
  Database,
  GitBranch,
  Globe,
  GripVertical,
  HelpCircle,
  Loader2,
  Lock,
  Plug,
  Plus,
  Power,
  Radio,
  Rocket,
  Save,
  Trash2,
  Zap,
} from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type {
  LogSource,
  MatchFieldPreset,
  NewRoutingRule,
  RoutingRule,
  SourceConfigType,
  SourceConfigTypeInfo,
  SourceConfigurationWithRules,
  UpdateRoutingRule,
  UpdateSourceConfiguration,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { SourceConfigForm } from '@/components/log-sources/SourceConfigForm';
import { SourceTypeCombobox } from '@/components/log-sources/SourceTypeCombobox';

// ============================================================================
// Constants & helpers
// ============================================================================

const TRANSPORT_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  http: Globe,
  vector: Radio,
  aws_s3: Cloud,
  gcp_pubsub: Cloud,
  kafka: Database,
  splunk_hec: Zap,
};

const TRANSPORT_LABEL: Record<string, string> = {
  http: 'HTTP',
  vector: 'Vector',
  aws_s3: 'AWS S3',
  gcp_pubsub: 'GCP Pub/Sub',
  kafka: 'Kafka',
  splunk_hec: 'Splunk HEC',
};

// Backend match_type values, with friendlier UI labels.
const MATCH_TYPES: Array<{
  value: string; // backend
  label: string; // dropdown label
  display: string; // short symbol shown on the rule card
}> = [
  { value: 'exact', label: 'Equals', display: '==' },
  { value: 'prefix', label: 'Starts with', display: 'starts with' },
  { value: 'suffix', label: 'Ends with', display: 'ends with' },
  { value: 'contains', label: 'Contains', display: 'contains' },
  { value: 'regex', label: 'Regex', display: 'matches /…/' },
  { value: 'default', label: 'Default (catch-all)', display: '(catch-all)' },
];

const matchTypeMeta = (value: string) =>
  MATCH_TYPES.find((m) => m.value === value) ?? { value, label: value, display: value };

// Canonical match field per transport. Backend stores these as plain strings;
// the mockup's `header:` / `body:` / `tag:` prefix conventions are display-only.
// We surface the canonical default as the "preferred" field but keep the input
// editable so legacy rules with non-canonical fields stay valid.
const CANONICAL_MATCH_FIELD: Partial<Record<SourceConfigType, { field: string; hint: string }>> = {
  http: { field: 'source_type', hint: 'Routes from the X-Source-Type header.' },
  vector: { field: 'source_type', hint: 'Vector tag/source_type.' },
  splunk_hec: { field: 'sourcetype', hint: 'Splunk HEC sourcetype field.' },
  kafka: { field: 'topic', hint: 'Kafka topic name.' },
  aws_s3: { field: 'bucket', hint: 'S3 bucket name.' },
  gcp_pubsub: { field: 'subscription', hint: 'GCP Pub/Sub subscription name.' },
};

// NAN-649: pull-source drivers (broker-bound). The detail page renders the
// two-mode UI (single source_type vs. multi) for these; HTTP / Vector keep
// today's UI exactly. Backend `is_pull_source` is the source of truth via
// the /types endpoint, but we hardcode the same set here so we can render
// before that query resolves.
//
// NAN-883: HEC is push, not pull — events arrive on the shared OOTB
// `splunk_hec_ingest` listener (:8088) with `sourcetype` in the JSON
// envelope. A user `splunk_hec` source config is a routing profile, not a
// new socket, so it shares HTTP's "one config, N rules" model.
const PULL_SOURCE_TYPES: SourceConfigType[] = ['kafka', 'aws_s3', 'aws_sqs', 'gcp_pubsub'];
const isPullSource = (t: string): boolean =>
  PULL_SOURCE_TYPES.includes(t as SourceConfigType);

// Per-driver wording for the in-form binding callout. Keeps the message
// short and concrete: what the source binds to, and how to multiplex.
const BINDING_CALLOUT: Partial<
  Record<
    SourceConfigType,
    { binding: string; multipleHint: string }
  >
> = {
  gcp_pubsub: {
    binding:
      'This Pub/Sub source binds to a single subscription. To ingest from multiple topics, create one Source Configuration per subscription.',
    multipleHint:
      'To split a single subscription into multiple source types, switch to Multiple-source-types mode below.',
  },
  kafka: {
    binding:
      'This Kafka source binds to one consumer group on one cluster. To ingest from another cluster, create a separate Source Configuration. Each Source Configuration must use a unique consumer group ID — two configs sharing a group will split partitions and each will only receive a fraction of the records.',
    multipleHint:
      'To split a single set of topics into multiple source types, switch to Multiple-source-types mode below.',
  },
  aws_s3: {
    binding:
      'This S3 source binds to a single SQS queue. To ingest from another queue or account, create a separate Source Configuration.',
    multipleHint:
      'To split objects from one queue into multiple source types, switch to Multiple-source-types mode below (e.g. by bucket or key prefix).',
  },
};

// NAN-883: HEC ships with a single OOTB listener (`splunk_hec_ingest` on
// :8088, shared `${VECTOR_AUTH_TOKEN}`). User HEC source configs are
// routing profiles only — they emit a transform consuming `hec_normalize`,
// not a new socket. Only one HEC routing config is expected per
// deployment; backend rejects duplicates with 409.
const HEC_BINDING_CALLOUT =
  'Splunk HEC events arrive on the platform-managed listener (:8088, shared token). This config decides how each event is routed based on its sourcetype. Only one HEC routing config is supported per deployment.';

const ROUTING_MODEL_DOCS_URL = 'https://nano.rs/docs/integrations/routing-model';

type PullMode = 'single' | 'multi';

/** Decide which mode to start in. Fresh configs (no rules, or only a default
 * rule) default to "single" — the simpler shape. Anything with non-default
 * rules already lives in multi-mode. */
const detectInitialPullMode = (rules: RoutingRule[]): PullMode => {
  const nonDefault = rules.filter((r) => r.match_type !== 'default');
  return nonDefault.length === 0 ? 'single' : 'multi';
};

const fmtCount = (n: number | null | undefined): string => {
  if (n == null || !Number.isFinite(n) || n <= 0) return '0';
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(2).replace(/\.?0+$/, '')}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}k`;
  return Math.round(n).toString();
};

const computeEps = (events24h: number | null | undefined): number => {
  if (!events24h || events24h <= 0) return 0;
  return events24h / 86_400;
};

const fmtRelative = (iso: string | null | undefined): string => {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return 'just now';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
};

interface AccessTelemetry {
  bytes_per_day_24h?: number | null;
  last_event_at?: string | null;
}

interface AccessRuleTelemetry {
  fires_24h?: number | null;
  last_fired_at?: string | null;
}

// ============================================================================
// Page
// ============================================================================

export default function SourceConfigurationDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { hasPermission } = useAuth();

  const canEdit = hasPermission('source_configs:edit');
  const canDeploy = hasPermission('source_configs:deploy');

  const { data: config, isLoading, refetch } = useQuery({
    queryKey: ['sourceConfig', id],
    queryFn: () => api.getSourceConfigWithRules(id!),
    enabled: !!id,
  });

  const { data: logSources = [] } = useQuery({
    queryKey: ['logSources'],
    queryFn: () => api.listLogSources(),
    staleTime: 60_000,
  });

  // NAN-649: per-driver type metadata (presets, push/pull, default field).
  // Cached forever — the data is descriptive and shipped from a static
  // hardcoded list in the backend.
  const { data: configTypes = [] } = useQuery({
    queryKey: ['sourceConfigTypes'],
    queryFn: () => api.listSourceConfigTypes(),
    staleTime: Infinity,
  });
  const typeInfo: SourceConfigTypeInfo | null = useMemo(
    () => configTypes.find((t) => t.config_type === config?.config_type) ?? null,
    [configTypes, config?.config_type],
  );

  useDocumentTitle(config?.name || 'Source Configuration', [config?.id]);
  useBreadcrumbTitle(config?.name);

  // Basic info dirty tracking
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [connectionConfig, setConnectionConfig] = useState<Record<string, unknown>>({});
  const [credentialId, setCredentialId] = useState<string | undefined>(undefined);

  // Rule editor state — backed by local copy so users can edit without saving
  // on every keystroke. Save on blur OR explicit Save (per-rule).
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [ruleDrafts, setRuleDrafts] = useState<Record<string, RoutingRule>>({});

  // Reorder dirty flag — drives "Pending Changes" detection alongside config-level edits.
  const [rulesModifiedSinceDeploy, setRulesModifiedSinceDeploy] = useState(false);

  // NAN-649: pull-source mode. `null` until config loads (so we can detect
  // initial mode from the saved rules); user-driven once set.
  const [pullMode, setPullMode] = useState<PullMode | null>(null);

  // Dialog states
  const [editConnectionOpen, setEditConnectionOpen] = useState(false);
  const [addRuleOpen, setAddRuleOpen] = useState(false);
  const [deployTargetOpen, setDeployTargetOpen] = useState(false);
  const [undeployTargetOpen, setUndeployTargetOpen] = useState(false);
  const [deleteRuleTarget, setDeleteRuleTarget] = useState<RoutingRule | null>(null);
  const [affectedLogSources, setAffectedLogSources] = useState<LogSource[]>([]);
  const [checkingAffected, setCheckingAffected] = useState(false);

  // Sync local form fields once when config first loads or after refetch.
  useEffect(() => {
    if (!config) return;
    setName(config.name ?? '');
    setDescription(config.description ?? '');
    setConnectionConfig(config.connection_config ?? {});
    setCredentialId(config.credential_id ?? undefined);
    if (!selectedRuleId && config.routing_rules.length > 0) {
      setSelectedRuleId(config.routing_rules[0]!.id);
    }
    // Drop drafts that no longer match a rule (rule deleted server-side).
    setRuleDrafts((prev) => {
      const valid: Record<string, RoutingRule> = {};
      for (const r of config.routing_rules) {
        if (prev[r.id]) valid[r.id] = prev[r.id]!;
      }
      return valid;
    });
    // NAN-649: initial pull-source mode detection (single vs. multi). Only
    // set on first load — let the user override afterwards.
    if (pullMode == null && isPullSource(config.config_type)) {
      setPullMode(detectInitialPullMode(config.routing_rules));
    }
  }, [config, selectedRuleId, pullMode]);

  // ----- Mutations -----

  const updateMutation = useMutation({
    mutationFn: (request: UpdateSourceConfiguration) =>
      api.updateSourceConfig(id!, {
        ...request,
        expected_updated_at: config?.updated_at,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfig', id] });
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      toast({ title: 'Saved' });
    },
    onError: (error) => {
      toast({ title: 'Failed to save', description: String(error), variant: 'destructive' });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ enabled }: { enabled: boolean }) => api.toggleSourceConfig(id!, enabled),
    onSuccess: (cfg) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfig', id] });
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      toast({ title: cfg.enabled ? 'Enabled' : 'Disabled' });
    },
    onError: (error) => {
      toast({ title: 'Failed to toggle', description: String(error), variant: 'destructive' });
    },
  });

  const deployMutation = useMutation({
    mutationFn: () => api.deploySourceConfig(id!),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfig', id] });
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      if (result.success) setRulesModifiedSinceDeploy(false);
      toast({
        title: result.success ? 'Deployed' : 'Deploy failed',
        description: result.message,
        variant: result.success ? 'default' : 'destructive',
      });
      setDeployTargetOpen(false);
    },
    onError: (error) => {
      toast({ title: 'Failed to deploy', description: String(error), variant: 'destructive' });
    },
  });

  const undeployMutation = useMutation({
    mutationFn: () => api.undeploySourceConfig(id!),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfig', id] });
      queryClient.invalidateQueries({ queryKey: ['sourceConfigs'] });
      toast({
        title: result.success ? 'Undeployed' : 'Undeploy failed',
        description: result.message,
        variant: result.success ? 'default' : 'destructive',
      });
      setUndeployTargetOpen(false);
    },
    onError: (error) => {
      toast({ title: 'Failed to undeploy', description: String(error), variant: 'destructive' });
    },
  });

  const createRuleMutation = useMutation({
    mutationFn: (request: NewRoutingRule) => api.createRoutingRule(id!, request),
    onSuccess: (rule) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfig', id] });
      setRulesModifiedSinceDeploy(true);
      toast({ title: 'Rule added' });
      setAddRuleOpen(false);
      setSelectedRuleId(rule.id);
    },
    onError: (error) => {
      toast({ title: 'Failed to add rule', description: String(error), variant: 'destructive' });
    },
  });

  const updateRuleMutation = useMutation({
    mutationFn: ({ ruleId, request }: { ruleId: string; request: UpdateRoutingRule }) =>
      api.updateRoutingRule(id!, ruleId, request),
    onSuccess: (_rule, vars) => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfig', id] });
      setRulesModifiedSinceDeploy(true);
      // clear the draft for this rule once persisted
      setRuleDrafts((prev) => {
        const { [vars.ruleId]: _, ...rest } = prev;
        return rest;
      });
      toast({ title: 'Rule updated' });
    },
    onError: (error) => {
      toast({ title: 'Failed to update rule', description: String(error), variant: 'destructive' });
    },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (ruleId: string) => api.deleteRoutingRule(id!, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfig', id] });
      setRulesModifiedSinceDeploy(true);
      toast({ title: 'Rule deleted' });
      setDeleteRuleTarget(null);
      setAffectedLogSources([]);
    },
    onError: (error) => {
      toast({ title: 'Failed to delete rule', description: String(error), variant: 'destructive' });
    },
  });

  const reorderMutation = useMutation({
    mutationFn: (ruleOrder: string[]) => api.reorderRoutingRules(id!, ruleOrder),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sourceConfig', id] });
      setRulesModifiedSinceDeploy(true);
    },
    onError: (error) => {
      toast({ title: 'Failed to reorder', description: String(error), variant: 'destructive' });
      // Refetch to restore server order if optimistic update was wrong.
      refetch();
    },
  });

  // ----- Derived state -----

  const hasBasicInfoChanges = useMemo(() => {
    if (!config) return false;
    return (
      name !== (config.name ?? '') ||
      (description ?? '') !== (config.description ?? '') ||
      JSON.stringify(connectionConfig) !== JSON.stringify(config.connection_config ?? {}) ||
      (credentialId ?? null) !== (config.credential_id ?? null)
    );
  }, [config, name, description, connectionConfig, credentialId]);

  const pendingChanges = useMemo<string[]>(() => {
    if (!config) return [];
    const changes: string[] = [];
    if (!config.deployed_at) {
      if (!config.deployed) changes.push('Configuration has never been deployed');
      return changes;
    }
    const deployedAt = new Date(config.deployed_at);
    if (new Date(config.updated_at) > deployedAt) changes.push('Configuration settings modified');
    const newRules = config.routing_rules.filter(
      (r) => new Date(r.created_at) > deployedAt,
    );
    if (newRules.length > 0)
      changes.push(`${newRules.length} new routing rule${newRules.length > 1 ? 's' : ''} added`);
    if (rulesModifiedSinceDeploy) changes.push('Routing rules modified');
    return changes;
  }, [config, rulesModifiedSinceDeploy]);

  const hasPendingChanges = pendingChanges.length > 0;

  // ----- Handlers -----

  const handleSaveBasicInfo = () => {
    // NAN-855: HEC connection_config is non-configurable per source — the
    // OOTB `splunk_hec_ingest` listener is shared. Always normalise to `{}`
    // so any legacy `address` / `valid_tokens` values in storage get cleared
    // on the next save (backend rejects non-empty vestigial fields).
    const normalizedConn =
      config?.config_type === 'splunk_hec' ? {} : connectionConfig;
    updateMutation.mutate({
      name: name.trim() || undefined,
      description: description.trim() || undefined,
      connection_config: normalizedConn,
      credential_id: credentialId ?? undefined,
    });
    setEditConnectionOpen(false);
  };

  const handleRuleFieldChange = (rule: RoutingRule, patch: Partial<RoutingRule>) => {
    setRuleDrafts((prev) => ({
      ...prev,
      [rule.id]: { ...rule, ...prev[rule.id], ...patch },
    }));
  };

  const handleCommitRuleDraft = (ruleId: string) => {
    const draft = ruleDrafts[ruleId];
    if (!draft) return;
    const orig = config?.routing_rules.find((r) => r.id === ruleId);
    if (!orig) return;
    const same =
      draft.match_field === orig.match_field &&
      draft.match_type === orig.match_type &&
      (draft.match_value ?? '') === (orig.match_value ?? '') &&
      draft.target_source_type === orig.target_source_type;
    if (same) {
      setRuleDrafts((prev) => {
        const { [ruleId]: _, ...rest } = prev;
        return rest;
      });
      return;
    }
    updateRuleMutation.mutate({
      ruleId,
      request: {
        match_field: draft.match_field,
        match_type: draft.match_type,
        match_value: draft.match_value || undefined,
        target_source_type: draft.target_source_type,
      },
    });
  };

  // NAN-1271: order routing rules with the `default` (catch-all) ALWAYS last
  // (see sortRulesDefaultLast). Used for the drag-reorder order so it matches
  // the displayed list in RulesList.
  const orderedRoutingRules = useMemo(
    () => sortRulesDefaultLast(config?.routing_rules ?? []),
    [config?.routing_rules],
  );

  const handleReorderDrop = (fromId: string, toId: string) => {
    if (!config || fromId === toId) return;
    const order = orderedRoutingRules.map((r) => r.id);
    const fromIdx = order.indexOf(fromId);
    const toIdx = order.indexOf(toId);
    if (fromIdx < 0 || toIdx < 0) return;
    order.splice(fromIdx, 1);
    order.splice(toIdx, 0, fromId);
    reorderMutation.mutate(order);
  };

  const checkAffectedLogSources = async (rule: RoutingRule) => {
    setCheckingAffected(true);
    try {
      const all = await api.listLogSources();
      setAffectedLogSources(
        all.filter((ls) => ls.match_values?.includes(rule.target_source_type)),
      );
    } catch (err) {
      console.error('Failed to check affected log sources:', err);
      setAffectedLogSources([]);
    } finally {
      setCheckingAffected(false);
    }
  };

  const openDeleteRule = async (rule: RoutingRule) => {
    setDeleteRuleTarget(rule);
    await checkAffectedLogSources(rule);
  };

  // ----- Render guards -----

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!config) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground">
        Source configuration not found.
      </div>
    );
  }

  const selectedRuleRaw = config.routing_rules.find((r) => r.id === selectedRuleId) ?? null;
  const selectedRule = selectedRuleRaw
    ? ruleDrafts[selectedRuleRaw.id] ?? selectedRuleRaw
    : null;

  // NAN-649: pull-source UI selector. Only relevant for pull drivers; HTTP /
  // Vector keep today's UI exactly. We default fresh pull configs to "single"
  // (one default rule, simplest mental model).
  const isPull = isPullSource(config.config_type);
  const effectivePullMode: PullMode | null = isPull ? pullMode ?? 'single' : null;
  const showSingleMode = isPull && effectivePullMode === 'single';

  // ============================================================================
  // Layout
  // ============================================================================

  return (
    <TooltipProvider delayDuration={200}>
      <div className="-m-3 flex h-[calc(100%+1.5rem)] min-h-0 flex-col overflow-hidden [contain:layout]">
        <SourceConfigHeader
          config={config}
          hasPendingChanges={hasPendingChanges}
          pendingChanges={pendingChanges}
          canEdit={canEdit}
          canDeploy={canDeploy}
          onToggle={(enabled) => toggleMutation.mutate({ enabled })}
          onDeploy={() => setDeployTargetOpen(true)}
          onUndeploy={() => setUndeployTargetOpen(true)}
          onOpenConnection={() => setEditConnectionOpen(true)}
          onViewLogs={() =>
            navigate(`/search?source_type=${encodeURIComponent(config.config_type)}`)
          }
          telemetry={config as AccessTelemetry}
        />

        {/* NAN-649: pull-source binding callout + mode switcher. HTTP / Vector
            (push sources) skip this entirely and render the legacy UI. */}
        {isPull && effectivePullMode != null && (
          <PullSourceBindingHeader
            configType={config.config_type as SourceConfigType}
            mode={effectivePullMode}
            canEdit={canEdit}
            onModeChange={setPullMode}
          />
        )}

        {/* NAN-883: HEC is push (routing profile over shared OOTB listener),
            not pull. Surface the binding model so users don't expect per-config
            ports / tokens. */}
        {config.config_type === 'splunk_hec' && (
          <HecBindingCallout />
        )}

        {showSingleMode ? (
          <div className="flex-1 min-h-0 overflow-auto">
            <SingleSourceTypeMode
              config={config}
              logSources={logSources}
              canEdit={canEdit}
              onCreateRule={(req) => createRuleMutation.mutate(req)}
              onUpdateRule={(ruleId, req) =>
                updateRuleMutation.mutate({ ruleId, request: req })
              }
              creating={createRuleMutation.isPending}
              updating={updateRuleMutation.isPending}
              onSwitchToMulti={() => setPullMode('multi')}
            />
          </div>
        ) : (
          /* Rules pane (left rail) + editor + test panel (right pane) */
          <div className="flex-1 min-h-0 grid grid-cols-[340px_1fr] grid-rows-[1fr] min-w-0">
            <RulesList
              config={config}
              selectedRuleId={selectedRuleId}
              ruleDrafts={ruleDrafts}
              logSources={logSources}
              canEdit={canEdit}
              onSelect={setSelectedRuleId}
              onAdd={() => setAddRuleOpen(true)}
              onReorder={handleReorderDrop}
            />

            <div className="h-full flex flex-col min-h-0 min-w-0 border-l-0">
              <div className="h-full min-h-0 overflow-auto">
                <RuleEditor
                  rule={selectedRule}
                  config={config}
                  typeInfo={typeInfo}
                  logSources={logSources}
                  canEdit={canEdit}
                  isDirty={selectedRuleRaw ? !!ruleDrafts[selectedRuleRaw.id] : false}
                  onChange={(patch) =>
                    selectedRuleRaw && handleRuleFieldChange(selectedRuleRaw, patch)
                  }
                  onSave={() => selectedRuleRaw && handleCommitRuleDraft(selectedRuleRaw.id)}
                  onDelete={() => selectedRuleRaw && openDeleteRule(selectedRuleRaw)}
                  saving={updateRuleMutation.isPending}
                />
              </div>
              {/* TestPanel hidden until the JS evaluator faithfully mirrors Vector's
                  per-transport field translations (e.g. HTTP X-Source-Type → source_type).
                  Re-enable once a server-side dry-run endpoint or a smarter client
                  evaluator lands. */}
            </div>
          </div>
        )}

        <DispatchedSources rules={config.routing_rules} logSources={logSources} />

        {/* ---------- Sheets / Dialogs ---------- */}

        <EditConnectionSheet
          open={editConnectionOpen}
          onOpenChange={setEditConnectionOpen}
          config={config}
          name={name}
          description={description}
          connectionConfig={connectionConfig}
          credentialId={credentialId}
          onNameChange={setName}
          onDescriptionChange={setDescription}
          onConnectionConfigChange={setConnectionConfig}
          onCredentialChange={setCredentialId}
          isDirty={hasBasicInfoChanges}
          saving={updateMutation.isPending}
          onSave={handleSaveBasicInfo}
          onCancel={() => {
            setName(config.name ?? '');
            setDescription(config.description ?? '');
            setConnectionConfig(config.connection_config ?? {});
            setCredentialId(config.credential_id ?? undefined);
            setEditConnectionOpen(false);
          }}
        />

        <AddRuleSheet
          open={addRuleOpen}
          onOpenChange={setAddRuleOpen}
          configType={config.config_type}
          typeInfo={typeInfo}
          logSources={logSources}
          submitting={createRuleMutation.isPending}
          onSubmit={(req) => createRuleMutation.mutate(req)}
        />

        <AlertDialog open={deployTargetOpen} onOpenChange={setDeployTargetOpen}>
          <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
            <AlertDialogHeader className="border-b border-border px-5 py-4">
              <AlertDialogTitle className="text-[14px] font-semibold">
                Deploy source config
              </AlertDialogTitle>
              <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground">
                Push &ldquo;{config.name}&rdquo; to Vector. Routing becomes live immediately.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <div className="px-5 py-4 text-[12px] text-foreground/90 space-y-2">
              {config.routing_rules.length === 0 && (
                <div className="text-amber-500 flex items-start gap-2">
                  <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                  <span>
                    No routing rules defined. Logs won&rsquo;t be routed to any parsers until
                    rules are added.
                  </span>
                </div>
              )}
              {hasPendingChanges && (
                <div>
                  <div className="text-[11px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-1">
                    Changes to deploy
                  </div>
                  <ul className="list-disc list-inside text-[11.5px] text-foreground/80 space-y-0.5">
                    {pendingChanges.map((c, i) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            <AlertDialogFooter className="border-t border-border px-5 py-3">
              <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
              <AlertDialogAction
                className="h-8 text-[11.5px]"
                onClick={() => deployMutation.mutate()}
              >
                {deployMutation.isPending && (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                )}
                <Rocket className="h-3.5 w-3.5" />
                Deploy
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <AlertDialog open={undeployTargetOpen} onOpenChange={setUndeployTargetOpen}>
          <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
            <AlertDialogHeader className="border-b border-border px-5 py-4">
              <AlertDialogTitle className="text-[14px] font-semibold">
                Undeploy source config
              </AlertDialogTitle>
              <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground">
                Remove &ldquo;{config.name}&rdquo; from Vector. Ingestion stops immediately.
                You can re-deploy at any time.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter className="border-t border-border px-5 py-3">
              <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
              <AlertDialogAction
                className="h-8 text-[11.5px] bg-amber-600 hover:bg-amber-700 text-white"
                onClick={() => undeployMutation.mutate()}
              >
                <Power className="h-3.5 w-3.5" />
                Undeploy
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <AlertDialog
          open={!!deleteRuleTarget}
          onOpenChange={(o) => {
            if (!o) {
              setDeleteRuleTarget(null);
              setAffectedLogSources([]);
            }
          }}
        >
          <AlertDialogContent className="max-w-lg gap-0 p-0 bg-card border-border text-foreground">
            <AlertDialogHeader className="border-b border-border px-5 py-4">
              <AlertDialogTitle className="text-[14px] font-semibold">
                Delete routing rule
              </AlertDialogTitle>
              <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground">
                {deleteRuleTarget && (
                  <>
                    Removes the rule that routes{' '}
                    <code className="text-foreground/90">{deleteRuleTarget.match_field}</code>{' '}
                    {deleteRuleTarget.match_type === 'default' ? (
                      '(catch-all)'
                    ) : (
                      <>
                        {matchTypeMeta(deleteRuleTarget.match_type).display}{' '}
                        <code className="text-foreground/90">
                          {deleteRuleTarget.match_value}
                        </code>
                      </>
                    )}{' '}
                    →{' '}
                    <code className="text-foreground/90">
                      {deleteRuleTarget.target_source_type}
                    </code>
                    .
                  </>
                )}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <div className="px-5 py-4">
              {checkingAffected ? (
                <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Checking for affected log sources…
                </div>
              ) : affectedLogSources.length > 0 ? (
                <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 flex items-start gap-2">
                  <CircleAlert className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
                  <div className="min-w-0">
                    <div className="text-[11.5px] font-medium text-amber-500">
                      {affectedLogSources.length} log source
                      {affectedLogSources.length > 1 ? 's' : ''} will stop receiving logs
                    </div>
                    <ul className="mt-1.5 text-[11px] text-foreground/80 list-disc list-inside space-y-0.5">
                      {affectedLogSources.slice(0, 6).map((ls) => (
                        <li key={ls.id} className="font-mono">
                          {ls.name}
                        </li>
                      ))}
                      {affectedLogSources.length > 6 && (
                        <li className="text-muted-foreground">
                          …and {affectedLogSources.length - 6} more
                        </li>
                      )}
                    </ul>
                  </div>
                </div>
              ) : null}
            </div>
            <AlertDialogFooter className="border-t border-border px-5 py-3">
              <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
              <AlertDialogAction
                disabled={checkingAffected}
                className="h-8 text-[11.5px] bg-red-600 hover:bg-red-700 text-white"
                onClick={() =>
                  deleteRuleTarget && deleteRuleMutation.mutate(deleteRuleTarget.id)
                }
              >
                <Trash2 className="h-3.5 w-3.5" />
                Delete rule
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </TooltipProvider>
  );
}

// ============================================================================
// Header
// ============================================================================

function SourceConfigHeader({
  config,
  hasPendingChanges,
  pendingChanges,
  canEdit,
  canDeploy,
  onToggle,
  onDeploy,
  onUndeploy,
  onOpenConnection,
  onViewLogs,
  telemetry,
}: {
  config: SourceConfigurationWithRules;
  hasPendingChanges: boolean;
  pendingChanges: string[];
  canEdit: boolean;
  canDeploy: boolean;
  onToggle: (enabled: boolean) => void;
  onDeploy: () => void;
  onUndeploy: () => void;
  onOpenConnection: () => void;
  onViewLogs: () => void;
  telemetry: AccessTelemetry;
}) {
  const Icon = TRANSPORT_ICON[config.config_type] ?? Box;
  const transportLabel = TRANSPORT_LABEL[config.config_type] ?? config.config_type;
  const eps = computeEps(config.events_24h);
  const bytesPerDay = telemetry.bytes_per_day_24h;
  const lastEventAt = telemetry.last_event_at;

  return (
    <div className="shrink-0 border-b border-border bg-card/40 px-4 py-3 flex items-center gap-4">
      <div className="w-10 h-10 rounded-md border border-border bg-card flex items-center justify-center shrink-0">
        <Icon className="w-[18px] h-[18px] text-muted-foreground" />
      </div>
      <div className="min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <h1 className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground truncate">
            {config.name}
          </h1>
          <span className="font-mono text-[10px] uppercase tracking-wider text-foreground/80 bg-foreground/[0.03] border border-border rounded px-1.5 py-0.5">
            {transportLabel}
          </span>
          {config.deployed ? (
            <span className="inline-flex items-center gap-1.5 px-2 h-[20px] rounded-[3px] bg-emerald-500/15 text-emerald-500 text-[10px] font-mono uppercase tracking-wider font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              Deployed
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2 h-[20px] rounded-[3px] bg-foreground/[0.03] text-foreground/80 border border-border text-[10px] font-mono uppercase tracking-wider font-semibold">
              Ready
            </span>
          )}
          {hasPendingChanges && (
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  className="inline-flex items-center gap-1.5 px-2 h-[20px] rounded-[3px] bg-amber-500/15 text-amber-500 text-[10px] font-mono uppercase tracking-wider font-semibold cursor-help"
                >
                  <CircleAlert className="w-3 h-3" />
                  Pending
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom" sideOffset={6} className="text-[11px]">
                <div className="font-medium mb-1">Changes not yet deployed:</div>
                <ul className="list-disc list-inside space-y-0.5">
                  {pendingChanges.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              </TooltipContent>
            </Tooltip>
          )}
        </div>
        {config.description && (
          <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed line-clamp-1 max-w-[760px]">
            {config.description}
          </div>
        )}
      </div>

      <div className="flex-1" />

      {/* Telemetry strip */}
      {config.deployed && (
        <div className="hidden lg:flex items-center gap-4 shrink-0 pr-2">
          <HeaderStat
            label="Events / 24h"
            value={fmtCount(config.events_24h)}
            mono
          />
          <div className="w-px h-8 bg-border" />
          <HeaderStat label="EPS" value={eps > 0 ? fmtCount(eps) : '0'} mono />
          <div className="w-px h-8 bg-border" />
          <HeaderStat
            label="Volume / day"
            value={bytesPerDay != null ? fmtBytes(bytesPerDay) : '—'}
            mono
            hint={
              bytesPerDay == null
                ? 'Awaiting backend telemetry.'
                : undefined
            }
          />
          <div className="w-px h-8 bg-border" />
          <HeaderStat
            label="Last event"
            value={lastEventAt ? fmtRelative(lastEventAt) : '—'}
            mono
            hint={
              lastEventAt == null
                ? 'Awaiting backend telemetry.'
                : undefined
            }
          />
        </div>
      )}

      <div className="flex items-center gap-1.5">
        {canEdit && (
          <EnabledToggle
            checked={config.enabled}
            onClick={() => onToggle(!config.enabled)}
          />
        )}
        <Button
          variant="outline"
          size="sm"
          className="h-[28px] px-2.5 text-[11.5px]"
          onClick={onOpenConnection}
        >
          <Plug className="h-3 w-3" />
          Connection
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="h-[28px] px-2.5 text-[11.5px] text-foreground/80"
          onClick={onViewLogs}
        >
          View logs
        </Button>
        {canDeploy && config.deployed && (
          <Button
            variant="outline"
            size="sm"
            className="h-[28px] px-2.5 text-[11.5px] border-amber-500/40 text-amber-500 hover:bg-amber-500/10"
            onClick={onUndeploy}
          >
            <Power className="h-3 w-3" />
            Undeploy
          </Button>
        )}
        {canDeploy && (
          <Button
            size="sm"
            className="h-[28px] px-3 text-[11.5px]"
            onClick={onDeploy}
            disabled={!hasPendingChanges && config.deployed}
          >
            <Rocket className="h-3 w-3" />
            {config.deployed ? 'Deploy changes' : 'Deploy'}
          </Button>
        )}
      </div>
    </div>
  );
}

function HeaderStat({
  label,
  value,
  mono,
  hint,
}: {
  label: string;
  value: string;
  mono?: boolean;
  hint?: string;
}) {
  const inner = (
    <div className="flex flex-col items-end">
      <div
        className={cn(
          'text-[12.5px] tabular-nums text-foreground',
          mono && 'font-mono',
        )}
      >
        {value}
      </div>
      <div className="flex items-center gap-1 text-[9px] font-mono uppercase tracking-[0.12em] text-muted-foreground mt-0.5">
        {label}
        {hint && <HelpCircle className="w-2.5 h-2.5" />}
      </div>
    </div>
  );
  if (!hint) return inner;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" className="cursor-help">
          {inner}
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom" sideOffset={6} className="text-[11px] max-w-[280px]">
        {hint}
      </TooltipContent>
    </Tooltip>
  );
}

function EnabledToggle({
  checked,
  onClick,
}: {
  checked: boolean;
  onClick: () => void;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={onClick}
          aria-pressed={checked}
          className={cn(
            'w-[30px] h-[17px] rounded-full flex items-center transition-colors relative shrink-0 mr-1',
            checked ? 'bg-primary' : 'bg-foreground/[0.05] border border-border',
          )}
        >
          <span
            className={cn(
              'absolute w-[13px] h-[13px] rounded-full bg-white shadow transition-all',
              checked ? 'left-[15px]' : 'left-[2px]',
            )}
          />
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom" sideOffset={6} className="text-[11px]">
        {checked ? 'Disable transport' : 'Enable transport'}
      </TooltipContent>
    </Tooltip>
  );
}

const fmtBytes = (n: number): string => {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let val = n;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return `${val.toFixed(val >= 100 ? 0 : 1)} ${units[i]}`;
};

// ============================================================================
// Connection summary (rendered inside the connection sheet)
// ============================================================================

function ConnectionSummary({ config }: { config: SourceConfigurationWithRules }) {
  const [copied, setCopied] = useState<string | null>(null);
  const summary = buildConnectionSummary(config);

  const copy = (key: string, text: string) => {
    void navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1400);
  };

  return (
    <div className="space-y-2">
      <ConnectionField
        label="Endpoint"
        copy={summary.full ? () => copy('endpoint', summary.full!) : undefined}
        copied={copied === 'endpoint'}
        hostHint={summary.usesPlaceholderHost}
      >
        <div className="font-mono text-[11.5px] text-foreground break-all">
          {summary.method && <span className="text-primary">{summary.method}</span>}{' '}
          <span>{summary.full ?? '—'}</span>
        </div>
      </ConnectionField>
      {summary.auth && (
        <ConnectionField label={summary.authLabel ?? 'Auth'}>
          <div className="font-mono text-[11.5px] text-foreground/80">{summary.auth}</div>
        </ConnectionField>
      )}
      {summary.headers && summary.headers.length > 0 && (
        <ConnectionField label="Headers">
          <div className="flex flex-col gap-0.5">
            {summary.headers.map((h, i) => (
              <div key={i} className="font-mono text-[11.5px]">
                <span className="text-muted-foreground">{h.key}:</span>{' '}
                <span className="text-foreground">{h.value}</span>
                {h.hint && (
                  <span className="text-muted-foreground/70 ml-2">({h.hint})</span>
                )}
              </div>
            ))}
          </div>
        </ConnectionField>
      )}
      {summary.snippet && (
        <div className="bg-card border border-border rounded-md px-3 py-2">
          <div className="flex items-center justify-between mb-1.5">
            <div className="text-[9px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Example
            </div>
            <button
              type="button"
              onClick={() => copy('snippet', summary.snippet!)}
              className="text-[10px] text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
            >
              {copied === 'snippet' ? (
                <>
                  <Check className="w-[10px] h-[10px] text-emerald-500" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-[10px] h-[10px]" /> Copy
                </>
              )}
            </button>
          </div>
          <pre className="font-mono text-[10.5px] text-foreground/80 leading-[1.55] whitespace-pre-wrap">
            {summary.snippet}
          </pre>
        </div>
      )}
    </div>
  );
}

function ConnectionField({
  label,
  copy,
  copied,
  hostHint,
  children,
}: {
  label: string;
  copy?: () => void;
  copied?: boolean;
  hostHint?: boolean;
  children: ReactNode;
}) {
  return (
    <div className="bg-card border border-border rounded-md px-3 py-2">
      <div className="flex items-center justify-between mb-0.5 gap-2">
        <div className="flex items-center gap-1 text-[9px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
          {label}
          {hostHint && (
            <Tooltip>
              <TooltipTrigger asChild>
                <button type="button" className="cursor-help">
                  <HelpCircle className="w-2.5 h-2.5" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom" sideOffset={6} className="text-[11px] max-w-[260px]">
                Replace <code className="font-mono">{'{your-ingest-host}'}</code> with your
                deployment&rsquo;s ingest host (find it in your tenant at{' '}
                <span className="font-mono">app.nano.rs</span>).
              </TooltipContent>
            </Tooltip>
          )}
        </div>
        {copy && (
          <button
            type="button"
            onClick={copy}
            className="text-[10px] text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
          >
            {copied ? (
              <>
                <Check className="w-[10px] h-[10px] text-emerald-500" /> Copied
              </>
            ) : (
              <>
                <Copy className="w-[10px] h-[10px]" /> Copy
              </>
            )}
          </button>
        )}
      </div>
      {children}
    </div>
  );
}

interface ConnectionSummary {
  method?: string;
  display: string;
  full?: string;
  authLabel?: string;
  auth?: string;
  headers?: Array<{ key: string; value: string; hint?: string }>;
  snippet?: string;
  usesPlaceholderHost: boolean;
}

function buildConnectionSummary(config: SourceConfigurationWithRules): ConnectionSummary {
  const cc = config.connection_config ?? {};
  const HOST = '{your-ingest-host}';
  const usesPlaceholderHost = true;

  switch (config.config_type) {
    case 'http': {
      const port = (cc.port as number | string) ?? 9090;
      const path = (cc.path as string) ?? '/ingest';
      const full = `https://${HOST}:${port}${path}`;
      return {
        method: 'POST',
        full,
        display: `POST ${path}`,
        authLabel: 'Auth',
        auth: 'Bearer ${NANO_INGEST_TOKEN}',
        headers: [
          { key: 'Content-Type', value: 'application/json' },
          {
            key: 'X-Source-Type',
            value: '<source_type>',
            hint: 'matched by routing rules',
          },
        ],
        snippet: [
          `curl -X POST ${full} \\`,
          `  -H 'Authorization: Bearer $NANO_INGEST_TOKEN' \\`,
          `  -H 'Content-Type: application/json' \\`,
          `  -H 'X-Source-Type: aws_cloudtrail' \\`,
          `  -d '{"eventSource":"s3.amazonaws.com",…}'`,
        ].join('\n'),
        usesPlaceholderHost,
      };
    }
    case 'vector': {
      const address = (cc.address as string) ?? `${HOST}:6000`;
      return {
        method: 'SOCKET',
        full: `vector://${address}`,
        display: `Vector ${address.includes(':') ? address : ':6000'}`,
        authLabel: 'Auth',
        auth: 'mTLS (certificate pinned)',
        headers: [],
        snippet: [
          '# In your upstream Vector config:',
          '[sinks.nano]',
          'type      = "vector"',
          `address   = "${address}"`,
          'inputs    = ["your_source"]',
          'tls.enabled = true',
        ].join('\n'),
        usesPlaceholderHost,
      };
    }
    case 'aws_s3': {
      const sqs = (cc.sqs_queue_url as string) ?? `arn:aws:sqs:us-east-1:••••:nano-ingest`;
      return {
        method: 'SQS',
        full: sqs,
        display: 'SQS-driven',
        authLabel: 'Assume role',
        auth: config.credential_id
          ? `credential ${config.credential_id}`
          : '(no credential attached)',
        headers: [],
        snippet: [
          '# S3 event notifications → SQS → nano poller',
          '# Configure in the S3 bucket properties:',
          'Event type: s3:ObjectCreated:*',
          `Destination: ${sqs}`,
          'Then grant sqs:ReceiveMessage to the assumed role above.',
        ].join('\n'),
        usesPlaceholderHost: false,
      };
    }
    case 'gcp_pubsub': {
      const project = (cc.project as string) ?? '<project>';
      const subscription = (cc.subscription as string) ?? '<subscription>';
      const full = subscription.startsWith('projects/')
        ? subscription
        : `projects/${project}/subscriptions/${subscription}`;
      return {
        method: 'SUB',
        full,
        display: 'Pub/Sub subscription',
        authLabel: 'Service account',
        auth: config.credential_id
          ? `credential ${config.credential_id}`
          : '(no credential attached)',
        headers: [],
        usesPlaceholderHost: false,
      };
    }
    case 'kafka': {
      const bootstrap = (cc.bootstrap_servers as string) ?? '<bootstrap>';
      const topics = ((cc.topics as string[]) ?? []).join(', ') || '<topics>';
      return {
        method: 'CONSUME',
        full: `bootstrap=${bootstrap}  topics=${topics}`,
        display: 'Kafka consumer',
        authLabel: 'Auth',
        auth: config.credential_id
          ? `credential ${config.credential_id}`
          : 'SASL_SSL / SCRAM-SHA-512',
        headers: [],
        usesPlaceholderHost: false,
      };
    }
    case 'splunk_hec': {
      const port = (cc.port as number | string) ?? 8088;
      const full = `https://${HOST}:${port}/services/collector/event`;
      return {
        method: 'POST',
        full,
        display: `Splunk HEC :${port}`,
        authLabel: 'Auth',
        auth: 'Splunk HEC token (rotate via credentials)',
        headers: [{ key: 'Authorization', value: 'Splunk <token>' }],
        snippet: [
          `curl -X POST ${full} \\`,
          `  -H 'Authorization: Splunk $HEC_TOKEN' \\`,
          `  -d '{"event":{…},"sourcetype":"okta:log"}'`,
        ].join('\n'),
        usesPlaceholderHost,
      };
    }
    default:
      return { display: 'No endpoint summary', usesPlaceholderHost: false };
  }
}

// ============================================================================
// Edit connection sheet
// ============================================================================

function EditConnectionSheet({
  open,
  onOpenChange,
  config,
  name,
  description,
  connectionConfig,
  credentialId,
  onNameChange,
  onDescriptionChange,
  onConnectionConfigChange,
  onCredentialChange,
  isDirty,
  saving,
  onSave,
  onCancel,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  config: SourceConfigurationWithRules;
  name: string;
  description: string;
  connectionConfig: Record<string, unknown>;
  credentialId: string | undefined;
  onNameChange: (v: string) => void;
  onDescriptionChange: (v: string) => void;
  onConnectionConfigChange: (v: Record<string, unknown>) => void;
  onCredentialChange: (id: string | undefined) => void;
  isDirty: boolean;
  saving: boolean;
  onSave: () => void;
  onCancel: () => void;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-[560px] sm:max-w-[560px] gap-0 p-0 bg-card border-l border-border text-foreground flex flex-col"
      >
        <SheetHeader className="border-b border-border px-5 py-4">
          <SheetTitle className="text-[14px] font-semibold">Connection</SheetTitle>
          <SheetDescription className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            {TRANSPORT_LABEL[config.config_type] ?? config.config_type}
          </SheetDescription>
        </SheetHeader>
        <div className="flex-1 min-h-0 overflow-y-auto px-5 py-4 space-y-5">
          <section className="space-y-2">
            <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Details
            </div>
            <ConnectionSummary config={config} />
          </section>
          <section className="space-y-3 border-t border-border pt-4">
            <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Edit settings
            </div>
            <div className="space-y-1.5">
              <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
                Name
              </Label>
              <Input
                value={name}
                onChange={(e) => onNameChange(e.target.value)}
                className="h-8 text-[12px] bg-card"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
                Description
              </Label>
              <Textarea
                value={description}
                onChange={(e) => onDescriptionChange(e.target.value)}
                className="text-[12px] bg-card min-h-[60px]"
              />
            </div>
            <div>
              <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-2 block">
                Connection settings
              </Label>
              <SourceConfigForm
                sourceType={config.config_type}
                config={connectionConfig}
                onConfigChange={onConnectionConfigChange}
                credentialId={credentialId}
                onCredentialChange={onCredentialChange}
              />
            </div>
          </section>
        </div>
        <SheetFooter className="border-t border-border px-5 py-3 flex-row sm:justify-between sm:space-x-0">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 text-[11.5px]"
            onClick={onCancel}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-8 text-[11.5px]"
            disabled={!isDirty || saving}
            onClick={onSave}
          >
            {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            <Save className="h-3.5 w-3.5" />
            Save
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// ============================================================================
// Rules list (left rail)
// ============================================================================

// NAN-1271: routing rules ordered with the `default` (catch-all) rule ALWAYS
// last, regardless of stored priority. The backend pins defaults last on every
// write, but this keeps the UI correct even for legacy rows (a fallback once
// seeded at priority 0 would otherwise sort first and look like it matches
// before every real rule).
function sortRulesDefaultLast(rules: RoutingRule[]): RoutingRule[] {
  return [...rules].sort(
    (a, b) =>
      Number(a.match_type === 'default') - Number(b.match_type === 'default') ||
      a.priority - b.priority,
  );
}

function RulesList({
  config,
  selectedRuleId,
  ruleDrafts,
  logSources,
  canEdit,
  onSelect,
  onAdd,
  onReorder,
}: {
  config: SourceConfigurationWithRules;
  selectedRuleId: string | null;
  ruleDrafts: Record<string, RoutingRule>;
  logSources: LogSource[];
  canEdit: boolean;
  onSelect: (id: string) => void;
  onAdd: () => void;
  onReorder: (fromId: string, toId: string) => void;
}) {
  const [dragId, setDragId] = useState<string | null>(null);
  const matchValueSet = useMemo(
    () => new Set(logSources.flatMap((ls) => ls.match_values ?? [])),
    [logSources],
  );
  const sourceTypeSet = useMemo(
    () => new Set(logSources.map((ls) => ls.source_type)),
    [logSources],
  );

  const hasParser = (rule: RoutingRule): boolean =>
    sourceTypeSet.has(rule.target_source_type) || matchValueSet.has(rule.target_source_type);

  return (
    <div className="flex flex-col min-h-0 bg-card/30 border-r border-border">
      <div className="flex items-center justify-between px-3 h-[36px] border-b border-border shrink-0">
        <div className="flex items-center gap-2">
          <GitBranch className="w-3.5 h-3.5 text-muted-foreground" />
          <div className="text-[10px] font-mono uppercase tracking-[0.12em] font-semibold text-foreground/80">
            Routing rules
          </div>
          <span className="font-mono text-[10px] text-muted-foreground">
            {config.routing_rules.length}
          </span>
        </div>
        {canEdit && (
          <button
            type="button"
            onClick={onAdd}
            className="h-[22px] px-2 rounded-[4px] border border-border text-foreground/80 hover:text-foreground hover:bg-foreground/[0.05] text-[11px] inline-flex items-center gap-1"
          >
            <Plus className="w-[11px] h-[11px]" />
            Add rule
          </button>
        )}
      </div>
      <div className="px-3 py-1.5 border-b border-border bg-foreground/[0.02] shrink-0">
        <div className="text-[10.5px] text-muted-foreground leading-relaxed">
          Ordered list — <span className="text-foreground/80">first match wins</span>. A
          default rule catches anything unmatched.
        </div>
      </div>
      <div className="flex-1 min-h-0 overflow-auto">
        {config.routing_rules.length === 0 ? (
          <div className="px-4 py-8 text-center text-[11.5px] text-muted-foreground">
            No routing rules yet. Add one to start dispatching events to a parser.
          </div>
        ) : (
          sortRulesDefaultLast(config.routing_rules).map((rule, i) => {
            const draft = ruleDrafts[rule.id];
            const display = draft ?? rule;
            const meta = matchTypeMeta(display.match_type);
            const fallback = display.match_type === 'default';
            const fires = (rule as RoutingRule & AccessRuleTelemetry).fires_24h;
            const lastFired = (rule as RoutingRule & AccessRuleTelemetry).last_fired_at;
            return (
              <div
                key={rule.id}
                draggable={canEdit && !fallback}
                onDragStart={() => setDragId(rule.id)}
                onDragEnd={() => setDragId(null)}
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => {
                  if (dragId && dragId !== rule.id) onReorder(dragId, rule.id);
                  setDragId(null);
                }}
                onClick={() => onSelect(rule.id)}
                className={cn(
                  'relative px-3 py-2.5 border-b border-border cursor-pointer transition-colors',
                  selectedRuleId === rule.id
                    ? 'bg-foreground/[0.04]'
                    : 'hover:bg-foreground/[0.02]',
                  dragId === rule.id && 'opacity-40',
                )}
              >
                {selectedRuleId === rule.id && (
                  <div className="absolute left-0 top-0 bottom-0 w-[2px] bg-primary" />
                )}
                <div className="flex items-start gap-2">
                  <div className="flex flex-col items-center gap-0.5 mt-0.5 shrink-0">
                    <div className="font-mono text-[9.5px] text-muted-foreground tabular-nums">
                      {fallback ? '↓' : String(i + 1).padStart(2, '0')}
                    </div>
                    {!fallback && canEdit && (
                      <GripVertical className="w-3 h-3 text-muted-foreground/60 cursor-grab" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <div className="text-[12.5px] font-medium text-foreground truncate">
                        {display.match_field || '(unnamed)'}
                      </div>
                      {fallback && (
                        <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground border border-border rounded px-1 py-px">
                          fallback
                        </span>
                      )}
                      {draft && (
                        <span className="font-mono text-[9px] uppercase tracking-wider text-amber-500 border border-amber-500/30 rounded px-1 py-px">
                          unsaved
                        </span>
                      )}
                    </div>
                    <div className="font-mono text-[10.5px] text-muted-foreground leading-[1.4] truncate">
                      {fallback ? (
                        <span className="text-muted-foreground/70">(any unmatched event)</span>
                      ) : (
                        <>
                          <span className="text-foreground/80">{display.match_field}</span>
                          <span className="text-muted-foreground/60 mx-1">{meta.display}</span>
                          {display.match_value && (
                            <span className="text-foreground">&quot;{display.match_value}&quot;</span>
                          )}
                        </>
                      )}
                    </div>
                    <div className="flex items-center gap-2 mt-1.5 font-mono text-[10px]">
                      <div className="flex items-center gap-1 text-muted-foreground">
                        <span className="text-muted-foreground/60">→</span>
                        <span className="text-foreground/80 truncate">
                          {display.target_source_type}
                        </span>
                      </div>
                      {!hasParser(rule) && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="inline-flex items-center text-amber-500 cursor-help">
                              <AlertTriangle className="w-3 h-3" />
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="top" sideOffset={6} className="text-[11px] max-w-[260px]">
                            No log source has this source_type in its match_values yet.
                          </TooltipContent>
                        </Tooltip>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-0.5 shrink-0">
                    <div className="font-mono text-[10.5px] text-foreground tabular-nums">
                      {fires != null ? fmtCount(fires) : '—'}
                    </div>
                    <div className="font-mono text-[9px] text-muted-foreground/70">
                      {lastFired ? fmtRelative(lastFired) : ''}
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Rule editor (right pane top)
// ============================================================================

function RuleEditor({
  rule,
  config,
  typeInfo,
  logSources,
  canEdit,
  isDirty,
  onChange,
  onSave,
  onDelete,
  saving,
}: {
  rule: RoutingRule | null;
  config: SourceConfigurationWithRules;
  typeInfo: SourceConfigTypeInfo | null;
  logSources: LogSource[];
  canEdit: boolean;
  isDirty: boolean;
  onChange: (patch: Partial<RoutingRule>) => void;
  onSave: () => void;
  onDelete: () => void;
  saving: boolean;
}) {
  if (!rule) {
    return (
      <div className="p-6 text-muted-foreground text-[12px]">Select a rule on the left.</div>
    );
  }
  const fallback = rule.match_type === 'default';
  const canonical = CANONICAL_MATCH_FIELD[config.config_type];
  const isCanonicalLocked =
    canonical != null && rule.match_field === canonical.field && !fallback;
  // NAN-649: per-driver presets — surface as a Select on pull sources.
  // HTTP / Vector keep the canonical-locked Input (one preset only).
  const presets: MatchFieldPreset[] = typeInfo?.match_field_presets ?? [];
  const isPull = isPullSource(config.config_type);
  const showPresetSelect = isPull && presets.length > 0 && !fallback;
  const matchedPreset = presets.find((p) => p.path === rule.match_field) ?? null;

  return (
    <div className="p-4 space-y-4">
      {/* Action row */}
      <div className="flex items-center gap-3">
        <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
          Rule
        </div>
        <div className="flex-1" />
        {canEdit && isDirty && (
          <Button
            size="sm"
            className="h-[26px] text-[11px]"
            onClick={onSave}
            disabled={saving}
          >
            {saving && <Loader2 className="h-3 w-3 animate-spin" />}
            <Save className="h-3 w-3" />
            Save changes
          </Button>
        )}
        {canEdit && !fallback && (
          <Button
            variant="ghost"
            size="sm"
            className="h-[26px] text-[11px] text-red-500 hover:bg-red-500/10"
            onClick={onDelete}
          >
            <Trash2 className="h-3 w-3" />
            Delete
          </Button>
        )}
      </div>

      {/* Match section */}
      <SectionCard title="Match">
        <div className="grid grid-cols-[1fr_140px_1fr] gap-2">
          <NanoLabel>Field</NanoLabel>
          <NanoLabel>Operator</NanoLabel>
          <NanoLabel>Value</NanoLabel>

          {showPresetSelect ? (
            <MatchFieldPresetSelect
              presets={presets}
              value={rule.match_field}
              onChange={(v) => onChange({ match_field: v })}
              disabled={!canEdit}
            />
          ) : isCanonicalLocked ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <div
                  className={cn(
                    'h-[28px] rounded-md border border-border bg-foreground/[0.02] px-2.5',
                    'flex items-center gap-2 text-[12px] font-mono text-foreground',
                  )}
                >
                  <Lock className="w-[10px] h-[10px] text-muted-foreground shrink-0" />
                  <span className="truncate">{rule.match_field}</span>
                  <span className="ml-auto text-[9.5px] text-muted-foreground uppercase tracking-[0.1em] shrink-0">
                    canonical
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent side="top" sideOffset={6} className="text-[11px] max-w-[260px]">
                {canonical?.hint} Edit advanced via &ldquo;Use custom field&rdquo;.
              </TooltipContent>
            </Tooltip>
          ) : (
            <Input
              value={rule.match_field}
              onChange={(e) => onChange({ match_field: e.target.value })}
              disabled={!canEdit || fallback}
              placeholder={canonical?.field ?? 'source_type'}
              className="h-[28px] text-[12px] font-mono bg-card"
            />
          )}

          <Select
            value={rule.match_type}
            disabled={!canEdit || fallback}
            onValueChange={(v) => onChange({ match_type: v })}
          >
            <SelectTrigger className="h-8 text-[12px] font-mono bg-card">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {MATCH_TYPES.map((m) => (
                <SelectItem key={m.value} value={m.value} className="text-[12px]">
                  {m.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Input
            value={rule.match_value ?? ''}
            disabled={!canEdit || fallback || rule.match_type === 'default'}
            onChange={(e) => onChange({ match_value: e.target.value })}
            placeholder={rule.match_type === 'regex' ? '^pattern$' : 'value…'}
            className="h-[28px] text-[12px] font-mono bg-card"
          />
        </div>

        <div className="text-[10.5px] text-muted-foreground leading-relaxed pt-1.5 flex items-center gap-2 flex-wrap">
          {rule.match_type === 'default'
            ? 'Catches any event not matched by a preceding rule. Route to a safe default parser.'
            : rule.match_type === 'regex'
              ? 'POSIX-extended regex. Anchor with ^ and $ if needed.'
              : 'Comparison is case-sensitive. Values are exact strings unless using regex.'}
          {showPresetSelect && matchedPreset != null && (
            <span className="font-mono text-foreground/70">
              .{matchedPreset.path} — {matchedPreset.description}
            </span>
          )}
          {!showPresetSelect && canonical && !isCanonicalLocked && !fallback && canEdit && (
            <button
              type="button"
              onClick={() => onChange({ match_field: canonical.field })}
              className="text-primary hover:underline ml-auto"
            >
              Use canonical field ({canonical.field})
            </button>
          )}
          {!showPresetSelect && isCanonicalLocked && canEdit && (
            <button
              type="button"
              onClick={() => onChange({ match_field: '' })}
              className="text-muted-foreground hover:text-foreground hover:underline ml-auto"
            >
              Use custom field
            </button>
          )}
        </div>
      </SectionCard>

      {/* Target section */}
      <SectionCard title="Target">
        <div className="space-y-3">
          <div>
            <NanoLabel>Source type (parser tag)</NanoLabel>
            <SourceTypeCombobox
              value={rule.target_source_type}
              onChange={(v) => onChange({ target_source_type: v })}
              logSources={logSources}
              placeholder="Select a parser…"
              disabled={!canEdit}
            />
            <div className="text-[10.5px] text-muted-foreground leading-relaxed mt-1.5">
              Events carry this tag downstream — log sources subscribe by it.
            </div>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

function SectionCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-card border border-border rounded-md overflow-hidden">
      <div className="px-3 h-[28px] flex items-center border-b border-border bg-foreground/[0.02]">
        <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-foreground/80 font-semibold">
          {title}
        </div>
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}

function NanoLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground mb-1">
      {children}
    </div>
  );
}


// ============================================================================
// Dispatched log sources strip
// ============================================================================

function DispatchedSources({
  rules,
  logSources,
}: {
  rules: RoutingRule[];
  logSources: LogSource[];
}) {
  const dispatched = useMemo(() => {
    const targets = new Set(rules.map((r) => r.target_source_type));
    return logSources.filter(
      (ls) =>
        targets.has(ls.source_type) ||
        (ls.match_values?.some((v) => targets.has(v)) ?? false),
    );
  }, [rules, logSources]);

  return (
    <div className="shrink-0 border-t border-border bg-card/30 px-4 py-2.5 flex items-center gap-3 flex-wrap">
      <div className="flex items-center gap-2 shrink-0">
        <ArrowUpRight className="w-3 h-3 text-muted-foreground" />
        <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Dispatches to
        </div>
        <span className="font-mono text-[11px] text-foreground/80">
          {dispatched.length} log source{dispatched.length === 1 ? '' : 's'}
        </span>
      </div>
      <div className="flex items-center gap-1.5 flex-wrap">
        {dispatched.length === 0 ? (
          <span className="font-mono text-[10.5px] text-muted-foreground/70">
            (no log sources subscribe to these source types)
          </span>
        ) : (
          dispatched.map((ls) => (
            <a
              key={ls.id}
              href={`/ingestion/log-sources/${ls.id}`}
              className="font-mono text-[10.5px] text-foreground/80 bg-card border border-border rounded px-2 py-1 hover:border-primary/40 hover:text-primary transition-colors inline-flex items-center gap-1"
            >
              {ls.name}
              <ArrowUpRight className="w-[9px] h-[9px] opacity-60" />
            </a>
          ))
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Add rule sheet
// ============================================================================

function AddRuleSheet({
  open,
  onOpenChange,
  configType,
  typeInfo,
  logSources,
  submitting,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  configType: string;
  typeInfo: SourceConfigTypeInfo | null;
  logSources: LogSource[];
  submitting: boolean;
  onSubmit: (req: NewRoutingRule) => void;
}) {
  const canonical = CANONICAL_MATCH_FIELD[configType as SourceConfigType];
  const presets: MatchFieldPreset[] = typeInfo?.match_field_presets ?? [];
  const isPull = isPullSource(configType);
  const showPresetSelect = isPull && presets.length > 0;
  // First preset is always the recommended one; fall back to canonical for
  // push sources and for pull sources without a fetched type metadata.
  const defaultField = showPresetSelect
    ? presets[0]?.path ?? canonical?.field ?? ''
    : canonical?.field ?? '';
  const [matchField, setMatchField] = useState('');
  const [matchType, setMatchType] = useState('prefix');
  const [matchValue, setMatchValue] = useState('');
  const [targetSourceType, setTargetSourceType] = useState('');

  useEffect(() => {
    if (open) {
      setMatchField(defaultField);
      setMatchType('prefix');
      setMatchValue('');
      setTargetSourceType('');
    }
  }, [open, defaultField]);

  const submit = () => {
    if (!matchField || !targetSourceType) return;
    onSubmit({
      match_field: matchField,
      match_type: matchType,
      match_value: matchType === 'default' ? undefined : matchValue || undefined,
      target_source_type: targetSourceType,
    });
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-[520px] sm:max-w-[520px] gap-0 p-0 bg-card border-l border-border text-foreground flex flex-col"
      >
        <SheetHeader className="border-b border-border px-5 py-4">
          <SheetTitle className="text-[14px] font-semibold">Add routing rule</SheetTitle>
          <SheetDescription className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            First match wins · ordered by priority
          </SheetDescription>
        </SheetHeader>
        <div className="flex-1 min-h-0 overflow-y-auto px-5 py-4 space-y-4">
          <div className="space-y-1.5">
            <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Match field
            </Label>
            {showPresetSelect ? (
              <MatchFieldPresetSelect
                presets={presets}
                value={matchField}
                onChange={setMatchField}
              />
            ) : (
              <Input
                value={matchField}
                onChange={(e) => setMatchField(e.target.value)}
                placeholder={canonical?.field ?? 'source_type'}
                className="h-8 text-[12px] font-mono bg-card"
              />
            )}
            {showPresetSelect ? (
              <p className="text-[10.5px] text-muted-foreground">
                {presets.find((p) => p.path === matchField)?.description ??
                  'Pick the field your publisher labels events with.'}
              </p>
            ) : (
              canonical && (
                <p className="text-[10.5px] text-muted-foreground">
                  Canonical field for this transport: <span className="font-mono">{canonical.field}</span>{' '}
                  — {canonical.hint}
                </p>
              )
            )}
          </div>
          <div className="space-y-1.5">
            <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Match type
            </Label>
            <Select value={matchType} onValueChange={setMatchType}>
              <SelectTrigger className="h-8 text-[12px] font-mono bg-card">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {MATCH_TYPES.map((m) => (
                  <SelectItem key={m.value} value={m.value} className="text-[12px]">
                    {m.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {matchType !== 'default' && (
            <div className="space-y-1.5">
              <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
                Match value
              </Label>
              <Input
                value={matchValue}
                onChange={(e) => setMatchValue(e.target.value)}
                placeholder={matchType === 'regex' ? '^pattern$' : 'value…'}
                className="h-8 text-[12px] font-mono bg-card"
              />
            </div>
          )}
          <div className="space-y-1.5">
            <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Target source type (parser tag)
            </Label>
            <SourceTypeCombobox
              value={targetSourceType}
              onChange={setTargetSourceType}
              logSources={logSources}
              placeholder="Select a parser…"
            />
          </div>
        </div>
        <SheetFooter className="border-t border-border px-5 py-3 flex-row sm:justify-between sm:space-x-0">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 text-[11.5px]"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-8 text-[11.5px]"
            disabled={submitting || !matchField || !targetSourceType}
            onClick={submit}
          >
            {submitting && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Add rule
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// ============================================================================
// NAN-649: Pull-source binding callout + mode switcher
// ============================================================================

/**
 * Above-the-fold explanatory bar shown only for pull sources (Pub/Sub, Kafka,
 * S3, HEC). The wording explains the broker binding model so users stop
 * trying to mirror HTTP's "one config, N source_types" pattern in places where
 * it doesn't apply, and offers a one-click mode switch.
 */
function PullSourceBindingHeader({
  configType,
  mode,
  canEdit,
  onModeChange,
}: {
  configType: SourceConfigType;
  mode: PullMode;
  canEdit: boolean;
  onModeChange: (m: PullMode) => void;
}) {
  const copy = BINDING_CALLOUT[configType];
  return (
    <div className="shrink-0 border-b border-border bg-foreground/[0.02] px-4 py-2.5">
      <div className="flex items-start gap-3 flex-wrap">
        <div className="flex-1 min-w-[280px]">
          <div className="text-[11.5px] text-foreground/85 leading-relaxed">
            {copy?.binding}{' '}
            {mode === 'single' && copy?.multipleHint}
          </div>
          <a
            href={ROUTING_MODEL_DOCS_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 mt-1 text-[10.5px] text-primary hover:underline"
          >
            Learn about pull-source routing
            <ArrowUpRight className="w-2.5 h-2.5" />
          </a>
        </div>
        {/* Mode switcher: segmented control. Disabled (read-only display)
            when the user lacks edit permission. */}
        <div
          role="tablist"
          aria-label="Routing mode"
          className="inline-flex items-stretch rounded-md border border-border bg-card overflow-hidden shrink-0"
        >
          <ModeButton
            label="Single source type"
            active={mode === 'single'}
            disabled={!canEdit}
            onClick={() => onModeChange('single')}
          />
          <div className="w-px bg-border" />
          <ModeButton
            label="Multiple source types"
            active={mode === 'multi'}
            disabled={!canEdit}
            onClick={() => onModeChange('multi')}
          />
        </div>
      </div>
    </div>
  );
}

/**
 * NAN-883: push-side HEC explanatory bar. HEC is not a per-config socket —
 * it consumes from the shared `splunk_hec_ingest` listener (:8088) with the
 * platform `${VECTOR_AUTH_TOKEN}`. This rules table is just the routing
 * profile for that shared stream.
 */
function HecBindingCallout() {
  return (
    <div className="shrink-0 border-b border-border bg-foreground/[0.02] px-4 py-2.5">
      <div className="text-[11.5px] text-foreground/85 leading-relaxed max-w-[860px]">
        {HEC_BINDING_CALLOUT}
      </div>
    </div>
  );
}

function ModeButton({
  label,
  active,
  disabled,
  onClick,
}: {
  label: string;
  active: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      disabled={disabled}
      onClick={onClick}
      className={cn(
        'h-[26px] px-3 text-[11px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60',
        active
          ? 'bg-foreground/[0.06] text-foreground'
          : 'text-muted-foreground hover:bg-foreground/[0.03] hover:text-foreground',
      )}
    >
      {label}
    </button>
  );
}

// ============================================================================
// NAN-649: per-driver match_field preset Select
// ============================================================================

/**
 * Renders the per-driver match_field preset list as a Select. Falls back to
 * a free-text Input when the user picks "Custom path" (handled by the
 * "__custom__" sentinel value the parent maps onto the rule) — keeps power
 * users unblocked without making the dropdown the only path.
 */
function MatchFieldPresetSelect({
  presets,
  value,
  onChange,
  disabled,
}: {
  presets: MatchFieldPreset[];
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  // If the current `value` is a known preset, render the dropdown.
  // Otherwise render an Input with a tiny "Use preset" affordance — keeps
  // legacy free-text rules editable.
  const matched = presets.find((p) => p.path === value);
  const [customMode, setCustomMode] = useState<boolean>(matched == null && value !== '');

  // If `value` becomes a preset path again (e.g. after parent reset), exit
  // custom mode automatically.
  useEffect(() => {
    if (presets.find((p) => p.path === value) != null) {
      setCustomMode(false);
    }
  }, [presets, value]);

  if (customMode) {
    return (
      <div className="flex items-center gap-1.5">
        <Input
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          placeholder="custom.vrl.path"
          className="h-[28px] text-[12px] font-mono bg-card"
        />
        <button
          type="button"
          onClick={() => {
            setCustomMode(false);
            onChange(presets[0]?.path ?? '');
          }}
          disabled={disabled}
          className="text-[10px] text-muted-foreground hover:text-foreground hover:underline shrink-0 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Use preset
        </button>
      </div>
    );
  }

  return (
    <Select
      value={matched?.path ?? presets[0]?.path ?? ''}
      disabled={disabled}
      onValueChange={(v) => {
        if (v === '__custom__') {
          setCustomMode(true);
          onChange('');
          return;
        }
        onChange(v);
      }}
    >
      <SelectTrigger className="h-8 text-[12px] font-mono bg-card">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {presets.map((p) => (
          <SelectItem key={p.path} value={p.path} className="text-[12px]">
            <div className="flex flex-col">
              <span className="font-medium">{p.label}</span>
              <span className="font-mono text-[10.5px] text-muted-foreground">
                .{p.path}
              </span>
            </div>
          </SelectItem>
        ))}
        <SelectItem value="__custom__" className="text-[12px] text-muted-foreground">
          Custom path…
        </SelectItem>
      </SelectContent>
    </Select>
  );
}

// ============================================================================
// NAN-649: Single-source-type mode (pull sources only)
// ============================================================================

/**
 * Simplified routing UI for pull configs with exactly one downstream
 * source_type — the LimaCharlie / Pub/Sub-per-vendor case. Renders one input
 * for the parser tag and persists it as a single `match_type=default` rule.
 *
 * If the user later adds non-default rules through "Multiple source types"
 * mode, this component becomes inaccessible (parent switches mode) — both
 * data shapes coexist on the same routing_rules table.
 */
function SingleSourceTypeMode({
  config,
  logSources,
  canEdit,
  onCreateRule,
  onUpdateRule,
  creating,
  updating,
  onSwitchToMulti,
}: {
  config: SourceConfigurationWithRules;
  logSources: LogSource[];
  canEdit: boolean;
  onCreateRule: (req: NewRoutingRule) => void;
  onUpdateRule: (ruleId: string, req: UpdateRoutingRule) => void;
  creating: boolean;
  updating: boolean;
  onSwitchToMulti: () => void;
}) {
  // The "single" rule is the first default rule. If multiple defaults exist
  // (legacy data) we operate on the first; the rest stay untouched.
  const defaultRule =
    config.routing_rules.find((r) => r.match_type === 'default') ?? null;
  const serverTarget = defaultRule?.target_source_type ?? '';
  const serverRuleId = defaultRule?.id ?? null;
  const [targetSourceType, setTargetSourceType] = useState(serverTarget);

  // Sync local state from the server cautiously: we don't want a refetch
  // (e.g. background revalidation) to clobber the user's mid-edit input.
  //
  // Strategy:
  //   - Track which rule id we last synced from in a ref.
  //   - When the underlying default rule swaps (id changes — e.g. delete +
  //     recreate, or mode flip surfacing a different rule), re-sync
  //     unconditionally; the prior local edit no longer applies.
  //   - When only the server's target value drifts under a stable id, only
  //     sync when the user isn't dirty relative to the server. The dirty
  //     comparison is against the *current* server value (`serverTarget`),
  //     not a snapshot, so a successful save (which makes local match
  //     server) lets the next refetch flow through naturally.
  const syncedRuleIdRef = useRef<string | null>(serverRuleId);
  useEffect(() => {
    const ruleChanged = syncedRuleIdRef.current !== serverRuleId;
    const userDirty = targetSourceType.trim() !== serverTarget;
    if (ruleChanged || !userDirty) {
      setTargetSourceType(serverTarget);
      syncedRuleIdRef.current = serverRuleId;
    }
    // `targetSourceType` is intentionally excluded — we read it for the
    // dirty check but only react to server-side changes. Including it
    // would re-fire on every keystroke and undo the dirty-guard.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverTarget, serverRuleId]);

  const dirty = targetSourceType.trim() !== serverTarget;
  const canSave =
    canEdit && dirty && targetSourceType.trim().length > 0 && !creating && !updating;

  const handleSave = () => {
    const value = targetSourceType.trim();
    if (!value) return;
    if (defaultRule) {
      onUpdateRule(defaultRule.id, {
        match_field: 'source_type',
        match_type: 'default',
        match_value: undefined,
        target_source_type: value,
      });
    } else {
      onCreateRule({
        match_field: 'source_type',
        match_type: 'default',
        target_source_type: value,
      });
    }
  };

  const nonDefaultCount = config.routing_rules.filter(
    (r) => r.match_type !== 'default',
  ).length;

  return (
    <div className="max-w-[640px] mx-auto px-6 py-6 space-y-4">
      <div className="space-y-2">
        <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
          Single source type
        </div>
        <h2 className="text-[14px] font-semibold text-foreground">
          Route every event from this feed to one parser
        </h2>
        <p className="text-[11.5px] text-muted-foreground leading-relaxed">
          All events arriving at this binding are tagged with a single source_type
          and dispatched to the matching log source.
        </p>
      </div>

      <div className="bg-card border border-border rounded-md p-4 space-y-3">
        <div className="space-y-1.5">
          <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Source type for this feed
          </Label>
          <SourceTypeCombobox
            value={targetSourceType}
            onChange={setTargetSourceType}
            logSources={logSources}
            placeholder="Select a parser…"
            disabled={!canEdit}
          />
          <p className="text-[10.5px] text-muted-foreground">
            Events carry this tag downstream — log sources subscribe by it.
          </p>
        </div>
        <div className="flex items-center justify-end gap-2 pt-1">
          <Button
            size="sm"
            className="h-[28px] text-[11.5px]"
            onClick={handleSave}
            disabled={!canSave}
          >
            {(creating || updating) && (
              <Loader2 className="h-3 w-3 animate-spin" />
            )}
            <Save className="h-3 w-3" />
            {defaultRule ? 'Save' : 'Create rule'}
          </Button>
        </div>
      </div>

      {nonDefaultCount > 0 && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2.5 flex items-start gap-2">
          <CircleAlert className="h-3.5 w-3.5 text-amber-500 mt-0.5 shrink-0" />
          <div className="text-[11.5px] text-foreground/80 leading-relaxed">
            This config also has {nonDefaultCount} non-default rule
            {nonDefaultCount === 1 ? '' : 's'} — they&rsquo;re still active. Switch to{' '}
            <button
              type="button"
              className="text-primary hover:underline"
              onClick={onSwitchToMulti}
            >
              Multiple source types
            </button>{' '}
            mode to review them.
          </div>
        </div>
      )}
    </div>
  );
}
