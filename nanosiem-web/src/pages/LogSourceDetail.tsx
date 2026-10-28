// SPDX-License-Identifier: AGPL-3.0-or-later

import { ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  ChevronRight,
  Copy,
  Edit,
  GitCommit,
  Play,
  Power,
  Rocket,
  RotateCcw,
  Rss,
  Save,
  Terminal,
  Upload,
  X,
  XCircle,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { useToast } from '@/hooks/use-toast';
import { useSharedTenant } from '@/hooks/use-shared-tenant';
import { useIngestGate } from '@/hooks/use-capabilities';
import { TenzirOnlyNote, TENZIR_ONLY_NOTE } from '@/components/add-data/TenzirOnlyNote';
import { useAuth } from '@/contexts/AuthContext';
import { SourceWritersCard } from '@/components/add-data/SourceWritersCard';
import { LogSourceDetailShell } from '@/components/log-sources/LogSourceDetailShell';
import { IngestActivitySparkline } from '@/components/add-data/IngestActivitySparkline';
import { LogSourceHealthPanel } from '@/components/log-sources/LogSourceHealthChart';
import { LogSourceDelivery } from '@/components/log-sources/LogSourceDelivery';
import {
  useDiscardLogSourceDraft,
  useDeployLogSource,
  useIngestionHistory,
  useLogSource,
  useLogSourceDeployments,
  useLogSourceDraftStatus,
  useLogSourceHealth,
  useLogSourceVersions,
  usePublishLogSource,
  useToggleLogSource,
  useUndeployLogSource,
  useUpdateLogSource,
  useValidateLogSource,
  useValidateLogSourceVrl,
} from '@/hooks/use-api';

import { VrlEditor } from '@/components/editor';
import { VrlLine } from '@/components/editor/VrlHighlight';
import { useVrlHighlight } from '@/components/editor/use-vrl-highlight';
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable';
import { useDefaultLayout } from 'react-resizable-panels';
import { computeDiff, type DiffLine, type VrlUpdateInfo } from '@/lib/parser-diff';
import { ParserTestLab } from '@/components/parser/ParserTestLab';
import { Markdown } from '@/components/ui/markdown';
import {
  formatElapsed,
  PARSER_JOB_MAX_WAIT_MS,
  useElapsedWhile,
  useMelodJob,
} from '@/enterprise/hooks/use-melod-job';
import { useMelodStatus } from '@/hooks/use-api';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useParserSidePanelTabs, type SidePanelTabId } from '@/components/log-sources/parserSidePanelTabs';
import type { CollectorError, MelodEditParserResponse } from '@/lib/api';
import { Send } from 'lucide-react';
import { PivtIcon } from '@/components/icons/PivtIcon';

import { api } from '@/lib/api';
import type {
  LogSource,
  LogSourceDeployment,
  LogSourceVersion,
  TenantParserRollout,
  SourceConfiguration,
  UpdateLogSource,
} from '@/lib/api';
import { formatRelativeCompact, formatUTCCompact } from '@/lib/date-utils';
import {
  SOURCE_TYPE_LABELS,
  logSourceTransportLabel,
} from '@/lib/log-source-transports';
import { cn } from '@/lib/utils';
import { LogSourceRolloutPanel } from '@/components/parser-rollout/LogSourceRolloutPanel';
import { useLatestLiveRollout, useLogSourceRollouts } from '@/components/parser-rollout/use-log-source-rollouts';
import { PlatformUpdateBanner } from '@/components/parser-rollout/PlatformUpdateBanner';
import { ParserSamplesEditor } from '@/components/parser-rollout/ParserSamplesEditor';
import {
  LOG_SOURCE_ROLLOUTS_QUERY_KEY,
  PARSER_ROLLOUTS_QUERY_KEY,
  parserServingState,
  rolloutFailureText,
  rolloutStateLabel,
  rolloutVersion,
  type ParserServingState,
} from '@/lib/parser-rollout';
import { nplFieldEquals } from '@/lib/npl-quote';
import {
  buildLogSourceParserPrompt,
  extractRecentParserSamples,
  isRawPassThroughVrl,
} from '@/lib/log-source-pivt-context';
import { useQuery } from '@tanstack/react-query';

const CONFIG_TYPE_TO_SOURCE_TYPE: Record<string, string> = {
  http: 'routed',
  vector: 'vector',
  kafka: 'kafka',
  aws_s3: 'aws_s3',
  gcp_pubsub: 'gcp_pubsub',
  azure_event_hubs: 'azure_event_hubs',
  splunk_hec: 'splunk_hec',
};

const CATEGORY_OPTIONS = [
  { value: 'network', label: 'Network' },
  { value: 'endpoint', label: 'Endpoint' },
  { value: 'cloud', label: 'Cloud' },
  { value: 'application', label: 'Application' },
  { value: 'security', label: 'Security' },
  { value: 'system', label: 'System' },
];

const TAB_IDS = ['overview', 'config', 'vrl', 'extension', 'deployments', 'versions'] as const;
type TabId = (typeof TAB_IDS)[number];
function isTabId(value: string | null): value is TabId {
  return value !== null && (TAB_IDS as readonly string[]).includes(value);
}

// `LogSource.source_type` is overloaded: for routed parsers it stores the transport
// sentinel `'routed'`, with the actual parsed identifier (what events get tagged with
// in ClickHouse, e.g. `apache_http_server`) living in `match_values[0]`. Use this when
// you mean "the source_type value that incoming events carry" — e.g. for log search
// queries, ingestion-history filters, parser filenames, and the read-only
// "Source type" display rows.
function effectiveSourceType(source: LogSource): string {
  return source.match_values?.[0] || source.source_type;
}

type ValidationResult = { valid: boolean; errors: string[] } | null;

export function LogSourceDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  // NAN-2597: hosted-shared tenants see which ingest credentials can write this source.
  const shared = useSharedTenant();
  // NAN-3844: no Vector on an `install.sh --tenzir` install, so deploy and
  // publish (which renders into Vector) are off; drafting and testing stay.
  const { tenzirOnly, blocked: vectorBlocked } = useIngestGate();
  const { hasPermission } = useAuth();

  const { data: logSource, loading, refetch } = useLogSource(id);
  useDocumentTitle(logSource?.name || 'Log Source', [logSource?.id]);
  useBreadcrumbTitle(logSource?.name);

  const { data: deployments, refetch: refetchDeployments } = useLogSourceDeployments(id);
  const { data: health, refetch: refetchHealth } = useLogSourceHealth(id);
  const { data: draftStatus, refetch: refetchDraftStatus } = useLogSourceDraftStatus(id);
  const { data: versions, refetch: refetchVersions } = useLogSourceVersions(id);
  const { data: ingestionHistory } = useIngestionHistory(24);
  // NAN-2983: the header shows the latest parser rollout (same query/poll as the rollout panel).
  const rolloutsQuery = useLogSourceRollouts(id ?? '', shared && !!id);
  // NAN-3298: the tenant's newest promoted roll (any source), to tell which version serves.
  const latestLiveQuery = useLatestLiveRollout(rolloutsQuery.data?.[0], shared && !!id);

  const { mutate: updateLogSource, loading: updating } = useUpdateLogSource();
  const { mutate: toggleLogSource } = useToggleLogSource();
  const { mutate: validateLogSource, loading: validating } = useValidateLogSource();
  const { mutate: validateVrl } = useValidateLogSourceVrl();
  // NAN-2607: on hosted-shared (`shared`, above), deploy / publish / revert roll
  // the parser out to the tenant's parser cell (a parser-bundle rollout), not to Vector.
  const { mutate: deployLogSource, loading: deploying } = useDeployLogSource();
  const { mutate: undeployLogSource, loading: undeploying } = useUndeployLogSource();
  const { mutate: publishLogSource, loading: publishing } = usePublishLogSource();
  const { mutate: discardDraft, loading: discarding } = useDiscardLogSourceDraft();

  // Deployed source-config list (used by the Configuration tab's source-type dropdown)
  const { data: deployedConfigs } = useQuery<SourceConfiguration[]>({
    queryKey: ['source-configs-deployed'],
    queryFn: () => api.listSourceConfigs({ deployed: true }),
    staleTime: 60_000,
  });
  const { data: activeSchema } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const searchSourceField = activeSchema?.schema === 'ocsf'
    ? 'metadata.log_source'
    : 'source_type';

  const availableSourceTypes = useMemo(() => {
    if (!deployedConfigs?.length) return [];
    const seen = new Set<string>();
    return deployedConfigs
      .filter((c) => {
        if (seen.has(c.config_type)) return false;
        seen.add(c.config_type);
        return true;
      })
      .map((c) => ({
        value: CONFIG_TYPE_TO_SOURCE_TYPE[c.config_type] ?? c.config_type,
        label: SOURCE_TYPE_LABELS[c.config_type] ?? c.config_type,
      }));
  }, [deployedConfigs]);

  // Tab state (persisted in URL so deep-links survive refresh).
  // The legacy `test` tab folded into `vrl` — alias it on read.
  const rawTab = searchParams.get('tab') || 'overview';
  const aliased: TabId = rawTab === 'test' ? 'vrl' : isTabId(rawTab) ? rawTab : 'overview';
  const [activeTab, setActiveTabState] = useState<TabId>(aliased);
  useEffect(() => {
    setActiveTabState(aliased);
  }, [aliased]);
  const setActiveTab = (tab: TabId) => setSearchParams({ tab });

  // Configuration form state
  const [isEditingConfig, setIsEditingConfig] = useState(false);
  const [formData, setFormData] = useState<UpdateLogSource>({});

  // VRL editor state
  const [isEditingVrl, setIsEditingVrl] = useState(false);
  const [editedVrl, setEditedVrl] = useState('');
  const [validationResult, setValidationResult] = useState<ValidationResult>(null);
  const [validatedJustNow, setValidatedJustNow] = useState(false);

  // AI diff state (pivt proposes edits, we render them inline in the editor)
  const [currentDiff, setCurrentDiff] = useState<DiffLine[] | null>(null);
  const [vrlHistory, setVrlHistory] = useState<string[]>([]);

  // VRL side-panel tab (AI / Test events / Diagnostics)
  const [sidePanelTab, setSidePanelTab] = useState<'ai' | 'test' | 'diag'>('test');

  // Versions tab state
  const [openVersion, setOpenVersion] = useState<number | null>(null);

  // Confirmation dialogs
  const [deployDialogOpen, setDeployDialogOpen] = useState(false);
  const [undeployDialogOpen, setUndeployDialogOpen] = useState(false);
  const [saveVrlDialogOpen, setSaveVrlDialogOpen] = useState(false);
  const [acceptDiffDialogOpen, setAcceptDiffDialogOpen] = useState(false);
  const [publishDialogOpen, setPublishDialogOpen] = useState(false);
  const [discardDraftDialogOpen, setDiscardDraftDialogOpen] = useState(false);
  const [revertVersionTarget, setRevertVersionTarget] = useState<LogSourceVersion | null>(null);

  // Per-source ingestion sparkline points (filtered from the global history endpoint).
  // The history endpoint keys rows by the source_type value events actually carry
  // (e.g. `apache_http_server`), which for routed parsers lives in `match_values[0]`,
  // not in `LogSource.source_type` (which is just the `'routed'` transport sentinel).
  const sparklinePoints = useMemo(() => {
    if (!ingestionHistory?.length || !logSource) return [] as number[];
    const want = effectiveSourceType(logSource).toLowerCase();
    return ingestionHistory
      .filter((p) => p.source_type.toLowerCase() === want)
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
      .map((p) => p.count);
  }, [ingestionHistory, logSource]);

  // ----- early return: loading / 404 -----

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <LoadingIcon className="w-6 h-6 text-muted-foreground" />
      </div>
    );
  }
  if (!logSource) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 px-4 text-center">
        <Rss className="w-10 h-10 text-muted-foreground/50" />
        <div className="text-[13px] font-medium text-foreground">Log source not found</div>
        <Button variant="outline" size="sm" className="h-8" onClick={() => navigate('/ingestion/log-sources')}>
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to log sources
        </Button>
      </div>
    );
  }

  // ----- derived state -----

  const currentVrl = isEditingVrl ? editedVrl : logSource.parser_vrl;
  const vrlDirty = isEditingVrl && editedVrl !== logSource.parser_vrl;
  const hasDraft = draftStatus?.has_draft_changes ?? false;
  const activeVersion = versions?.find((v) => v.is_active);
  const latestRollout = rolloutsQuery.data?.[0];
  const activeVersionNumber = draftStatus?.active_version_number ?? activeVersion?.version_number;
  // NAN-3298: an active version serves only once a parser-bundle roll carrying it is promoted.
  const serving = parserServingState(
    shared ? rolloutsQuery.data : undefined,
    latestLiveQuery.data,
    activeVersionNumber,
  );

  // "Full description" in the header: jump to the Feed details card.
  const showFeedDetails = () => {
    if (activeTab !== 'overview') setActiveTab('overview');
    // The tab switch goes through the URL and an effect, so wait a frame pair for the card to mount.
    requestAnimationFrame(() =>
      requestAnimationFrame(() =>
        document.getElementById('feed-details')?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      ),
    );
  };

  // ----- mutation handlers -----

  const handleToggle = async () => {
    try {
      await toggleLogSource({ id: logSource.id, enabled: !logSource.enabled });
      toast({ title: logSource.enabled ? 'Log source disabled' : 'Log source enabled' });
      refetch();
      refetchHealth();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to toggle',
        variant: 'destructive',
      });
    }
  };

  const handleDeploy = async () => {
    try {
      const result = await deployLogSource(logSource.id);
      if (shared) {
        const rollout = (result as { rollout?: unknown } | undefined)?.rollout;
        toast({
          title: 'Activated',
          description: rollout ? `"${logSource.name}" is rolling out to your parser cell.` : `"${logSource.name}" is active.`,
        });
        invalidateRollouts();
      } else {
        toast({ title: 'Deployed', description: `"${logSource.name}" has been deployed to Vector.` });
      }
      setDeployDialogOpen(false);
      refetch();
      refetchHealth();
      refetchDeployments();
      queryClient.invalidateQueries({ queryKey: ['log-sources'] });
    } catch (err) {
      toast({
        title: 'Deploy failed',
        description: err instanceof Error ? err.message : 'Failed to deploy',
        variant: 'destructive',
      });
    }
  };

  const handleUndeploy = async () => {
    try {
      await undeployLogSource(logSource.id);
      toast({
        title: 'Undeployed',
        description: shared
          ? `"${logSource.name}" is deactivated; it leaves your parser cell with the next rollout.`
          : `"${logSource.name}" has been removed from Vector.`,
      });
      setUndeployDialogOpen(false);
      refetch();
      refetchHealth();
      refetchDeployments();
      queryClient.invalidateQueries({ queryKey: ['log-sources'] });
    } catch (err) {
      toast({
        title: 'Undeploy failed',
        description: err instanceof Error ? err.message : 'Failed to undeploy',
        variant: 'destructive',
      });
    }
  };

  const handlePublish = async () => {
    try {
      const result = await publishLogSource(logSource.id);
      if (result.success && shared) {
        toast({
          title: 'Published',
          description: (result as { rollout?: unknown }).rollout
            ? `Version created; "${logSource.name}" is rolling out to your parser cell.`
            : `Version created and "${logSource.name}" activated.`,
        });
        invalidateRollouts();
      } else if (result.success) {
        toast({
          title: 'Published & deployed',
          description: `Version created and "${logSource.name}" deployed.`,
        });
        // Best-effort: redeploy any source-configs whose routing rules target this parser.
        // If something fails here the parser is still deployed, so we swallow per-config errors.
        const matchValues = logSource.match_values ?? [];
        if (matchValues.length > 0 && deployedConfigs?.length) {
          try {
            await Promise.all(
              deployedConfigs.map(async (config) => {
                const rules = await api.listRoutingRules(config.id);
                if (rules.some((r) => matchValues.includes(r.target_source_type))) {
                  await api.deploySourceConfig(config.id);
                }
              }),
            );
          } catch {
            /* per-config redeploy failures are best-effort */
          }
        }
      } else {
        toast({ title: 'Publish failed', description: result.message, variant: 'destructive' });
      }
      setPublishDialogOpen(false);
      refetch();
      refetchHealth();
      refetchDeployments();
      refetchDraftStatus();
      refetchVersions();
      queryClient.invalidateQueries({ queryKey: ['log-sources'] });
    } catch (err) {
      toast({
        title: 'Publish failed',
        description: err instanceof Error ? err.message : 'Failed to publish',
        variant: 'destructive',
      });
    }
  };

  function invalidateRollouts() {
    if (id) void queryClient.invalidateQueries({ queryKey: LOG_SOURCE_ROLLOUTS_QUERY_KEY(id) });
    void queryClient.invalidateQueries({ queryKey: PARSER_ROLLOUTS_QUERY_KEY });
  }

  const handleDiscardDraft = async () => {
    try {
      await discardDraft(logSource.id);
      toast({ title: 'Draft discarded', description: 'Working copy reset to active deployed version.' });
      setDiscardDraftDialogOpen(false);
      refetch();
      refetchDraftStatus();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to discard draft',
        variant: 'destructive',
      });
    }
  };

  const handleRevertVersion = async (version: LogSourceVersion) => {
    try {
      await updateLogSource({
        id: logSource.id,
        data: {
          parser_vrl: version.parser_vrl,
          expected_updated_at: logSource.updated_at,
        },
      });
      toast({
        title: 'Draft updated',
        description: `Working copy set to v${version.version_number}'s parser. Publish when ready.`,
      });
      setRevertVersionTarget(null);
      refetch();
      refetchDraftStatus();
    } catch (err) {
      toast({
        title: 'Revert failed',
        description: err instanceof Error ? err.message : 'Failed to revert',
        variant: 'destructive',
      });
    }
  };

  const handleStartEditConfig = () => {
    setFormData({
      name: logSource.name,
      description: logSource.description || '',
      source_type: logSource.source_type,
      category: logSource.category,
      vendor: logSource.vendor,
      product: logSource.product,
      stale_alert_enabled: logSource.stale_alert_enabled,
      stale_threshold_minutes: logSource.stale_threshold_minutes,
      sampling_ratio: logSource.sampling_ratio,
      sampling_exclude_condition: logSource.sampling_exclude_condition,
    });
    setIsEditingConfig(true);
  };

  const handleSaveConfig = async () => {
    try {
      const changed: UpdateLogSource = {};
      if (formData.name !== logSource.name) changed.name = formData.name;
      if (formData.description !== (logSource.description || '')) changed.description = formData.description;
      if (formData.source_type !== logSource.source_type) changed.source_type = formData.source_type;
      if (formData.category !== logSource.category) changed.category = formData.category;
      if (formData.vendor !== logSource.vendor) changed.vendor = formData.vendor;
      if (formData.product !== logSource.product) changed.product = formData.product;
      if (formData.stale_alert_enabled !== logSource.stale_alert_enabled)
        changed.stale_alert_enabled = formData.stale_alert_enabled;
      if (formData.stale_threshold_minutes !== logSource.stale_threshold_minutes)
        changed.stale_threshold_minutes = formData.stale_threshold_minutes;
      if (formData.sampling_ratio !== logSource.sampling_ratio)
        changed.sampling_ratio = formData.sampling_ratio;
      if (formData.sampling_exclude_condition !== logSource.sampling_exclude_condition)
        changed.sampling_exclude_condition = formData.sampling_exclude_condition;

      if (Object.keys(changed).length === 0) {
        toast({ title: 'No changes', description: 'Nothing was modified.' });
        setIsEditingConfig(false);
        return;
      }
      changed.expected_updated_at = logSource.updated_at;
      await updateLogSource({ id: logSource.id, data: changed });
      toast({ title: 'Configuration updated', description: `"${logSource.name}" has been updated.` });
      setIsEditingConfig(false);
      refetch();
      refetchDraftStatus();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to update',
        variant: 'destructive',
      });
    }
  };

  const handleStartEditVrl = () => {
    setEditedVrl(logSource.parser_vrl);
    setIsEditingVrl(true);
    setValidationResult(null);
    setValidatedJustNow(false);
  };

  const handleCancelEditVrl = () => {
    setIsEditingVrl(false);
    setEditedVrl('');
    setValidationResult(null);
    setValidatedJustNow(false);
  };

  const handleValidate = async () => {
    try {
      const vrl = isEditingVrl ? editedVrl : logSource.parser_vrl;
      const syntaxResult = await validateVrl(vrl);
      if (!syntaxResult.valid) {
        setValidationResult(syntaxResult);
        setSidePanelTab('diag');
        toast({ title: 'VRL invalid', description: syntaxResult.errors.join(', '), variant: 'destructive' });
        return;
      }
      // For the deployed VRL (no edits) we also persist validated=true on the row
      if (!isEditingVrl) {
        const result = await validateLogSource(logSource.id);
        setValidationResult(result);
        if (result.valid) {
          toast({ title: 'VRL validated', description: 'Validation status saved.' });
          setValidatedJustNow(true);
        } else {
          toast({ title: 'VRL invalid', description: result.errors.join(', '), variant: 'destructive' });
        }
        refetch();
      } else {
        setValidationResult(syntaxResult);
        toast({ title: 'VRL validated', description: 'Syntax check passed.' });
        setValidatedJustNow(true);
      }
      setSidePanelTab('diag');
    } catch (err) {
      toast({
        title: 'Validation error',
        description: err instanceof Error ? err.message : 'Failed to validate',
        variant: 'destructive',
      });
    }
  };

  const handleSaveVrlClick = async () => {
    try {
      const syntaxResult = await validateVrl(editedVrl);
      setValidationResult(syntaxResult);
      if (!syntaxResult.valid) {
        setSidePanelTab('diag');
        toast({
          title: 'VRL invalid',
          description: 'Fix syntax errors before saving',
          variant: 'destructive',
        });
        return;
      }
      setSaveVrlDialogOpen(true);
    } catch (err) {
      toast({
        title: 'Validation error',
        description: err instanceof Error ? err.message : 'Failed to validate',
        variant: 'destructive',
      });
    }
  };

  const handleSaveVrlConfirmed = async () => {
    try {
      setVrlHistory((prev) => [...prev, logSource.parser_vrl]);
      await updateLogSource({
        id: logSource.id,
        data: {
          parser_vrl: editedVrl,
          expected_updated_at: logSource.updated_at,
        },
      });
      toast({ title: 'VRL saved', description: 'Parser code updated. Deploy to apply changes.' });
      setIsEditingVrl(false);
      setSaveVrlDialogOpen(false);
      setValidatedJustNow(false);
      refetch();
      refetchDraftStatus();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save',
        variant: 'destructive',
      });
    }
  };

  const handleAiVrlUpdate = (info: VrlUpdateInfo) => {
    setVrlHistory((prev) => [...prev, currentVrl]);
    if (info.diff) setCurrentDiff(info.diff);
    setEditedVrl(info.newVrl);
    setIsEditingVrl(true);
    toast({ title: 'VRL updated', description: 'Review the changes and click Accept to save.' });
  };

  const handleAiUndo = () => {
    if (vrlHistory.length === 0) return;
    const previousVrl = vrlHistory[vrlHistory.length - 1];
    setVrlHistory((prev) => prev.slice(0, -1));
    setEditedVrl(previousVrl);
    setCurrentDiff(null);
  };

  const handleAcceptDiffConfirmed = async () => {
    try {
      setVrlHistory((prev) => [...prev, logSource.parser_vrl || '']);
      await updateLogSource({
        id: logSource.id,
        data: {
          parser_vrl: editedVrl,
          expected_updated_at: logSource.updated_at,
        },
      });
      setCurrentDiff(null);
      setAcceptDiffDialogOpen(false);
      setIsEditingVrl(false);
      toast({ title: 'Draft saved', description: 'Publish when ready to apply changes.' });
      refetch();
      refetchDraftStatus();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save',
        variant: 'destructive',
      });
    }
  };

  // ----- render -----

  return (
    <TooltipProvider delayDuration={200}>
      {/* NAN-3011/3014: full-width app page shell; scrolls in AppLayout, never its own box. */}
      <LogSourceDetailShell>
        <LogSourceHero
          source={logSource}
          dirty={vrlDirty}
          health={health}
          activeVersion={activeVersionNumber}
          rollout={shared ? latestRollout : undefined}
          serving={serving}
          onShowDetails={showFeedDetails}
          deploying={deploying}
          undeploying={undeploying}
          deployBlocked={vectorBlocked}
          onToggleEnabled={handleToggle}
          onDeploy={() => setDeployDialogOpen(true)}
          onUndeploy={() => setUndeployDialogOpen(true)}
          onClone={() => navigate(`/ingestion/log-sources/new?clone=${logSource.id}`)}
          onViewLogs={() =>
            navigate(
              `/search#q=${encodeURIComponent(`${searchSourceField}=${effectiveSourceType(logSource)}`)}`,
            )
          }
        />
        <DraftBanner
          show={hasDraft}
          activeVersion={draftStatus?.active_version_number}
          publishing={publishing}
          discarding={discarding}
          validated={logSource.validated}
          publishBlocked={vectorBlocked}
          onPublish={() => setPublishDialogOpen(true)}
          onDiscard={() => setDiscardDraftDialogOpen(true)}
        />
        {tenzirOnly && <TenzirOnlyNote />}
        {shared && (
          <div className="flex flex-col gap-3" data-testid="shared-rollout-section">
            <PlatformUpdateBanner />
            <LogSourceRolloutPanel
              logSourceId={logSource.id}
              versions={versions ?? undefined}
              onReverted={() => {
                refetch();
                refetchDraftStatus();
                refetchVersions();
                refetchDeployments();
              }}
            />
          </div>
        )}
        <TabNav active={activeTab} onChange={setActiveTab} />

        <div className="min-w-0">
          {activeTab === 'overview' && (
            <div className="flex flex-col gap-3">
              <OverviewTab
                source={logSource}
                health={health}
                activeVersion={activeVersion}
                serving={serving}
                sparklinePoints={sparklinePoints}
                volume={shared ? <IngestActivitySparkline logSourceId={logSource.id} embedded /> : undefined}
              />
              {shared && (
                <div className="flex flex-col gap-3">
                  {/* NAN-3661: pull sources + connector feeds into this lane, with state, last error and the fix. */}
                  <LogSourceDelivery logSourceId={logSource.id} health={health} />
                  {/* NAN-3207: volume vs expected band + segments; honours ?segment=<dim>:<value>. */}
                  <LogSourceHealthPanel logSourceId={logSource.id} />
                  <SourceWritersCard
                    logSourceId={logSource.id}
                    canRevoke={hasPermission('log_sources:deploy')}
                    canIssue={hasPermission('log_sources:deploy')}
                  />
                  <ParserSamplesEditor logSourceId={logSource.id} />
                </div>
              )}
            </div>
          )}
          {activeTab === 'config' && (
            <ConfigurationTab
              source={logSource}
              isEditing={isEditingConfig}
              formData={formData}
              setFormData={setFormData}
              onStartEdit={handleStartEditConfig}
              onCancel={() => {
                setIsEditingConfig(false);
                setFormData({});
              }}
              onSave={handleSaveConfig}
              updating={updating}
              availableSourceTypes={availableSourceTypes}
            />
          )}
          {activeTab === 'vrl' && (
            <EditorFrame>
            <VrlEditorTab
              source={logSource}
              currentVrl={currentVrl}
              isEditing={isEditingVrl}
              editedVrl={editedVrl}
              setEditedVrl={setEditedVrl}
              dirty={vrlDirty}
              currentDiff={currentDiff}
              vrlHistory={vrlHistory}
              validating={validating}
              updating={updating}
              validatedJustNow={validatedJustNow}
              validationResult={validationResult}
              sidePanelTab={sidePanelTab}
              onSidePanelTabChange={setSidePanelTab}
              onStartEdit={handleStartEditVrl}
              onCancelEdit={handleCancelEditVrl}
              onValidate={handleValidate}
              onSaveVrl={handleSaveVrlClick}
              onAcceptDiff={() => setAcceptDiffDialogOpen(true)}
              onUndo={handleAiUndo}
              onAiVrlUpdate={handleAiVrlUpdate}
            />
            </EditorFrame>
          )}
          {activeTab === 'extension' && (
            <EditorFrame>
            <ExtensionTab
              source={logSource}
              updating={updating}
              onSave={async ({ extension_vrl, extension_enabled }) => {
                await updateLogSource({
                  id: logSource.id,
                  data: {
                    extension_vrl,
                    extension_enabled,
                    expected_updated_at: logSource.updated_at,
                  },
                });
                refetch();
                refetchDraftStatus();
              }}
            />
            </EditorFrame>
          )}
          {activeTab === 'deployments' && (
            <DeploymentsTab
              deployments={deployments ?? null}
              rollouts={shared ? rolloutsQuery.data : undefined}
              serving={serving}
            />
          )}
          {activeTab === 'versions' && (
            <VersionsTab
              versions={versions ?? null}
              hasDraft={hasDraft}
              publishing={publishing}
              validated={logSource.validated}
              openVersion={openVersion}
              onToggleOpen={(id) => setOpenVersion(openVersion === id ? null : id)}
              onPublish={() => setPublishDialogOpen(true)}
              onRequestRevert={(v) => setRevertVersionTarget(v)}
            />
          )}
        </div>

        {/* Confirmation dialogs */}
        <ConfirmDialog
          open={deployDialogOpen}
          onOpenChange={setDeployDialogOpen}
          title="Deploy log source"
          description={
            shared
              ? `Activate "${logSource.name}". A custom parser is built, validated and rolled out to your parser cell; the current parser keeps serving until it is live.`
              : `Deploy "${logSource.name}" to Vector. Incoming logs matching this source type will be parsed using the current VRL.`
          }
          confirmLabel={deploying ? 'Deploying…' : 'Deploy'}
          confirmIcon={deploying ? <LoadingIcon className="w-3.5 h-3.5" /> : <Rocket className="w-3.5 h-3.5" />}
          onConfirm={handleDeploy}
          disabled={deploying || vectorBlocked}
        />
        <ConfirmDialog
          open={undeployDialogOpen}
          onOpenChange={setUndeployDialogOpen}
          title="Undeploy log source"
          description={
            shared
              ? `Deactivate "${logSource.name}" in your source registry. It leaves your parser cell with the next rollout.`
              : `Remove "${logSource.name}" from Vector. Incoming logs for this source type will no longer be parsed until you redeploy.`
          }
          confirmLabel={undeploying ? 'Undeploying…' : 'Undeploy'}
          confirmIcon={undeploying ? <LoadingIcon className="w-3.5 h-3.5" /> : <Power className="w-3.5 h-3.5" />}
          confirmTone="warn"
          onConfirm={handleUndeploy}
          disabled={undeploying}
        />
        <ConfirmDialog
          open={saveVrlDialogOpen}
          onOpenChange={setSaveVrlDialogOpen}
          title="Save VRL changes?"
          description={`Save your VRL changes to "${logSource.name}". You'll need to deploy the log source for changes to take effect on incoming logs.`}
          confirmLabel={updating ? 'Saving…' : 'Save changes'}
          confirmIcon={updating ? <LoadingIcon className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
          onConfirm={handleSaveVrlConfirmed}
          disabled={updating}
        />
        <ConfirmDialog
          open={publishDialogOpen}
          onOpenChange={setPublishDialogOpen}
          title="Publish log source?"
          description={
            shared
              ? 'Create a new version from your current draft and roll it out to your parser cell. The previous active version is preserved in history and keeps serving until the rollout is live.'
              : tenzirOnly
                ? TENZIR_ONLY_NOTE
                : 'Create a new version from your current draft and deploy it to Vector. The previous active version is preserved in history.'
          }
          confirmLabel={publishing ? 'Publishing…' : 'Publish'}
          confirmIcon={publishing ? <LoadingIcon className="w-3.5 h-3.5" /> : <Rocket className="w-3.5 h-3.5" />}
          onConfirm={handlePublish}
          disabled={publishing || vectorBlocked}
        />
        <ConfirmDialog
          open={discardDraftDialogOpen}
          onOpenChange={setDiscardDraftDialogOpen}
          title="Discard draft changes?"
          description={`Reset your working copy to the active deployed version${
            draftStatus?.active_version_number ? ` (v${draftStatus.active_version_number})` : ''
          }. Any unsaved edits will be lost.`}
          confirmLabel={discarding ? 'Discarding…' : 'Discard draft'}
          confirmIcon={discarding ? <LoadingIcon className="w-3.5 h-3.5" /> : <RotateCcw className="w-3.5 h-3.5" />}
          confirmTone="warn"
          onConfirm={handleDiscardDraft}
          disabled={discarding}
        />
        <ConfirmDialog
          open={acceptDiffDialogOpen}
          onOpenChange={setAcceptDiffDialogOpen}
          title="Save parser changes?"
          description="Save your AI-edited parser as a draft. You can review and publish it when ready."
          confirmLabel={updating ? 'Saving…' : 'Save draft'}
          confirmIcon={updating ? <LoadingIcon className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
          onConfirm={handleAcceptDiffConfirmed}
          disabled={updating}
        />
        <ConfirmDialog
          open={!!revertVersionTarget}
          onOpenChange={(open) => !open && setRevertVersionTarget(null)}
          title={revertVersionTarget ? `Revert to v${revertVersionTarget.version_number}?` : ''}
          description={
            revertVersionTarget
              ? `Update your working copy to v${revertVersionTarget.version_number}'s parser as a draft. Review the changes and publish when ready.`
              : ''
          }
          confirmLabel={updating ? 'Reverting…' : 'Revert to draft'}
          confirmIcon={updating ? <LoadingIcon className="w-3.5 h-3.5" /> : <RotateCcw className="w-3.5 h-3.5" />}
          confirmTone="warn"
          onConfirm={() => {
            if (revertVersionTarget) handleRevertVersion(revertVersionTarget);
          }}
          disabled={updating}
        />
      </LogSourceDetailShell>
    </TooltipProvider>
  );
}

// ============================================================================
// Hero
// ============================================================================

const EYEBROW = 'font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground';

type PillTone = 'emerald' | 'amber' | 'red' | 'primary' | 'neutral';
const PILL_TONE: Record<PillTone, string> = {
  emerald: 'bg-emerald-500/10 text-emerald-500',
  amber: 'bg-amber-500/10 text-amber-500',
  red: 'bg-red-500/10 text-red-500',
  primary: 'bg-primary/10 text-primary',
  neutral: 'bg-foreground/[0.05] text-foreground/80',
};

function StatusPill({
  tone,
  children,
  className,
  title,
}: {
  tone: PillTone;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-[3px] px-[7px] py-[3px] font-mono text-[10.5px] font-semibold uppercase tracking-[0.08em] whitespace-nowrap',
        PILL_TONE[tone],
        className,
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {children}
    </span>
  );
}

function rolloutPill(
  rollout: TenantParserRollout | undefined,
): { tone: PillTone; label: string; title?: string } | null {
  if (!rollout) return null;
  const version = rolloutVersion(rollout);
  const subject = version != null ? `v${version} rollout` : 'Rollout';
  const title = rolloutFailureText(rollout) ?? undefined;
  if (rollout.state === 'failed') return { tone: 'red', label: `${subject} failed`, title };
  if (rollout.state === 'rolled_back') return { tone: 'red', label: `${subject} rolled back`, title };
  if (rollout.state === 'live') return null;
  return { tone: 'amber', label: `${subject} ${rolloutStateLabel(rollout.state).toLowerCase()}` };
}

function fmtFull(n: number | null | undefined): string {
  return n == null ? '—' : n.toLocaleString();
}

function LogSourceHero({
  source,
  dirty,
  health,
  activeVersion,
  rollout,
  serving,
  deploying,
  undeploying,
  deployBlocked = false,
  onToggleEnabled,
  onDeploy,
  onUndeploy,
  onClone,
  onViewLogs,
  onShowDetails,
}: {
  source: LogSource;
  dirty: boolean;
  health:
    | {
        events_last_24h?: number;
        events_last_hour?: number;
        last_event_at?: string | null;
        parse_success_rate_24h?: number | null;
      }
    | null
    | undefined;
  activeVersion: number | undefined;
  rollout: TenantParserRollout | undefined;
  /** NAN-3298: which version actually serves; `tracked` false = registry fields are the truth. */
  serving: ParserServingState;
  deploying: boolean;
  undeploying: boolean;
  /** NAN-3844: Tenzir-only install, no Vector to deploy into. */
  deployBlocked?: boolean;
  onToggleEnabled: () => void;
  onDeploy: () => void;
  onUndeploy: () => void;
  onClone: () => void;
  onViewLogs: () => void;
  onShowDetails: () => void;
}) {
  const transportLabel = logSourceTransportLabel(source);
  // NAN-3298: when rollouts track this source, the pill follows the version that is NOT serving yet
  // (in flight / failed / rolled back); a newest rollout carried live by a later roll needs no pill.
  const pill = rolloutPill(serving.tracked ? (serving.failed ?? serving.inFlight ?? undefined) : rollout);
  const successRate = health?.parse_success_rate_24h;
  const stats: Array<{ label: string; value: string; title?: string }> = [
    { label: 'Events · 24h', value: fmtFull(health?.events_last_24h) },
    { label: 'Events · 1h', value: fmtFull(health?.events_last_hour) },
    { label: 'Parse success', value: successRate == null ? '—' : `${(successRate * 100).toFixed(1)}%` },
    {
      label: 'Last event',
      value: health?.last_event_at ? formatRelativeCompact(health.last_event_at) : '—',
      title: health?.last_event_at ? formatUTCCompact(health.last_event_at) : undefined,
    },
  ];
  const longDescription = (source.description?.length ?? 0) > 160;

  return (
    <section className="rounded-md border border-border bg-card">
      <div className="flex flex-wrap items-start gap-4 px-4 py-3">
        <div className="flex h-10 w-10 flex-none items-center justify-center rounded-md border border-border bg-foreground/[0.03] text-muted-foreground">
          <Rss className="h-[18px] w-[18px]" strokeWidth={1.5} />
        </div>

        <div className="flex min-w-0 flex-[1_1_420px] flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="m-0 min-w-0 break-words text-[18px] font-semibold tracking-[-0.01em] text-foreground">
              {source.name}
            </h1>
            <div className="flex flex-wrap gap-1.5">
              {['Feed workspace', transportLabel, 'Parser'].map((tag) => (
                <span
                  key={tag}
                  className="rounded-[3px] border border-border px-1.5 py-0.5 font-mono text-[10.5px] uppercase tracking-[0.06em] text-muted-foreground whitespace-nowrap"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>

          {source.description && (
            <p className="m-0 max-w-[760px] text-[12px] leading-[18px] text-muted-foreground">
              <span className={cn(longDescription && 'line-clamp-2')}>{source.description}</span>
              {longDescription && (
                <button type="button" onClick={onShowDetails} className="mt-0.5 text-primary hover:underline">
                  Full description
                </button>
              )}
            </p>
          )}

          <div className="mt-0.5 flex flex-wrap gap-1.5">
            {source.deployed && serving.tracked ? (
              serving.servingVersion != null ? (
                <StatusPill tone="emerald">Deployed · v{serving.servingVersion}</StatusPill>
              ) : (
                <StatusPill tone="neutral">Not live yet</StatusPill>
              )
            ) : source.deployed ? (
              <StatusPill tone="emerald">Deployed{activeVersion ? ` · v${activeVersion}` : ''}</StatusPill>
            ) : (
              <StatusPill tone="neutral">Ready</StatusPill>
            )}
            {pill && (
              <StatusPill tone={pill.tone} title={pill.title}>
                {pill.label}
              </StatusPill>
            )}
            {source.validated ? (
              <StatusPill tone="primary">Validated</StatusPill>
            ) : (
              <StatusPill tone="amber">Not validated</StatusPill>
            )}
            {source.namespace && source.namespace !== 'default' && (
              <StatusPill tone="neutral">{source.namespace}</StatusPill>
            )}
            {dirty && <StatusPill tone="amber">Unsaved VRL changes</StatusPill>}
            {source.validation_error && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="cursor-help">
                    <StatusPill tone="red">Validation failed</StatusPill>
                  </span>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[420px] text-[11px]">
                  {source.validation_error}
                </TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onToggleEnabled}
            aria-pressed={source.enabled}
            className="inline-flex h-7 items-center gap-2 rounded-md border border-border pl-1.5 pr-2.5 font-mono text-[11px] uppercase tracking-[0.06em] text-foreground hover:bg-muted/50"
          >
            <SwitchGlyph checked={source.enabled} />
            {source.enabled ? 'Enabled' : 'Disabled'}
          </button>
          <Button variant="outline" size="sm" className="h-7 gap-1.5 px-2.5 text-[11.5px] font-medium" onClick={onViewLogs}>
            <Terminal className="h-3.5 w-3.5" strokeWidth={1.5} />
            View logs
          </Button>
          <Button variant="outline" size="sm" className="h-7 gap-1.5 px-2.5 text-[11.5px] font-medium" onClick={onClone}>
            <Copy className="h-3.5 w-3.5" strokeWidth={1.5} />
            Clone
          </Button>
          <span className="mx-0.5 h-5 w-px bg-border" aria-hidden="true" />
          {source.deployed && (
            <Button
              variant="ghost"
              size="sm"
              disabled={undeploying}
              onClick={onUndeploy}
              className="h-7 gap-1.5 px-2.5 text-[11.5px] font-medium text-red-500 hover:bg-red-500/10 hover:text-red-500"
            >
              {undeploying ? <LoadingIcon className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" strokeWidth={1.5} />}
              Undeploy
            </Button>
          )}
          <Button
            variant="default"
            size="sm"
            disabled={!source.validated || deploying || deployBlocked}
            title={deployBlocked ? TENZIR_ONLY_NOTE : undefined}
            onClick={onDeploy}
            className="h-7 gap-1.5 px-3 text-[11.5px] font-semibold"
          >
            {deploying ? <LoadingIcon className="h-3.5 w-3.5" /> : <Upload className="h-3.5 w-3.5" strokeWidth={1.5} />}
            {source.deployed ? 'Redeploy' : 'Deploy'}
          </Button>
        </div>
      </div>

      {/* Live telemetry strip. The negative margins hide the trailing cell borders. */}
      <div className="overflow-hidden rounded-b-md border-t border-border">
        <div className="-mb-px -mr-px grid grid-cols-2 sm:grid-cols-4">
          {stats.map((s) => (
            <div key={s.label} className="flex min-w-0 flex-col gap-0.5 border-b border-r border-border px-4 py-2">
              <span className={EYEBROW}>{s.label}</span>
              <span
                className="truncate font-mono text-[14px] font-medium text-foreground tabular-nums"
                title={s.title}
              >
                {s.value}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/** Visual switch inside the header's Enabled button (the button carries the semantics). */
function SwitchGlyph({ checked }: { checked: boolean }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'relative block h-4 w-[26px] flex-none rounded-full transition-colors',
        checked ? 'bg-primary' : 'bg-foreground/[0.08]',
      )}
    >
      <span
        className={cn(
          'absolute top-0.5 h-3 w-3 rounded-full transition-all',
          checked ? 'left-3 bg-primary-foreground' : 'left-0.5 bg-muted-foreground',
        )}
      />
    </span>
  );
}

// Visual-only switch for read-only contexts. Avoids the focusable
// no-op button that visually looks interactive but does nothing.
function ReadOnlyToggle({ checked }: { checked: boolean }) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        'w-[30px] h-[17px] rounded-full flex items-center relative shrink-0 opacity-70',
        checked ? 'bg-primary/60' : 'bg-foreground/[0.05] border border-border',
      )}
    >
      <span
        className={cn(
          'absolute w-[13px] h-[13px] rounded-full bg-white/80',
          checked ? 'left-[15px]' : 'left-[2px]',
        )}
      />
    </div>
  );
}

function fmtCount(n: number | null | undefined): string {
  if (n == null) return '—';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

/** VRL / extension editors need a bounded height inside the scrolling page. */
function EditorFrame({ children }: { children: ReactNode }) {
  return (
    <div className="h-[max(560px,calc(100vh-8rem))] overflow-hidden rounded-md border border-border bg-card">
      {children}
    </div>
  );
}

// ============================================================================
// Draft banner
// ============================================================================

function DraftBanner({
  show,
  activeVersion,
  publishing,
  discarding,
  validated,
  publishBlocked = false,
  onPublish,
  onDiscard,
}: {
  show: boolean;
  activeVersion: number | undefined;
  publishing: boolean;
  discarding: boolean;
  validated: boolean;
  /** NAN-3844: Tenzir-only install, publishing deploys into Vector. */
  publishBlocked?: boolean;
  onPublish: () => void;
  onDiscard: () => void;
}) {
  if (!show) return null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-amber-500/30 bg-amber-500/[0.06] px-3.5 py-2">
      <div className="flex min-w-0 items-start gap-2.5">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" strokeWidth={1.5} />
        <div className="text-[11.5px] leading-[17px] text-amber-600 dark:text-amber-400">
          <span className="font-semibold">Unpublished changes</span>
          <span className="ml-2 text-amber-600/80 dark:text-amber-400/80">
            Working copy differs from deployed version
            {activeVersion ? ` (v${activeVersion})` : ''}. Changes won't affect live parsing until published.
          </span>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          className="h-7 gap-1.5 px-2.5 text-[11.5px] font-medium"
          disabled={discarding}
          onClick={onDiscard}
        >
          {discarding ? <LoadingIcon className="h-3.5 w-3.5" /> : <RotateCcw className="h-3.5 w-3.5" strokeWidth={1.5} />}
          Discard draft
        </Button>
        <Button
          size="sm"
          className="h-7 gap-1.5 bg-amber-600 px-3 text-[11.5px] font-semibold text-white hover:bg-amber-700"
          disabled={publishing || !validated || publishBlocked}
          title={publishBlocked ? TENZIR_ONLY_NOTE : undefined}
          onClick={onPublish}
        >
          {publishing ? <LoadingIcon className="h-3.5 w-3.5" /> : <Rocket className="h-3.5 w-3.5" strokeWidth={1.5} />}
          Publish
        </Button>
      </div>
    </div>
  );
}

// ============================================================================
// Tab nav
// ============================================================================

function TabNav({ active, onChange }: { active: TabId; onChange: (id: TabId) => void }) {
  const tabs: Array<{ id: TabId; label: string }> = [
    { id: 'overview', label: 'Overview' },
    { id: 'config', label: 'Configuration' },
    { id: 'vrl', label: 'VRL editor' },
    { id: 'extension', label: 'Extension' },
    { id: 'deployments', label: 'Deployments' },
    { id: 'versions', label: 'Versions' },
  ];
  return (
    <div className="flex gap-1 overflow-x-auto overflow-y-hidden border-b border-border" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={active === t.id}
          onClick={() => onChange(t.id)}
          className={cn(
            '-mb-px whitespace-nowrap border-b-2 px-3 py-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.1em] transition-colors',
            active === t.id
              ? 'border-primary text-foreground'
              : 'border-transparent text-muted-foreground hover:text-foreground/80',
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ============================================================================
// LSCard / LSRow primitives
// ============================================================================

function LSCard({
  id,
  title,
  eyebrow,
  action,
  children,
  className,
}: {
  id?: string;
  title: string;
  eyebrow?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div id={id} className={cn('min-w-0 overflow-hidden rounded-md border border-border bg-card', className)}>
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 border-b border-border px-4 py-2">
        {eyebrow && <span className={EYEBROW}>{eyebrow}</span>}
        <div className="text-[12px] font-semibold text-foreground">{title}</div>
        <div className="flex-1" />
        {action}
      </div>
      <div>{children}</div>
    </div>
  );
}

function LSRow({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[110px_minmax(0,1fr)] items-baseline gap-3 border-b border-border px-4 py-1.5 last:border-b-0 sm:grid-cols-[140px_minmax(0,1fr)]">
      <div className={EYEBROW}>{label}</div>
      <div className={cn('min-w-0 text-[11.5px] [overflow-wrap:anywhere]', mono ? 'font-mono text-foreground' : 'text-foreground')}>
        {children}
      </div>
    </div>
  );
}

// ============================================================================
// Overview tab
// ============================================================================

type HealthTone = 'red' | 'amber' | 'emerald' | 'muted';
const HEALTH_TONE: Record<HealthTone, string> = {
  red: 'text-red-500',
  amber: 'text-amber-500',
  emerald: 'text-emerald-500',
  muted: 'text-muted-foreground',
};

function OverviewTab({
  source,
  health,
  activeVersion,
  serving,
  sparklinePoints,
  volume,
}: {
  source: LogSource;
  health:
    | {
        health_status?: string;
        error_rate_24h?: number | null;
        parse_errors_24h?: number;
        parse_attempts_24h?: number;
        parse_success_rate_24h?: number | null;
        events_last_24h?: number;
        events_last_hour?: number;
        last_event_at?: string | null;
        collector_errors?: CollectorError[];
        collector_errors_24h?: number;
        collector_error_hint?: string | null;
        pending_reason?: string | null;
      }
    | null
    | undefined;
  activeVersion: LogSourceVersion | undefined;
  /** NAN-3298: the version actually serving ingest (hosted-shared parser rollouts). */
  serving: ParserServingState;
  sparklinePoints: number[];
  /**
   * NAN-2599: hosted-shared replaces the history sparkline with hourly events + parse failures.
   * NAN-3297: rendered inside the About panel's right column, so pass the embedded variant.
   */
  volume?: ReactNode;
}) {
  const isLive = source.deployed && (sparklinePoints.length > 0 || (health?.events_last_24h ?? 0) > 0);
  const parseErrors = health?.parse_errors_24h ?? 0;
  const parseAttempts = health?.parse_attempts_24h ?? 0;
  const parseSuccessRate = health?.parse_success_rate_24h;
  // NAN-3298: with rollouts tracking the parser, "Deployed" / "Version" are the promoted
  // roll's, not the registry activation's (publish activates before the roll lands).
  const deployedAt = serving.tracked ? serving.servingSince : source.deployed_at;
  const servingVersion = serving.tracked ? serving.servingVersion : (activeVersion?.version_number ?? null);
  const notServing = serving.failed ?? serving.inFlight;
  const notServingVersion = notServing ? rolloutVersion(notServing) : null;
  const notServingFailure = serving.failed ? rolloutFailureText(serving.failed) : null;
  const activeNotServing =
    serving.tracked && activeVersion != null && serving.servingVersion !== activeVersion.version_number;
  // NAN-2196. A failing collector produces no events, so every volume-derived
  // status reads it as "quiet" — the state this outranks below.
  const collectorErrors = health?.collector_errors ?? [];
  // Errors cover a 24h window, so their mere presence does NOT mean the
  // collector is failing *now*: a source that broke this morning and recovered
  // would otherwise be labelled broken while actively ingesting. Data arriving
  // after the most recent error is the evidence of recovery.
  const newestErrorAt = collectorErrors[0]?.timestamp;
  const collectorRecovered =
    Boolean(newestErrorAt) &&
    Boolean(health?.last_event_at) &&
    new Date(health!.last_event_at!).getTime() > new Date(newestErrorAt!).getTime();
  const collectorFailing = collectorErrors.length > 0 && !collectorRecovered;

  /*
    NAN-2196: collector failure outranks everything below it. The statuses
    that follow are all derived from event volume, and a collector that
    cannot reach its queue produces no volume — so without this branch a hard
    failure renders as "No data yet" or "Stale", which is exactly how the
    original bug stayed invisible.
  */
  const status: { label: string; tone: HealthTone } = collectorFailing
    ? { label: 'Collector failing — not receiving data', tone: 'red' }
    : health?.health_status === 'error'
      ? { label: 'Errors detected', tone: 'red' }
      : source.deployed && parseErrors > 0
        ? { label: 'Parsing degraded', tone: 'amber' }
        : health?.health_status === 'healthy'
          ? { label: 'Healthy', tone: 'emerald' }
          : health?.health_status === 'stale'
            ? { label: 'Stale — no recent events', tone: 'amber' }
            : !source.deployed
              ? { label: 'Ready to deploy', tone: 'muted' }
              : { label: 'No data yet', tone: 'muted' };

  return (
    <div className="flex flex-col gap-3">
      <LSCard id="feed-details" eyebrow="About" title="Feed details" className="scroll-mt-4">
        <div className="grid grid-cols-1 lg:grid-cols-2">
          <div className="flex min-w-0 flex-col gap-3 border-b border-border p-4 lg:border-b-0 lg:border-r">
            <span className={EYEBROW}>Description</span>
            <p className="m-0 whitespace-pre-line text-[12px] leading-[18px] text-foreground/80">
              {source.description || '—'}
            </p>
            {activeVersion && (
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 rounded-md border border-border bg-background/60 px-3 py-2">
                <span className="font-mono text-[11px] font-semibold text-primary">v{activeVersion.version_number}</span>
                {activeVersion.change_reason && (
                  <span className="min-w-0 text-[11.5px] text-muted-foreground">{activeVersion.change_reason}</span>
                )}
                {activeNotServing && (
                  <span
                    className={cn('font-mono text-[10.5px]', serving.failed ? 'text-red-500' : 'text-amber-500')}
                    data-testid="active-version-not-serving"
                  >
                    {serving.failed
                      ? `not serving · ${rolloutStateLabel(serving.failed.state).toLowerCase()}`
                      : serving.inFlight
                        ? 'not serving yet · rolling out'
                        : 'not serving'}
                  </span>
                )}
                <span className="flex-1" />
                <span className="font-mono text-[11px] text-muted-foreground">{formatUTCCompact(activeVersion.created_at)}</span>
              </div>
            )}
          </div>
          <div className="min-w-0">
            <div>
              <LSRow label="Category" mono>
                <span className="text-foreground">{source.category || '—'}</span>
              </LSRow>
              <LSRow label="Source type" mono>
                <span className="text-primary">{effectiveSourceType(source)}</span>
              </LSRow>
              <LSRow label="Vendor">
                <span className="text-foreground">{source.vendor || '—'}</span>
              </LSRow>
              <LSRow label="Product">
                <span className="text-foreground">{source.product || '—'}</span>
              </LSRow>
              <LSRow label="Namespace" mono>
                <span className="text-foreground">{source.namespace || 'default'}</span>
              </LSRow>
              <LSRow label="Created" mono>
                <span className="text-muted-foreground">{formatUTCCompact(source.created_at)}</span>
              </LSRow>
              <LSRow label="Updated" mono>
                <span className="text-muted-foreground">{formatUTCCompact(source.updated_at)}</span>
              </LSRow>
            </div>

            {/*
              NAN-3297: feed health and hourly ingest live under the metadata
              rows instead of as two stranded cards below the panel.
            */}
            <section aria-label="Feed health" data-testid="feed-health-section">
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 border-y border-border px-4 py-1.5">
                <span className={EYEBROW}>Health</span>
                <span className="text-[12px] font-semibold text-foreground">Feed health</span>
                <span className="flex-1" />
                <span
                  className={cn('inline-flex items-center gap-1.5 font-mono text-[11px]', HEALTH_TONE[status.tone])}
                  data-testid="feed-health-status"
                >
                  <span
                    className={cn('h-1.5 w-1.5 rounded-full bg-current', isLive && status.tone === 'emerald' && 'animate-pulse')}
                  />
                  {status.label}
                </span>
              </div>
              <div>
                <LSRow label="Parse success" mono>
                  {parseSuccessRate == null ? (
                    <span className="text-muted-foreground">—</span>
                  ) : (
                    <span
                      className={cn(
                        parseSuccessRate < 0.99 ? 'text-red-500' : parseSuccessRate < 1 ? 'text-amber-500' : 'text-emerald-500',
                      )}
                    >
                      {(parseSuccessRate * 100).toFixed(2)}%
                    </span>
                  )}
                </LSRow>
                <LSRow label="Failures · 24h" mono>
                  <span className={parseErrors > 0 ? 'text-amber-500' : 'text-foreground'}>{fmtFull(parseErrors)}</span>
                  {parseAttempts > 0 && (
                    <span className="ml-2 font-sans text-[12px] text-muted-foreground">of {fmtFull(parseAttempts)} production events</span>
                  )}
                </LSRow>
                <LSRow label="Deployed" mono>
                  <span className="text-foreground" data-testid="feed-deployed-at">
                    {deployedAt ? formatUTCCompact(deployedAt) : '—'}
                  </span>
                </LSRow>
                <LSRow label="Version" mono>
                  <span className="text-foreground" data-testid="feed-serving-version">
                    {servingVersion != null ? `v${servingVersion}` : '—'}
                  </span>
                  {notServing && notServingVersion != null && (
                    <span
                      className={cn('ml-2 font-mono text-[11px]', serving.failed ? 'text-red-500' : 'text-amber-500')}
                      data-testid="feed-version-not-serving"
                    >
                      {serving.failed
                        ? `v${notServingVersion} ${rolloutStateLabel(serving.failed.state).toLowerCase()}`
                        : `v${notServingVersion} ${rolloutStateLabel(notServing.state).toLowerCase()}…`}
                    </span>
                  )}
                  {notServingFailure && (
                    <div
                      className="mt-0.5 line-clamp-2 break-words font-sans text-[11px] leading-[16px] text-red-500/90"
                      title={notServingFailure}
                    >
                      {notServingFailure}
                    </div>
                  )}
                </LSRow>
              </div>
              <p className="m-0 border-t border-border px-4 py-2 text-[11.5px] leading-[17px] text-muted-foreground">
                Runtime failures are preserved as searchable events in{' '}
                <code className="font-mono text-foreground/70">metadata.parse_error</code>. Static VRL validation is not
                included.
              </p>
            </section>
            {volume}
          </div>
        </div>
      </LSCard>

      {/*
        NAN-3765: an enabled source the Vector configuration does not include
        yet (e.g. its source configuration is not deployed). It deploys on its
        own once the reason clears; until then nothing can arrive.
      */}
      {health?.pending_reason && (
        <div
          className="border border-amber-500/40 px-4 py-2.5 text-[11.5px] leading-[17px] text-amber-600 dark:text-amber-500"
          data-testid="log-source-pending-reason"
        >
          <span className="mr-2 font-mono text-[10.5px] uppercase tracking-[0.1em]">Not deployed</span>
          {health.pending_reason}
        </div>
      )}

      {/*
        NAN-2196. Rendered only when the collector has actually reported a
        failure, so a healthy source gains no empty panel. Placed directly under
        the About panel (which carries feed health and hourly volume, NAN-3297):
        when a source is broken, "why" sits next to "how much".
      */}
      {collectorErrors.length > 0 && (
        <LSCard
          eyebrow="Collector"
          title="Recent collector errors"
          action={
            <span className={cn('font-mono text-[10.5px]', collectorFailing ? 'text-red-500' : 'text-muted-foreground')}>
              {fmtCount(health?.collector_errors_24h ?? collectorErrors.length)} in 24h
            </span>
          }
        >
          <div className="border-b border-border px-4 py-3 text-[11.5px] leading-[17px] text-foreground/80">
            {collectorRecovered ? (
              <>
                The collector reported these errors, then resumed — data has arrived since the
                most recent one. Shown because a recovered feed may still have a gap.
              </>
            ) : (
              <>
                These are reported by the collector itself, not by the parser. They mean data is
                not arriving — distinct from data arriving and failing to parse.
              </>
            )}
          </div>

          {/* A diagnosis for a feed that has since recovered would misdirect. */}
          {collectorFailing && health?.collector_error_hint && (
            <div className="border-b border-border px-4 py-3 text-[11.5px] leading-[17px] text-amber-600 dark:text-amber-500">
              {health.collector_error_hint}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-[11.5px]">
              <thead>
                <tr className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
                  <th className="px-4 py-2 font-semibold">Time</th>
                  <th className="px-4 py-2 font-semibold">Level</th>
                  <th className="px-4 py-2 font-semibold">Message</th>
                  <th className="px-4 py-2 font-semibold">Code</th>
                </tr>
              </thead>
              <tbody>
                {collectorErrors.map((e, i) => (
                  <tr key={`${e.timestamp}-${i}`} className="border-t border-border align-top">
                    <td className="whitespace-nowrap px-4 py-1.5 font-mono text-[11px] text-muted-foreground">
                      {formatUTCCompact(e.timestamp)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-1.5 font-mono text-[11px]">
                      <span className={e.level === 'ERROR' ? 'text-red-500' : 'text-amber-500'}>{e.level || '—'}</span>
                    </td>
                    <td className="px-4 py-1.5 text-foreground/90">{e.message || '—'}</td>
                    <td className="whitespace-nowrap px-4 py-1.5 font-mono text-[11px] text-muted-foreground">
                      {e.error_code || '—'}
                      {e.stage && <div className="mt-0.5 text-foreground/50">{e.stage}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {(health?.collector_errors_24h ?? 0) > collectorErrors.length && (
            <div className="border-t border-border px-4 py-2.5 text-[12px] text-muted-foreground">
              Showing the {collectorErrors.length} most recent of{' '}
              {fmtCount(health?.collector_errors_24h)} in the last 24 hours.
            </div>
          )}
        </LSCard>
      )}

      {!volume && <Sparkline points={sparklinePoints} isLive={isLive} sourceDeployed={source.deployed} />}
    </div>
  );
}

function Sparkline({
  points,
  isLive,
  sourceDeployed,
}: {
  points: number[];
  isLive: boolean;
  sourceDeployed: boolean;
}) {
  // Empty state when there's no data — the chart slot still renders so the page doesn't reflow.
  if (points.length < 2) {
    return (
      <LSCard eyebrow="Ingest" title="Event volume">
        <div className="flex flex-col items-center justify-center gap-1.5 px-4 py-10 text-center text-muted-foreground">
          <div className="text-[12px] font-semibold text-foreground">No event volume recorded yet</div>
          <div className="max-w-[380px] text-[12px] leading-[17px]">
            {sourceDeployed
              ? 'Event volume chart will appear once ingestion resumes.'
              : 'Deploy this feed to start receiving events.'}
          </div>
        </div>
      </LSCard>
    );
  }

  const max = Math.max(1, ...points);
  const W = 1360;
  const H = 96;
  const PAD_T = 4;
  const innerH = H - PAD_T;
  const xAt = (i: number) => (i / (points.length - 1)) * W;
  const yAt = (v: number) => PAD_T + innerH - (v / max) * innerH;
  const d = points.map((v, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`).join(' ');
  const dFill = `${d} L${xAt(points.length - 1).toFixed(1)},${H} L0,${H} Z`;

  return (
    <LSCard
      eyebrow={isLive ? 'Live' : 'Ingest'}
      title="Event volume"
      action={
        <span className="font-mono text-[10.5px] text-muted-foreground">
          peak <span className="text-foreground">{max.toLocaleString()}</span> / bucket
        </span>
      }
    >
      <div>
        <svg viewBox={`0 0 ${W} ${H}`} className="h-[96px] w-full border-b border-border" preserveAspectRatio="none">
          <line x1={0} x2={W} y1={PAD_T + innerH / 2} y2={PAD_T + innerH / 2} stroke="var(--border)" strokeWidth="1" strokeDasharray="2,3" />
          <path d={dFill} fill="var(--primary)" fillOpacity="0.18" />
          <path d={d} fill="none" stroke="var(--primary)" strokeWidth="1.5" strokeOpacity="0.9" vectorEffect="non-scaling-stroke" />
        </svg>
        <div className="mt-1.5 flex justify-between font-mono text-[10.5px] text-muted-foreground/70">
          <span>−24h</span>
          <span>−12h</span>
          <span>now</span>
        </div>
      </div>
    </LSCard>
  );
}

// ============================================================================
// Configuration tab
// ============================================================================

function ConfigurationTab({
  source,
  isEditing,
  formData,
  setFormData,
  onStartEdit,
  onCancel,
  onSave,
  updating,
  availableSourceTypes,
}: {
  source: LogSource;
  isEditing: boolean;
  formData: UpdateLogSource;
  setFormData: (f: UpdateLogSource) => void;
  onStartEdit: () => void;
  onCancel: () => void;
  onSave: () => void;
  updating: boolean;
  availableSourceTypes: Array<{ value: string; label: string }>;
}) {
  const sourceType = formData.source_type ?? source.source_type;
  const transportLabel = SOURCE_TYPE_LABELS[sourceType] ?? sourceType;
  const samplingRatio = formData.sampling_ratio ?? source.sampling_ratio;
  const samplingPct = samplingRatio != null ? Math.round(samplingRatio * 100) : null;
  const staleEnabled = isEditing
    ? formData.stale_alert_enabled ?? source.stale_alert_enabled ?? true
    : source.stale_alert_enabled ?? true;
  const staleThreshold = isEditing
    ? formData.stale_threshold_minutes ?? source.stale_threshold_minutes ?? 15
    : source.stale_threshold_minutes ?? 15;

  return (
    <div className="space-y-4">
      <LSCard
        eyebrow="Identity"
        title="Source configuration"
        action={
          isEditing ? (
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="h-7 text-[11.5px]" onClick={onCancel}>
                Cancel
              </Button>
              <Button size="sm" className="h-7 text-[11.5px] gap-1.5" onClick={onSave} disabled={updating}>
                {updating ? <LoadingIcon className="w-3 h-3" /> : <Save className="w-3 h-3" />}
                Save changes
              </Button>
            </div>
          ) : (
            <Button variant="outline" size="sm" className="h-7 text-[11.5px] gap-1.5" onClick={onStartEdit}>
              <Edit className="w-3 h-3" />
              Edit
            </Button>
          )
        }
      >
        <LSRow label="Name">
          {isEditing ? (
            <Input
              value={formData.name ?? ''}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="h-8 text-[12px] bg-card"
            />
          ) : (
            <span className="text-foreground">{source.name}</span>
          )}
        </LSRow>
        <LSRow label="Source type" mono>
          {isEditing ? (
            <Select
              value={formData.source_type ?? source.source_type}
              onValueChange={(v) => setFormData({ ...formData, source_type: v })}
            >
              <SelectTrigger className="h-8 text-[12px] bg-card">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {availableSourceTypes.map((t) => (
                  <SelectItem key={t.value} value={t.value} className="text-[12px]">
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            // Read view shows what events actually carry (parsed identifier).
            // Edit view above is the transport dropdown — separate concern, edits
            // `source_type` directly which for routed parsers is the `'routed'`
            // sentinel rather than the parsed identifier.
            <span className="text-primary">{effectiveSourceType(source)}</span>
          )}
        </LSRow>
        <LSRow label="Description">
          {isEditing ? (
            <Textarea
              value={formData.description ?? ''}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="resize-none text-[12px] bg-card"
              rows={2}
            />
          ) : (
            <div className="text-foreground/80 leading-relaxed">{source.description || '—'}</div>
          )}
        </LSRow>
        <LSRow label="Category" mono>
          {isEditing ? (
            <Select
              value={formData.category ?? ''}
              onValueChange={(v) => setFormData({ ...formData, category: v })}
            >
              <SelectTrigger className="h-8 text-[12px] bg-card">
                <SelectValue placeholder="Select category" />
              </SelectTrigger>
              <SelectContent>
                {CATEGORY_OPTIONS.map((c) => (
                  <SelectItem key={c.value} value={c.value} className="text-[12px]">
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <span className="text-foreground">{source.category || '—'}</span>
          )}
        </LSRow>
        <LSRow label="Vendor">
          {isEditing ? (
            <Input
              value={formData.vendor ?? ''}
              onChange={(e) => setFormData({ ...formData, vendor: e.target.value })}
              className="h-8 text-[12px] bg-card"
            />
          ) : (
            <span className="text-foreground">{source.vendor || '—'}</span>
          )}
        </LSRow>
        <LSRow label="Product">
          {isEditing ? (
            <Input
              value={formData.product ?? ''}
              onChange={(e) => setFormData({ ...formData, product: e.target.value })}
              className="h-8 text-[12px] bg-card"
            />
          ) : (
            <span className="text-foreground">{source.product || '—'}</span>
          )}
        </LSRow>
        <LSRow label="Transport">
          <span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[4px] border border-border bg-foreground/[0.03]">
            <span className="text-[10.5px] font-mono text-foreground/80">{transportLabel}</span>
          </span>
        </LSRow>
      </LSCard>

      <LSCard
        eyebrow="Alerting"
        title="Staleness monitoring"
        action={
          <span
            className={cn(
              'inline-flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider rounded px-1.5 py-0.5',
              staleEnabled
                ? 'text-emerald-500 bg-emerald-500/15'
                : 'text-muted-foreground bg-foreground/[0.03] border border-border',
            )}
          >
            {staleEnabled ? 'ENABLED' : 'DISABLED'}
          </span>
        }
      >
        <div className="flex items-start gap-4 px-4 py-3 border-b border-border">
          <div className="flex-1 min-w-0">
            <div className="text-[12px] text-foreground">Alert when this feed goes stale</div>
            <div className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed max-w-[560px]">
              Fires a platform alert when no events arrive within the threshold window. Recommended for production
              sources.
            </div>
          </div>
          {isEditing ? (
            <Switch
              checked={staleEnabled}
              onCheckedChange={(v) => setFormData({ ...formData, stale_alert_enabled: v })}
            />
          ) : (
            <ReadOnlyToggle checked={staleEnabled} />
          )}
        </div>
        <div
          className={cn(
            'flex items-center gap-4 px-4 py-3 transition-opacity',
            staleEnabled ? '' : 'opacity-40 pointer-events-none',
          )}
        >
          <div className="w-[140px] text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Stale threshold
          </div>
          <div className="flex items-center gap-2">
            {isEditing ? (
              <Input
                type="number"
                min={1}
                max={1440}
                value={staleThreshold}
                onChange={(e) =>
                  setFormData({ ...formData, stale_threshold_minutes: parseInt(e.target.value) || 15 })
                }
                className="h-7 w-20 text-[12px] bg-card font-mono"
              />
            ) : (
              <span className="font-mono text-[12px] text-foreground tabular-nums">{staleThreshold}</span>
            )}
            <span className="text-[11px] text-muted-foreground">minutes without events</span>
          </div>
        </div>
      </LSCard>

      <LSCard
        eyebrow="Volume"
        title="Event sampling"
        action={
          <span
            className={cn(
              'inline-flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider rounded px-1.5 py-0.5',
              samplingPct != null
                ? 'text-emerald-500 bg-emerald-500/15'
                : 'text-muted-foreground bg-foreground/[0.03] border border-border',
            )}
          >
            {samplingPct != null ? 'ENABLED' : 'OFF'}
          </span>
        }
      >
        <div className="flex items-start gap-4 px-4 py-3 border-b border-border">
          <div className="flex-1 min-w-0">
            <div className="text-[12px] text-foreground">Sample a percentage of incoming events</div>
            <div className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed max-w-[560px]">
              Reduces ingest cost by randomly dropping events before they hit the repository. Avoid on
              high-fidelity sources like audit logs — sampling is lossy and cannot be reversed.
            </div>
          </div>
          {isEditing ? (
            <Switch
              checked={samplingPct != null}
              onCheckedChange={(v) =>
                setFormData({ ...formData, sampling_ratio: v ? 0.5 : null })
              }
            />
          ) : (
            <ReadOnlyToggle checked={samplingPct != null} />
          )}
        </div>
        {samplingPct != null && (
          <div className="flex items-center gap-4 px-4 py-3 border-b border-border">
            <div className="w-[140px] text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Sampling rate
            </div>
            <div className="flex items-center gap-2 flex-1 max-w-[460px]">
              {isEditing ? (
                <input
                  type="range"
                  min={1}
                  max={100}
                  value={samplingPct}
                  onChange={(e) => setFormData({ ...formData, sampling_ratio: Number(e.target.value) / 100 })}
                  className="flex-1 accent-primary"
                />
              ) : (
                <div className="flex-1 h-1.5 rounded-full bg-foreground/[0.05] overflow-hidden">
                  <div className="h-full bg-primary" style={{ width: `${samplingPct}%` }} />
                </div>
              )}
              <div className="w-14 text-right font-mono text-[12px] text-foreground tabular-nums">
                {samplingPct}%
              </div>
            </div>
          </div>
        )}
        {samplingPct != null && samplingPct > 0 && samplingPct < 100 && (
          <div className="flex items-start gap-4 px-4 py-3">
            <div className="w-[140px] text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground pt-[1px]">
              Exclude condition
            </div>
            <div className="flex-1">
              {isEditing ? (
                <Input
                  value={formData.sampling_exclude_condition ?? source.sampling_exclude_condition ?? ''}
                  onChange={(e) =>
                    setFormData({ ...formData, sampling_exclude_condition: e.target.value || null })
                  }
                  placeholder='.action != "allow"'
                  className="h-8 text-[12px] bg-card font-mono"
                />
              ) : (
                <span className="font-mono text-[12px] text-foreground">
                  {source.sampling_exclude_condition || '—'}
                </span>
              )}
              <div className="text-[10.5px] text-muted-foreground/70 mt-1">
                Events matching this VRL condition are never dropped.
              </div>
            </div>
          </div>
        )}
      </LSCard>
    </div>
  );
}

// ============================================================================
// VRL editor tab
// ============================================================================

function VrlEditorTab({
  source,
  currentVrl,
  isEditing,
  editedVrl,
  setEditedVrl,
  dirty,
  currentDiff,
  vrlHistory,
  validating,
  updating,
  validatedJustNow,
  validationResult,
  sidePanelTab,
  onSidePanelTabChange,
  onStartEdit,
  onCancelEdit,
  onValidate,
  onSaveVrl,
  onAcceptDiff,
  onUndo,
  onAiVrlUpdate,
}: {
  source: LogSource;
  currentVrl: string;
  isEditing: boolean;
  editedVrl: string;
  setEditedVrl: (v: string) => void;
  dirty: boolean;
  currentDiff: DiffLine[] | null;
  vrlHistory: string[];
  validating: boolean;
  updating: boolean;
  validatedJustNow: boolean;
  validationResult: ValidationResult;
  sidePanelTab: 'ai' | 'test' | 'diag';
  onSidePanelTabChange: (id: 'ai' | 'test' | 'diag') => void;
  onStartEdit: () => void;
  onCancelEdit: () => void;
  onValidate: () => void;
  onSaveVrl: () => void;
  onAcceptDiff: () => void;
  onUndo: () => void;
  onAiVrlUpdate: (info: VrlUpdateInfo) => void;
}) {
  const sidePanel = useParserSidePanelTabs(sidePanelTab);
  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Toolbar */}
      <div className="shrink-0 flex flex-wrap items-center gap-2 px-4 py-2 border-b border-border bg-card/40">
        <div className="flex items-center gap-2 min-w-0">
          <PivtIcon className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="text-[11.5px] font-mono text-foreground truncate">{effectiveSourceType(source)}.vrl</span>
          <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">
            VRL · parser
          </span>
          {dirty && (
            <span className="inline-flex items-center gap-1 text-[10px] font-mono text-amber-500 bg-amber-500/15 rounded px-1.5 py-0.5">
              <span className="w-1 h-1 rounded-full bg-amber-500" />
              UNSAVED
            </span>
          )}
        </div>
        <div className="flex-1" />

        {currentDiff ? (
          <>
            <Button size="sm" className="h-7 text-[11.5px] gap-1.5 bg-emerald-600 hover:bg-emerald-700 text-white" onClick={onAcceptDiff}>
              <Check className="w-3 h-3" />
              Accept changes
            </Button>
            {vrlHistory.length > 0 && (
              <Button variant="outline" size="sm" className="h-7 text-[11.5px] gap-1.5" onClick={onUndo}>
                <RotateCcw className="w-3 h-3" />
                Undo
              </Button>
            )}
          </>
        ) : isEditing ? (
          <>
            <Button
              size="sm"
              className="h-7 text-[11.5px] gap-1.5"
              onClick={onSaveVrl}
              disabled={updating || validating}
            >
              {updating ? <LoadingIcon className="w-3 h-3" /> : <Save className="w-3 h-3" />}
              Save VRL
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-[11.5px] gap-1.5"
              onClick={onValidate}
              disabled={validating}
            >
              {validating ? <LoadingIcon className="w-3 h-3" /> : <Check className="w-3 h-3" />}
              Validate
            </Button>
            <Button variant="outline" size="sm" className="h-7 text-[11.5px]" onClick={onCancelEdit}>
              Cancel
            </Button>
          </>
        ) : (
          <>
            <Button variant="outline" size="sm" className="h-7 text-[11.5px] gap-1.5" onClick={onStartEdit}>
              <Edit className="w-3 h-3" />
              Edit VRL
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-[11.5px] gap-1.5"
              onClick={onValidate}
              disabled={validating}
            >
              {validating ? <LoadingIcon className="w-3 h-3" /> : <Check className="w-3 h-3" />}
              Validate
            </Button>
          </>
        )}

        {validatedJustNow && !validating && (
          <span className="text-[10px] font-mono text-muted-foreground whitespace-nowrap ml-1">
            <span className="text-emerald-500">✓</span> Validated
          </span>
        )}
      </div>

      {/* 60/40 split */}
      <div className="flex-1 min-h-0 grid grid-rows-[minmax(0,3fr)_minmax(0,2fr)] divide-y divide-border lg:grid-rows-1 lg:grid-cols-[minmax(0,1fr)_480px] lg:divide-y-0 lg:divide-x">
        {/* Editor */}
        <div className="flex flex-col min-h-0 bg-background">
          {currentDiff ? (
            <VrlAiDiffView
              prevVrl={vrlHistory[vrlHistory.length - 1] ?? source.parser_vrl ?? ''}
              newVrl={editedVrl}
            />
          ) : isEditing ? (
            <VrlEditor value={editedVrl} onChange={setEditedVrl} className="h-full" />
          ) : (
            <VrlEditor value={currentVrl} onChange={() => undefined} readOnly className="h-full" />
          )}
        </div>

        {/* Side panel */}
        <div className="flex flex-col min-h-0 bg-card/40">
          <div className="shrink-0 flex items-center gap-1 px-3 py-1.5 border-b border-border">
            {sidePanel.tabs.map((t) => {
              const Icon = t.Icon;
              const isActive = sidePanel.active === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => onSidePanelTabChange(t.id)}
                  className={cn(
                    'h-7 px-2.5 rounded text-[11px] flex items-center gap-1.5 transition-colors whitespace-nowrap',
                    isActive ? 'text-foreground bg-foreground/[0.06]' : 'text-muted-foreground hover:text-foreground/80',
                  )}
                >
                  <Icon className="w-3 h-3" />
                  {t.label}
                </button>
              );
            })}
          </div>
          <div className="flex-1 min-h-0 overflow-hidden">
            {/* Each panel mounts unconditionally so chat history and test-event state
                survive tab switches; we toggle visibility via `hidden` instead of
                conditional rendering to avoid losing scroll/typing state. */}
            {sidePanel.aiAvailable && (
              <div className={cn('h-full', sidePanel.active === 'ai' ? 'block' : 'hidden')}>
                <LogSourceAiPanel
                  parserId={source.id}
                  sourceName={source.name}
                  sourceType={effectiveSourceType(source)}
                  currentVrl={currentVrl}
                  onVrlUpdate={onAiVrlUpdate}
                  onUndo={onUndo}
                  canUndo={vrlHistory.length > 0}
                />
              </div>
            )}
            <div className={cn('h-full overflow-auto', sidePanel.active === 'test' ? 'block' : 'hidden')}>
              <ParserTestLab
                logSourceId={source.id}
                vrlCode={editedVrl || source.parser_vrl}
                sourceType={source.match_values?.[0] || source.source_type}
                currentDeployedVrl={source.parser_vrl}
              />
            </div>
            <div className={cn('h-full overflow-auto', sidePanel.active === 'diag' ? 'block' : 'hidden')}>
              <DiagnosticsPanel result={validationResult} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function DiagnosticsPanel({ result }: { result: ValidationResult }) {
  if (!result) {
    return (
      <div className="p-3">
        <div className="rounded-md bg-foreground/[0.03] border border-border p-3">
          <div className="text-[11.5px] text-foreground">No diagnostics yet</div>
          <div className="text-[10.5px] text-muted-foreground mt-1 leading-relaxed">
            Run <span className="font-mono">Validate</span> from the toolbar to see VRL diagnostics here.
          </div>
        </div>
      </div>
    );
  }
  if (result.valid) {
    return (
      <div className="p-3">
        <div className="rounded-md bg-emerald-500/10 border border-emerald-500/30 p-3">
          <div className="flex items-start gap-2">
            <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
            <div className="text-[11.5px] text-emerald-600 dark:text-emerald-400">
              <div className="font-medium">All validator checks passed.</div>
              <div className="text-[10.5px] text-emerald-600/80 dark:text-emerald-400/80 mt-1">
                VRL parses cleanly with no errors or warnings.
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className="p-3">
      <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground mb-2">
        {result.errors.length} error{result.errors.length === 1 ? '' : 's'}
      </div>
      <div className="space-y-2">
        {result.errors.map((err, i) => (
          <div key={i} className="rounded-md bg-red-500/10 border border-red-500/30 p-2.5">
            <div className="flex items-start gap-2">
              <XCircle className="w-3.5 h-3.5 text-red-500 shrink-0 mt-0.5" />
              <pre className="font-mono text-[11px] text-red-600 dark:text-red-400 whitespace-pre-wrap leading-relaxed flex-1 min-w-0">
                {err}
              </pre>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// Deployments tab
// ============================================================================

const ROLLOUT_TONE: Record<string, string> = {
  live: 'text-emerald-500 bg-emerald-500/15',
  failed: 'text-red-500 bg-red-500/15',
  rolled_back: 'text-red-500 bg-red-500/15',
};

/**
 * NAN-3298: on hosted-shared, deploy / publish only activate the registry entry;
 * the parser reaches ingest through a parser-bundle rollout. Show the rollouts
 * (with failures and roll-backs) first, then the registry history.
 */
function DeploymentsTab({
  deployments,
  rollouts,
  serving,
}: {
  deployments: LogSourceDeployment[] | null;
  /** Hosted-shared only: this source's parser rollouts, newest first. */
  rollouts?: TenantParserRollout[];
  serving: ParserServingState;
}) {
  const shared = rollouts !== undefined;
  return (
    <div className="flex flex-col gap-3">
      {shared && rollouts.length > 0 && <ParserRolloutHistory rollouts={rollouts} serving={serving} />}
      <RegistryDeploymentHistory deployments={deployments} shared={shared} />
    </div>
  );
}

function ParserRolloutHistory({ rollouts, serving }: { rollouts: TenantParserRollout[]; serving: ParserServingState }) {
  return (
    <LSCard
      eyebrow="Ingest"
      title="Parser rollouts"
      action={
        <span className="font-mono text-[10.5px] text-muted-foreground" data-testid="rollout-serving-version">
          serving {serving.servingVersion != null ? `v${serving.servingVersion}` : '—'}
        </span>
      }
    >
      <div data-testid="deployments-rollouts">
        {rollouts.map((r) => {
          const version = rolloutVersion(r);
          const failure = rolloutFailureText(r);
          return (
            <div key={r.id} className="flex items-start gap-3 border-b border-border px-4 py-2 last:border-b-0">
              <span className="w-10 shrink-0 font-mono text-[11.5px] text-foreground">{version != null ? `v${version}` : '—'}</span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={cn(
                      'rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider',
                      ROLLOUT_TONE[r.state] ?? 'text-amber-500 bg-amber-500/15',
                    )}
                  >
                    {rolloutStateLabel(r.state)}
                  </span>
                  <span className="font-mono text-[10.5px] text-muted-foreground">{r.kind.replace(/_/g, ' ')}</span>
                  <span className="font-mono text-[10.5px] text-muted-foreground">{formatUTCCompact(r.requested_at)}</span>
                  {r.completed_at && (
                    <span className="font-mono text-[10.5px] text-muted-foreground">→ {formatUTCCompact(r.completed_at)}</span>
                  )}
                  {version != null && version === serving.servingVersion && r.state === 'live' && (
                    <span className="rounded bg-primary/15 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-primary">
                      Serving
                    </span>
                  )}
                </div>
                {failure && <div className="mt-1 break-words text-[11px] leading-relaxed text-red-500/90">{failure}</div>}
              </div>
            </div>
          );
        })}
      </div>
    </LSCard>
  );
}

function RegistryDeploymentHistory({ deployments, shared }: { deployments: LogSourceDeployment[] | null; shared: boolean }) {
  const title = shared ? 'Registry activations' : 'Deployment history';
  if (!deployments || deployments.length === 0) {
    return (
      <div>
        <LSCard eyebrow="History" title={title}>
          <div className="flex flex-col items-center justify-center py-12 gap-2 text-muted-foreground">
            <Upload className="w-5 h-5 opacity-40" />
            <div className="text-[11.5px]">No deployments yet.</div>
            <div className="text-[10.5px] text-muted-foreground/70">
              Deploy this feed to start the history.
            </div>
          </div>
        </LSCard>
      </div>
    );
  }

  return (
    <div>
      <LSCard
        eyebrow="History"
        title={title}
        action={
          <span className="text-[10.5px] font-mono text-muted-foreground">
            {deployments.length} event{deployments.length === 1 ? '' : 's'}
          </span>
        }
      >
        <div className="relative">
          {deployments.map((d, i) => {
            const isLast = i === deployments.length - 1;
            const ok = d.status === 'success';
            return (
              <div key={d.id} className="relative flex items-start gap-3 px-4 py-3 border-b border-border last:border-b-0">
                {!isLast && <div className="absolute left-[30px] top-[32px] bottom-[-12px] w-px bg-border" />}
                <div
                  className={cn(
                    'w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 mt-0.5',
                    ok ? 'border-emerald-500/40 bg-emerald-500/10' : 'border-red-500/40 bg-red-500/10',
                  )}
                >
                  {ok ? (
                    <Check className="w-3 h-3 text-emerald-500" />
                  ) : (
                    <X className="w-3 h-3 text-red-500" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={cn(
                        'text-[12px] font-medium whitespace-nowrap',
                        ok ? 'text-foreground' : 'text-red-500',
                      )}
                    >
                      {d.action === 'deploy'
                        ? ok
                          ? shared
                            ? 'Activated in registry'
                            : 'Deployed successfully'
                          : 'Deployment failed'
                        : ok
                        ? 'Undeployed successfully'
                        : 'Undeploy failed'}
                    </span>
                    <span
                      className={cn(
                        'text-[10px] font-mono uppercase tracking-wider rounded px-1.5 py-0.5',
                        ok ? 'text-emerald-500 bg-emerald-500/15' : 'text-red-500 bg-red-500/15',
                      )}
                    >
                      {d.status}
                    </span>
                    <span className="text-[10.5px] font-mono text-muted-foreground">
                      {formatUTCCompact(d.deployed_at)}
                    </span>
                  </div>
                  {d.error_message && (
                    <div className="text-[11px] text-red-500/90 mt-1 leading-relaxed">{d.error_message}</div>
                  )}
                </div>
                {i === 0 && (
                  <span className="shrink-0 text-[10px] font-mono uppercase tracking-wider text-primary bg-primary/15 rounded px-1.5 py-0.5 self-center">
                    Current
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </LSCard>
    </div>
  );
}

// ============================================================================
// Versions tab
// ============================================================================

function VersionsTab({
  versions,
  hasDraft,
  publishing,
  validated,
  openVersion,
  onToggleOpen,
  onPublish,
  onRequestRevert,
}: {
  versions: LogSourceVersion[] | null;
  hasDraft: boolean;
  publishing: boolean;
  validated: boolean;
  openVersion: number | null;
  onToggleOpen: (id: number) => void;
  onPublish: () => void;
  onRequestRevert: (v: LogSourceVersion) => void;
}) {
  if (!versions || versions.length === 0) {
    return (
      <div>
        <LSCard eyebrow="Audit" title="Version history">
          <div className="flex flex-col items-center justify-center py-12 gap-2 text-muted-foreground">
            <GitCommit className="w-5 h-5 opacity-40" />
            <div className="text-[11.5px]">No published versions yet.</div>
            <div className="text-[10.5px] text-muted-foreground/70">
              Publish this log source to create the first version.
            </div>
          </div>
        </LSCard>
      </div>
    );
  }

  return (
    <div>
      <LSCard
        eyebrow="Audit"
        title="Version history"
        action={
          <div className="flex items-center gap-2">
            <span className="text-[10.5px] font-mono text-muted-foreground">
              {versions.length} version{versions.length === 1 ? '' : 's'}
            </span>
            {hasDraft && (
              <Button
                size="sm"
                className="h-7 text-[11.5px] gap-1.5"
                disabled={publishing || !validated}
                onClick={onPublish}
              >
                {publishing ? <LoadingIcon className="w-3 h-3" /> : <Rocket className="w-3 h-3" />}
                Publish current draft
              </Button>
            )}
          </div>
        }
      >
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2 w-[90px] text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">
                Version
              </th>
              <th className="text-left px-4 py-2 w-[140px] text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">
                Reason
              </th>
              <th className="text-left px-4 py-2 w-[200px] text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">
                Date
              </th>
              <th className="text-right px-4 py-2 w-[180px] text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">
                Change
              </th>
              <th className="text-right px-4 py-2 w-[120px] text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {versions.map((v, i) => {
              const open = openVersion === v.id;
              const prev = versions[i + 1] ?? null;
              const stats = prev ? diffStats(lineDiff(prev.parser_vrl, v.parser_vrl)) : null;
              return (
                <VersionRow
                  key={v.id}
                  v={v}
                  prev={prev}
                  open={open}
                  isFirst={i === 0}
                  stats={stats}
                  onToggleOpen={() => onToggleOpen(v.id)}
                  onRequestRevert={() => onRequestRevert(v)}
                />
              );
            })}
          </tbody>
        </table>
      </LSCard>
    </div>
  );
}

function VersionRow({
  v,
  prev,
  open,
  isFirst,
  stats,
  onToggleOpen,
  onRequestRevert,
}: {
  v: LogSourceVersion;
  prev: LogSourceVersion | null;
  open: boolean;
  isFirst: boolean;
  stats: { added: number; removed: number } | null;
  onToggleOpen: () => void;
  onRequestRevert: () => void;
}) {
  return (
    <>
      <tr
        className={cn(
          'border-b border-border hover:bg-foreground/[0.03] cursor-pointer transition-colors',
          open && 'bg-foreground/[0.03]',
        )}
        onClick={onToggleOpen}
      >
        <td className="px-4 py-2.5">
          <div className="flex items-center gap-2">
            <ChevronRight className={cn('w-3 h-3 text-muted-foreground/70 transition-transform', open && 'rotate-90')} />
            <span className="font-mono text-[11.5px] text-foreground">v{v.version_number}</span>
            {v.is_active && (
              <span className="text-[9.5px] font-mono uppercase tracking-wider text-primary bg-primary/15 rounded px-1 py-px">
                active
              </span>
            )}
            {isFirst && !v.is_active && (
              <span className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground bg-foreground/[0.05] rounded px-1 py-px">
                latest
              </span>
            )}
          </div>
        </td>
        <td className="px-4 py-2.5">
          <ReasonBadge reason={v.change_reason} />
          {v.reverted_from_version != null && (
            <span className="text-[10.5px] text-muted-foreground ml-2">from v{v.reverted_from_version}</span>
          )}
        </td>
        <td className="px-4 py-2.5">
          <span className="font-mono text-[10.5px] text-muted-foreground">{formatUTCCompact(v.created_at)}</span>
        </td>
        <td className="px-4 py-2.5 text-right">
          {stats ? (
            <span className="inline-flex items-center gap-2 font-mono text-[10.5px] tabular-nums">
              <span className="text-emerald-500">+{stats.added}</span>
              <span className="text-red-500">−{stats.removed}</span>
              <DiffBar added={stats.added} removed={stats.removed} />
            </span>
          ) : (
            <span className="font-mono text-[10.5px] text-muted-foreground/70">—</span>
          )}
        </td>
        <td className="px-4 py-2.5 text-right">
          {!v.is_active && (
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-[10.5px] gap-1.5"
              onClick={(e) => {
                e.stopPropagation();
                onRequestRevert();
              }}
            >
              <RotateCcw className="w-3 h-3" />
              Revert
            </Button>
          )}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-border">
          <td colSpan={5} className="p-0">
            <VersionDiffPanel v={v} prev={prev} />
          </td>
        </tr>
      )}
    </>
  );
}

function ReasonBadge({ reason }: { reason: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    publish: { label: 'Published', cls: 'text-emerald-500 bg-emerald-500/15' },
    revert: { label: 'Reverted', cls: 'text-amber-500 bg-amber-500/15' },
    initial_creation: { label: 'Created', cls: 'text-emerald-500 bg-emerald-500/15' },
  };
  const m = map[reason] ?? { label: reason, cls: 'text-foreground/80 bg-foreground/[0.05] border border-border' };
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider rounded px-1.5 py-0.5',
        m.cls,
      )}
    >
      {m.label}
    </span>
  );
}

function DiffBar({ added, removed }: { added: number; removed: number }) {
  const total = Math.max(1, added + removed);
  const aw = (added / total) * 100;
  const rw = (removed / total) * 100;
  return (
    <span className="inline-flex w-[60px] h-[6px] rounded-sm overflow-hidden bg-foreground/[0.05] border border-border">
      <span className="h-full bg-emerald-500" style={{ width: `${aw}%` }} />
      <span className="h-full bg-red-500" style={{ width: `${rw}%` }} />
    </span>
  );
}

function VersionDiffPanel({ v, prev }: { v: LogSourceVersion; prev: LogSourceVersion | null }) {
  const prevVrl = prev?.parser_vrl;
  const oldHl = useVrlHighlight(prevVrl);
  const newHl = useVrlHighlight(v.parser_vrl);
  if (!prevVrl) {
    // First version — show the code as a plain listing with + markers
    const lines = v.parser_vrl.split('\n');
    return (
      <div className="bg-foreground/[0.02] border-t border-border px-5 py-3">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">Initial VRL</span>
          <span className="text-[10.5px] font-mono text-muted-foreground">v{v.version_number}</span>
          <div className="flex-1" />
          <span className="text-[10.5px] font-mono text-emerald-500">+{lines.length} lines</span>
        </div>
        <div className="rounded-md border border-border bg-background overflow-auto max-h-[360px]">
          <pre className="font-mono text-[11px] leading-[1.6] p-0 m-0">
            {lines.map((line, i) => (
              <div key={i} className="flex bg-emerald-500/[0.06]">
                <span className="w-10 pr-2 text-right shrink-0 text-muted-foreground/70 select-none">{i + 1}</span>
                <span className="w-5 text-center text-emerald-500 shrink-0 select-none">+</span>
                <span className="text-foreground/80 pr-4 flex-1 whitespace-pre">
                  <VrlLine segments={newHl[i]} text={line} />
                </span>
              </div>
            ))}
          </pre>
        </div>
      </div>
    );
  }

  const diff = lineDiff(prevVrl, v.parser_vrl);
  const stats = diffStats(diff);

  return (
    <div className="bg-foreground/[0.02] border-t border-border px-5 py-3">
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">VRL diff</span>
        <span className="font-mono text-[10.5px] text-muted-foreground">v{prev.version_number}</span>
        <ChevronRight className="w-3 h-3 text-muted-foreground/70" />
        <span className="font-mono text-[10.5px] text-foreground">v{v.version_number}</span>
        <div className="flex-1" />
        <span className="font-mono text-[10.5px] text-emerald-500">+{stats.added}</span>
        <span className="font-mono text-[10.5px] text-red-500">−{stats.removed}</span>
      </div>
      <div className="rounded-md border border-border bg-background overflow-auto max-h-[420px]">
        <pre className="font-mono text-[11px] leading-[1.6] p-0 m-0">
          {diff.map((d, i) => {
            const rowBg =
              d.kind === 'add' ? 'bg-emerald-500/[0.08]' : d.kind === 'del' ? 'bg-red-500/[0.08]' : '';
            const sign = d.kind === 'add' ? '+' : d.kind === 'del' ? '−' : ' ';
            const signColor =
              d.kind === 'add' ? 'text-emerald-500' : d.kind === 'del' ? 'text-red-500' : 'text-muted-foreground/70';
            return (
              <div key={i} className={cn('flex', rowBg)}>
                <span className="w-9 pr-1 text-right shrink-0 text-muted-foreground/70 select-none">{d.l || ''}</span>
                <span className="w-9 pr-1 text-right shrink-0 text-muted-foreground/70 select-none border-r border-border">
                  {d.r || ''}
                </span>
                <span className={cn('w-5 text-center shrink-0 select-none', signColor)}>{sign}</span>
                <span className="pr-4 flex-1 text-foreground/80 whitespace-pre">
                  <VrlLine segments={d.kind === 'del' ? oldHl[(d.l ?? 0) - 1] : newHl[(d.r ?? 0) - 1]} text={d.text} />
                </span>
              </div>
            );
          })}
        </pre>
      </div>
    </div>
  );
}

// Inline diff shown inside the VRL editor pane after pivt applies an edit.
// Uses the same density / coloring as VersionDiffPanel on the Versions tab.
function VrlAiDiffView({ prevVrl, newVrl }: { prevVrl: string; newVrl: string }) {
  const diff = lineDiff(prevVrl, newVrl);
  const oldHl = useVrlHighlight(prevVrl);
  const newHl = useVrlHighlight(newVrl);
  const stats = diffStats(diff);
  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="shrink-0 flex items-center gap-2 px-4 py-2 border-b border-border bg-foreground/[0.02]">
        <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">
          pivt diff
        </span>
        <span className="text-[10.5px] font-mono text-muted-foreground">current</span>
        <ChevronRight className="w-3 h-3 text-muted-foreground/70" />
        <span className="text-[10.5px] font-mono text-foreground">proposed</span>
        <div className="flex-1" />
        <span className="font-mono text-[10.5px] text-emerald-500">+{stats.added}</span>
        <span className="font-mono text-[10.5px] text-red-500">−{stats.removed}</span>
      </div>
      <div className="flex-1 min-h-0 overflow-auto bg-background">
        <pre className="font-mono text-[11px] leading-[1.6] p-0 m-0">
          {diff.map((d, i) => {
            const rowBg =
              d.kind === 'add' ? 'bg-emerald-500/[0.08]' : d.kind === 'del' ? 'bg-red-500/[0.08]' : '';
            const sign = d.kind === 'add' ? '+' : d.kind === 'del' ? '−' : ' ';
            const signColor =
              d.kind === 'add'
                ? 'text-emerald-500'
                : d.kind === 'del'
                  ? 'text-red-500'
                  : 'text-muted-foreground/70';
            return (
              <div key={i} className={cn('flex', rowBg)}>
                <span className="w-9 pr-1 text-right shrink-0 text-muted-foreground/70 select-none">
                  {d.l || ''}
                </span>
                <span className="w-9 pr-1 text-right shrink-0 text-muted-foreground/70 select-none border-r border-border">
                  {d.r || ''}
                </span>
                <span className={cn('w-5 text-center shrink-0 select-none', signColor)}>{sign}</span>
                <span className="pr-4 flex-1 text-foreground/80 whitespace-pre">
                  <VrlLine segments={d.kind === 'del' ? oldHl[(d.l ?? 0) - 1] : newHl[(d.r ?? 0) - 1]} text={d.text} />
                </span>
              </div>
            );
          })}
        </pre>
      </div>
    </div>
  );
}

// ----- diff helpers -----

type DiffEntry = { kind: 'eq' | 'add' | 'del'; text: string; l?: number; r?: number };

// LCS-based line diff. Same algorithm as design-ref/shadcn/log-source-tabs.jsx.
function lineDiff(oldText: string, newText: string): DiffEntry[] {
  const a = (oldText || '').split('\n');
  const b = (newText || '').split('\n');
  const n = a.length;
  const m = b.length;
  const dp: Int32Array[] = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out: DiffEntry[] = [];
  let i = 0;
  let j = 0;
  let l = 1;
  let r = 1;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: 'eq', text: a[i], l: l++, r: r++ });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ kind: 'del', text: a[i], l: l++ });
      i++;
    } else {
      out.push({ kind: 'add', text: b[j], r: r++ });
      j++;
    }
  }
  while (i < n) out.push({ kind: 'del', text: a[i++], l: l++ });
  while (j < m) out.push({ kind: 'add', text: b[j++], r: r++ });
  return out;
}

function diffStats(diff: DiffEntry[]) {
  return {
    added: diff.filter((d) => d.kind === 'add').length,
    removed: diff.filter((d) => d.kind === 'del').length,
  };
}

// ============================================================================
// AI panel (inline)
// ============================================================================

type AiChatMessage = {
  role: 'user' | 'assistant';
  content: string;
  hasChanges?: boolean;
  validation?: { valid: boolean; errors: string[] };
};

const AI_QUICK_ACTIONS = [
  'Explain this parser',
  'Add a field for user agent',
  'Redact sensitive fields',
  'Find redundant logic',
];

// Inline pivt chat sized to match the dense redesign tokens (text-[11.5px], h-6 chips,
// rounded-md cards). Uses the same useMelodJob + api.melodEditParser plumbing as the
// shared ParserEditChat, but renders without the Card chrome and at the smaller text
// scale called for in design-ref/shadcn/log-source-vrl.jsx (AIAssistPanel, lines 294+).
export function LogSourceAiPanel({
  parserId,
  sourceName,
  sourceType,
  currentVrl,
  onVrlUpdate,
  onUndo,
  canUndo,
  mode = 'parser',
  baseParserVrl,
}: {
  parserId: string;
  sourceName: string;
  sourceType: string;
  currentVrl: string;
  onVrlUpdate: (info: VrlUpdateInfo) => void;
  onUndo?: () => void;
  canUndo?: boolean;
  /**
   * NAN-874: when 'extension', the panel edits a parser EXTENSION overlay
   * instead of the parser. The agent is given the OOTB parser as read-only
   * context via `baseParserVrl` so it targets the right field names.
   */
  mode?: 'parser' | 'extension';
  baseParserVrl?: string;
}) {
  const { toast } = useToast();
  const { data: activeSchema } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const searchSourceField = activeSchema?.schema === 'ocsf'
    ? 'metadata.log_source'
    : 'source_type';
  // NAN-4132: no AI capability → no ai-availability probe (fail closed).
  const melodCapable = useCapabilities().capabilities.melod === true;
  const { data: melodStatus, loading: melodStatusLoading } = useMelodStatus({ skip: !melodCapable });
  const editParserJob = useMelodJob<MelodEditParserResponse>();
  const loading = editParserJob.loading;
  const elapsedMs = useElapsedWhile(loading);
  const rawPassThrough = mode === 'parser' && isRawPassThroughVrl(currentVrl);

  const [messages, setMessages] = useState<AiChatMessage[]>([]);
  const [input, setInput] = useState('');
  // Optional sample-log input (Play-icon toggles visibility). When non-empty,
  // each non-blank line is passed to melodEditParser as `sample_logs` so the
  // agent sees actual event shapes AND the runtime-retry loop validates the
  // proposed VRL against them.
  const [sampleLogs, setSampleLogs] = useState('');
  const [showSampleInput, setShowSampleInput] = useState(false);
  const [fetchingSamples, setFetchingSamples] = useState(false);
  const [autoSampleCount, setAutoSampleCount] = useState(0);
  const autoSamplesRef = useRef<{ parserId: string; sourceType: string; samples: string[] } | null>(null);
  const storageKey = `melod-session-${mode}-${parserId}`;
  const [sessionId, setSessionId] = useState<string | undefined>(
    () => localStorage.getItem(storageKey) ?? undefined,
  );
  const scrollRef = useState<HTMLDivElement | null>(null);
  const [scrollEl, setScrollEl] = scrollRef;
  const busy = loading || fetchingSamples;
  const hasAutoSampleContext = autoSamplesRef.current?.parserId === parserId
    && autoSamplesRef.current.sourceType === sourceType;

  // Auto-scroll to bottom when messages change.
  useEffect(() => {
    if (scrollEl) scrollEl.scrollTop = scrollEl.scrollHeight;
  }, [messages, loading, scrollEl]);

  const send = async (text: string) => {
    const userMessage = text.trim();
    if (!userMessage || busy) return;
    const vrlBefore = currentVrl;
    let messageAdded = false;
    let sampleFetchAttempted = false;

    try {
      let sampleLogsArray = sampleLogs
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const shouldAutoFetch = mode === 'parser'
        && sampleLogsArray.length === 0
        && (rawPassThrough || hasAutoSampleContext);

      if (shouldAutoFetch) {
        const cached = autoSamplesRef.current;
        if (cached?.parserId === parserId && cached.sourceType === sourceType) {
          sampleLogsArray = cached.samples;
        } else {
          sampleFetchAttempted = true;
          setFetchingSamples(true);
          const now = new Date();
          const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          const response = await api.search({
            query: nplFieldEquals(searchSourceField, sourceType),
            time_range: { start: yesterday.toISOString(), end: now.toISOString() },
            limit: 5,
            skip_field_stats: true,
          });
          sampleLogsArray = extractRecentParserSamples(response.results ?? []);
          if (sampleLogsArray.length === 0) {
            throw new Error(`No recent events found for ${searchSourceField}="${sourceType}". Wait for the collector to run or paste a sample with the play button.`);
          }
          autoSamplesRef.current = { parserId, sourceType, samples: sampleLogsArray };
          setAutoSampleCount(sampleLogsArray.length);
        }
      }

      const modelMessage = mode === 'parser' && (rawPassThrough || hasAutoSampleContext || shouldAutoFetch)
        ? buildLogSourceParserPrompt({
            userMessage,
            sourceName,
            sourceType,
            isRawPassThrough: rawPassThrough,
          })
        : userMessage;

      setInput('');
      setMessages((prev) => [...prev, { role: 'user', content: userMessage }]);
      messageAdded = true;
      const response = await editParserJob.start(() =>
        api.melodEditParser({
          parser_id: parserId,
          current_vrl: currentVrl,
          message: modelMessage,
          session_id: sessionId,
          ...(sampleLogsArray.length > 0
            ? { sample_logs: sampleLogsArray }
            : {}),
          // NAN-874: only send base_parser_vrl when editing an extension overlay.
          ...(mode === 'extension' && baseParserVrl
            ? { base_parser_vrl: baseParserVrl }
            : {}),
        }),
        // NAN-4778: parser edits can run many minutes; wait for the job.
        { maxWaitMs: PARSER_JOB_MAX_WAIT_MS },
      );
      if (response.session_id) {
        setSessionId(response.session_id);
        localStorage.setItem(storageKey, response.session_id);
      }
      const hasChanges = !!response.updated_vrl;
      if (response.updated_vrl) {
        onVrlUpdate({
          newVrl: response.updated_vrl,
          previousVrl: vrlBefore,
          diff: computeDiff(vrlBefore, response.updated_vrl),
        });
      }
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: response.message,
          hasChanges,
          validation: response.validation,
        },
      ]);
    } catch (err) {
      toast({
        title: sampleFetchAttempted ? 'Could not load recent samples' : 'Error',
        description: err instanceof Error ? err.message : 'Failed to process request',
        variant: 'destructive',
      });
      if (messageAdded) setMessages((prev) => prev.slice(0, -1));
    } finally {
      setFetchingSamples(false);
    }
  };

  if (melodStatusLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <PivtIcon className="w-4 h-4 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (!melodCapable || !melodStatus?.connected) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-4 text-center">
        <PivtIcon className="w-6 h-6 text-muted-foreground mb-2" />
        <div className="text-[12px] text-foreground">pivt not configured</div>
        <div className="text-[10.5px] text-muted-foreground mt-1 max-w-[280px]">
          Configure pivt in Settings to enable AI-powered parser editing.
        </div>
      </div>
    );
  }

  const lineCount = currentVrl.split('\n').length;
  const quickActions = rawPassThrough
    ? [
        'Build a complete parser from recent events',
        'Explain the raw event shape',
        'Map the most useful security fields',
        'Generate parser test cases',
      ]
    : AI_QUICK_ACTIONS;

  return (
    <div className="flex flex-col h-full min-h-0 overflow-hidden">
      {/* Scrollable conversation */}
      <div ref={setScrollEl} className="flex-1 min-h-0 overflow-auto px-3 py-3 space-y-3">
        <div className="rounded-md bg-primary/[0.06] border border-primary/20 p-2.5 flex items-start gap-2">
          <PivtIcon className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5" />
          <div className="text-[11px] text-foreground/80 leading-relaxed">
            {mode === 'extension' ? (
              <>
                <span className="font-medium text-foreground">pivt is editing your extension overlay</span> —{' '}
                <span className="font-mono text-[10.5px]">{lineCount}</span> lines. The OOTB parser is in pivt's
                context as read-only reference; edits here only touch the extension.
              </>
            ) : rawPassThrough ? (
              <>
                <span className="font-medium text-foreground">pivt recognizes this raw pass-through</span> —{' '}
                <span className="font-mono text-[10.5px]">source_type={sourceType}</span>. Recent events are fetched
                automatically when you ask it to build the parser.
              </>
            ) : (
              <>
                <span className="font-medium text-foreground">pivt has full context of this parser</span> —{' '}
                <span className="font-mono text-[10.5px]">{lineCount}</span> lines. Ask for edits, explanations, or
                test cases.
              </>
            )}
          </div>
        </div>

        {messages.map((msg, i) => (
          <AiMessage key={i} message={msg} />
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-[11px] text-muted-foreground" role="status">
            <PivtIcon className="w-3.5 h-3.5 animate-spin text-primary" />
            <span>{editParserJob.progress && editParserJob.progress !== 'Working...' ? editParserJob.progress : 'pivt is thinking…'}</span>
            <span className="font-mono text-[10.5px]">{formatElapsed(elapsedMs)}</span>
          </div>
        )}
        {fetchingSamples && (
          <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
            <LoadingIcon className="w-3.5 h-3.5 text-primary" />
            <span>Fetching recent events for <span className="font-mono">{sourceType}</span>…</span>
          </div>
        )}
      </div>

      {/* Quick actions + input */}
      <div className="shrink-0 px-3 py-2 border-t border-border">
        <div className="flex items-center gap-1.5 flex-wrap mb-2">
          {quickActions.map((a) => (
            <button
              key={a}
              type="button"
              onClick={() => send(a)}
              disabled={busy}
              className="h-6 px-2 rounded-full border border-border bg-card text-[10.5px] text-foreground/80 hover:text-foreground hover:border-primary/40 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {a}
            </button>
          ))}
        </div>
        {showSampleInput && (
          <div className="mb-2">
            <label className="mb-1 block font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Sample logs (one per line)
            </label>
            <Textarea
              value={sampleLogs}
              onChange={(e) => setSampleLogs(e.target.value)}
              placeholder="Paste 1–5 raw events. pivt sees these and the retry loop validates against them."
              rows={3}
              className="resize-none min-h-[64px] max-h-[160px] px-2.5 py-1.5 rounded-md border border-border bg-card font-mono text-[11px] focus:border-primary focus:outline-none focus-visible:ring-0"
            />
          </div>
        )}
        {autoSampleCount > 0 && !showSampleInput && (
          <div className="mb-2 font-mono text-[10px] text-muted-foreground">
            {autoSampleCount} recent event{autoSampleCount === 1 ? '' : 's'} loaded automatically · source_type={sourceType}
          </div>
        )}
        <div className="flex items-end gap-2">
          <button
            type="button"
            onClick={() => setShowSampleInput((v) => !v)}
            title={showSampleInput ? 'Hide sample logs' : 'Add sample logs for pivt'}
            className={cn(
              'h-[34px] w-[34px] shrink-0 flex items-center justify-center rounded-md border transition-colors',
              showSampleInput
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-border bg-card text-muted-foreground hover:text-foreground hover:border-primary/40',
            )}
          >
            <Play className="w-3.5 h-3.5" />
          </button>
          <Textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                void send(input);
              }
            }}
            rows={2}
            placeholder="Ask pivt to modify, explain, or generate tests…"
            className="flex-1 resize-none min-h-[56px] max-h-[160px] px-2.5 py-1.5 rounded-md border border-border bg-card text-[12px] focus:border-primary focus:outline-none focus-visible:ring-0"
          />
          <Button
            size="sm"
            className="h-[34px] gap-1.5 shrink-0"
            onClick={() => void send(input)}
            disabled={!input.trim() || busy}
          >
            {busy ? <LoadingIcon className="w-3.5 h-3.5" /> : <Send className="w-3.5 h-3.5" />}
          </Button>
        </div>
        {canUndo && onUndo && (
          <div className="mt-2 flex justify-end">
            <button
              type="button"
              onClick={onUndo}
              className="text-[10.5px] font-mono text-muted-foreground hover:text-foreground transition-colors"
            >
              Undo last AI edit
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function AiMessage({ message }: { message: AiChatMessage }) {
  if (message.role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-md bg-foreground/[0.05] border border-border px-2.5 py-1.5 text-[11.5px] text-foreground whitespace-pre-wrap">
          {message.content}
        </div>
      </div>
    );
  }
  return (
    <div className="flex items-start gap-2">
      <div className="shrink-0 w-5 h-5 rounded-full bg-primary/15 border border-primary/30 flex items-center justify-center mt-0.5">
        <PivtIcon className="w-2.5 h-2.5 text-primary" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[11.5px] text-foreground/80 leading-[1.55]">
          <Markdown className="prose prose-invert prose-sm max-w-none [&_p]:text-[11.5px] [&_p]:my-1 [&_code]:text-[10.5px] [&_pre]:text-[10.5px]">
            {message.content}
          </Markdown>
        </div>
        {message.hasChanges && (
          <div className="mt-1.5 inline-flex items-center gap-1 text-[10px] font-mono text-emerald-500 bg-emerald-500/15 rounded px-1.5 py-0.5">
            <Check className="w-3 h-3" /> Changes applied — see diff in editor
          </div>
        )}
        {message.validation && (
          <div
            className={cn(
              'mt-1.5 inline-flex items-center gap-1 text-[10px] font-mono rounded px-1.5 py-0.5',
              message.validation.valid
                ? 'text-emerald-500 bg-emerald-500/15'
                : 'text-red-500 bg-red-500/15',
            )}
          >
            {message.validation.valid ? <Check className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
            {message.validation.valid ? 'VRL valid' : `${message.validation.errors.length} error${message.validation.errors.length === 1 ? '' : 's'}`}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Confirm dialog
// ============================================================================

function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  confirmIcon,
  confirmTone = 'default',
  onConfirm,
  disabled,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  confirmIcon?: ReactNode;
  confirmTone?: 'default' | 'warn' | 'danger';
  onConfirm: () => void;
  disabled?: boolean;
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
        <AlertDialogHeader className="border-b border-border px-5 py-4">
          <AlertDialogTitle className="text-[14px] font-semibold">{title}</AlertDialogTitle>
          <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground">
            {description}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter className="border-t border-border px-5 py-3">
          <AlertDialogCancel className="h-8 text-[11.5px]">Cancel</AlertDialogCancel>
          <AlertDialogAction
            className={cn(
              'h-8 text-[11.5px] gap-1.5',
              confirmTone === 'warn' && 'bg-amber-600 hover:bg-amber-700 text-white',
              confirmTone === 'danger' && 'bg-red-600 hover:bg-red-700 text-white',
            )}
            disabled={disabled}
            onClick={onConfirm}
          >
            {confirmIcon}
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

// ============================================================================
// Parser extension tab (NAN-874)
// ============================================================================

function ExtensionTab({
  source,
  updating,
  onSave,
}: {
  source: LogSource;
  updating: boolean;
  onSave: (data: { extension_vrl: string; extension_enabled: boolean }) => Promise<void>;
}) {
  const shared = useSharedTenant();
  const { toast } = useToast();
  const initialExt = source.extension_vrl ?? '';
  const [editedExt, setEditedExt] = useState(initialExt);
  const [enabled, setEnabled] = useState<boolean>(source.extension_enabled ?? false);
  const [sidePanelTab, setSidePanelTab] = useState<SidePanelTabId>('test');
  const sidePanel = useParserSidePanelTabs(sidePanelTab);
  const [validationResult, setValidationResult] = useState<ValidationResult>(null);
  const [validating, setValidating] = useState(false);
  const [validatedJustNow, setValidatedJustNow] = useState(false);

  // Persist the editor/side-panel split across reloads.
  const extLayout = useDefaultLayout({
    id: 'logsource-extension-tab-v1',
    panelIds: ['extension-editor', 'extension-side-panel'],
    storage: typeof window !== 'undefined' ? window.localStorage : undefined,
  });

  // Reset when navigating to a different log_source.
  useEffect(() => {
    setEditedExt(source.extension_vrl ?? '');
    setEnabled(source.extension_enabled ?? false);
    setValidationResult(null);
    setValidatedJustNow(false);
  }, [source.id, source.extension_vrl, source.extension_enabled]);

  const dirty =
    editedExt !== (source.extension_vrl ?? '') || enabled !== (source.extension_enabled ?? false);
  const isStub = !source.parser_vrl || source.parser_vrl.trim() === '';

  const handleValidate = async () => {
    setValidating(true);
    setValidatedJustNow(false);
    try {
      const result = await api.validateLogSourceVrl(editedExt);
      setValidationResult({ valid: result.valid, errors: result.errors });
      setValidatedJustNow(true);
      setTimeout(() => setValidatedJustNow(false), 3000);
      if (!result.valid) {
        // Auto-switch to Diagnostics so the user sees the errors.
        setSidePanelTab('diag');
      }
    } catch (err) {
      toast({
        title: 'Validation failed',
        description: err instanceof Error ? err.message : 'Unable to validate',
        variant: 'destructive',
      });
    } finally {
      setValidating(false);
    }
  };

  const handleSave = async () => {
    try {
      await onSave({ extension_vrl: editedExt, extension_enabled: enabled });
      toast({
        title: 'Extension saved',
        description: shared
          ? 'Draft updated. Publish a new version to roll the extension out to your parser cell.'
          : 'Draft updated. Publish a new version and redeploy to push the extension to Vector.',
      });
    } catch (err) {
      toast({
        title: 'Save failed',
        description: err instanceof Error ? err.message : 'Unable to save',
        variant: 'destructive',
      });
    }
  };

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Toolbar — same shape as VrlEditorTab */}
      <div className="shrink-0 flex flex-wrap items-center gap-2 px-4 py-2 border-b border-border bg-card/40">
        <div className="flex items-center gap-2 min-w-0">
          <PivtIcon className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="text-[11.5px] font-mono text-foreground truncate">
            {effectiveSourceType(source)}.ext.vrl
          </span>
          <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">
            VRL · extension
          </span>
          {isStub && (
            <span className="font-mono text-[10px] text-muted-foreground/80">
              (stub — extension IS the parser)
            </span>
          )}
          {dirty && (
            <span className="inline-flex items-center gap-1 text-[10px] font-mono text-amber-500 bg-amber-500/15 rounded px-1.5 py-0.5">
              <span className="w-1 h-1 rounded-full bg-amber-500" />
              UNSAVED
            </span>
          )}
        </div>
        <div className="flex-1" />
        <label className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          <Switch checked={enabled} onCheckedChange={setEnabled} disabled={updating} />
          <span>Enabled</span>
        </label>
        <Button
          variant="outline"
          size="sm"
          className="h-7 text-[11.5px] gap-1.5"
          onClick={handleValidate}
          disabled={validating}
        >
          {validating ? <LoadingIcon className="w-3 h-3" /> : <Check className="w-3 h-3" />}
          Validate
        </Button>
        <Button
          size="sm"
          className="h-7 text-[11.5px] gap-1.5"
          onClick={handleSave}
          disabled={!dirty || updating}
        >
          {updating ? <LoadingIcon className="w-3 h-3" /> : <Save className="w-3 h-3" />}
          Save
        </Button>
        {validatedJustNow && !validating && validationResult?.valid && (
          <span className="text-[10px] font-mono text-muted-foreground whitespace-nowrap ml-1">
            <span className="text-emerald-500">✓</span> Validated
          </span>
        )}
      </div>

      {/* Resizable editor / side-panel split. extLayout persists drag position via localStorage. */}
      <div className="flex-1 min-h-0">
        <ResizablePanelGroup
          orientation="horizontal"
          defaultLayout={extLayout.defaultLayout}
          onLayoutChanged={extLayout.onLayoutChanged}
          className="divide-x divide-border"
        >
          <ResizablePanel id="extension-editor" defaultSize="58%" minSize="30%">
            <div className="flex flex-col min-h-0 h-full bg-background">
              <VrlEditor value={editedExt} onChange={setEditedExt} className="h-full" />
            </div>
          </ResizablePanel>

          <ResizableHandle withHandle />

          <ResizablePanel id="extension-side-panel" defaultSize="42%" minSize="22%">
            <div className="flex flex-col min-h-0 h-full bg-card/40">
              <div className="shrink-0 flex items-center gap-1 px-3 py-1.5 border-b border-border">
                {sidePanel.tabs.map((t) => {
                  const Icon = t.Icon;
                  const isActive = sidePanel.active === t.id;
                  return (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => setSidePanelTab(t.id)}
                      className={cn(
                        'h-7 px-2.5 rounded text-[11px] flex items-center gap-1.5 transition-colors whitespace-nowrap',
                        isActive ? 'text-foreground bg-foreground/[0.06]' : 'text-muted-foreground hover:text-foreground/80',
                      )}
                    >
                      <Icon className="w-3 h-3" />
                      {t.label}
                    </button>
                  );
                })}
              </div>
              <div className="flex-1 min-h-0 overflow-hidden">
                {/* Each panel mounts unconditionally so chat/test state survives tab switches. */}
                {sidePanel.aiAvailable && (
                  <div className={cn('h-full', sidePanel.active === 'ai' ? 'block' : 'hidden')}>
                    <LogSourceAiPanel
                      parserId={source.id}
                      sourceName={source.name}
                      sourceType={effectiveSourceType(source)}
                      currentVrl={editedExt}
                      mode="extension"
                      baseParserVrl={source.parser_vrl}
                      onVrlUpdate={(info) => setEditedExt(info.newVrl)}
                    />
                  </div>
                )}
                <div className={cn('h-full overflow-auto', sidePanel.active === 'test' ? 'block' : 'hidden')}>
                  <ParserTestLab
                    logSourceId={source.id}
                    vrlCode={source.parser_vrl}
                    sourceType={effectiveSourceType(source)}
                    extensionVrl={editedExt}
                  />
                </div>
                <div className={cn('h-full overflow-auto', sidePanel.active === 'diag' ? 'block' : 'hidden')}>
                  <DiagnosticsPanel result={validationResult} />
                </div>
              </div>
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </div>
  );
}

export default LogSourceDetail;
