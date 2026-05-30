// SPDX-License-Identifier: AGPL-3.0-or-later

import { ReactNode, useEffect, useMemo, useState } from 'react';
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
  Loader2,
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
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable';
import { useDefaultLayout } from 'react-resizable-panels';
import { computeDiff, type DiffLine, type VrlUpdateInfo } from '@/lib/parser-diff';
import { ParserTestLab } from '@/components/parser/ParserTestLab';
import { Markdown } from '@/components/ui/markdown';
import { useMelodJob } from '@/enterprise/hooks/use-melod-job';
import { useMelodStatus } from '@/hooks/use-api';
import type { MelodEditParserResponse } from '@/lib/api';
import { Send } from 'lucide-react';
import { SourceConfigForm } from '@/components/log-sources/SourceConfigForm';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';

import { api } from '@/lib/api';
import type {
  LogSource,
  LogSourceDeployment,
  LogSourceVersion,
  SourceConfiguration,
  UpdateLogSource,
} from '@/lib/api';
import { formatUTCCompact } from '@/lib/date-utils';
import {
  SOURCE_TYPE_LABELS,
  logSourceTransportLabel,
} from '@/lib/log-source-transports';
import { cn } from '@/lib/utils';
import { useQuery } from '@tanstack/react-query';

const CONFIG_TYPE_TO_SOURCE_TYPE: Record<string, string> = {
  http: 'routed',
  vector: 'vector',
  kafka: 'kafka',
  aws_s3: 'aws_s3',
  gcp_pubsub: 'gcp_pubsub',
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

  const { data: logSource, loading, refetch } = useLogSource(id);
  useDocumentTitle(logSource?.name || 'Log Source', [logSource?.id]);
  useBreadcrumbTitle(logSource?.name);

  const { data: deployments, refetch: refetchDeployments } = useLogSourceDeployments(id);
  const { data: health, refetch: refetchHealth } = useLogSourceHealth(id);
  const { data: draftStatus, refetch: refetchDraftStatus } = useLogSourceDraftStatus(id);
  const { data: versions, refetch: refetchVersions } = useLogSourceVersions(id);
  const { data: ingestionHistory } = useIngestionHistory(24);

  const { mutate: updateLogSource, loading: updating } = useUpdateLogSource();
  const { mutate: toggleLogSource } = useToggleLogSource();
  const { mutate: validateLogSource, loading: validating } = useValidateLogSource();
  const { mutate: validateVrl } = useValidateLogSourceVrl();
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
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (!logSource) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 px-4 text-center">
        <Rss className="w-10 h-10 text-muted-foreground/50" />
        <div className="text-[13px] font-medium text-foreground">Log source not found</div>
        <Button variant="outline" size="sm" className="h-8" onClick={() => navigate('/ingestion/log-sources')}>
          <ArrowLeft className="w-3.5 h-3.5 mr-1.5" />
          Back to log sources
        </Button>
      </div>
    );
  }

  // ----- derived state -----

  const currentVrl = isEditingVrl ? editedVrl : logSource.parser_vrl;
  const vrlDirty = isEditingVrl && editedVrl !== logSource.parser_vrl;
  const hasDraft = draftStatus?.has_draft_changes ?? false;

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
      await deployLogSource(logSource.id);
      toast({ title: 'Deployed', description: `"${logSource.name}" has been deployed to Vector.` });
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
      toast({ title: 'Undeployed', description: `"${logSource.name}" has been removed from Vector.` });
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
      if (result.success) {
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
      await updateLogSource({ id: logSource.id, data: { parser_vrl: version.parser_vrl } });
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
      source_config: logSource.source_config,
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
      if (JSON.stringify(formData.source_config) !== JSON.stringify(logSource.source_config))
        changed.source_config = formData.source_config;
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
      await updateLogSource({ id: logSource.id, data: { parser_vrl: editedVrl } });
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
      await updateLogSource({ id: logSource.id, data: { parser_vrl: editedVrl } });
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
      <div className="flex flex-col min-h-0 -m-3 bg-background h-[calc(100%+1.5rem)]">
        <LogSourceHero
          source={logSource}
          dirty={vrlDirty}
          health={health}
          deploying={deploying}
          undeploying={undeploying}
          onToggleEnabled={handleToggle}
          onDeploy={() => setDeployDialogOpen(true)}
          onUndeploy={() => setUndeployDialogOpen(true)}
          onClone={() => navigate(`/ingestion/log-sources/new?clone=${logSource.id}`)}
          onViewLogs={() =>
            navigate(
              `/search?q=${encodeURIComponent(`source_type=${effectiveSourceType(logSource)}`)}`,
            )
          }
        />
        <DraftBanner
          show={hasDraft}
          activeVersion={draftStatus?.active_version_number}
          publishing={publishing}
          discarding={discarding}
          validated={logSource.validated}
          onPublish={() => setPublishDialogOpen(true)}
          onDiscard={() => setDiscardDraftDialogOpen(true)}
        />
        <TabNav active={activeTab} onChange={setActiveTab} />

        <div className="flex-1 min-h-0 overflow-auto">
          {activeTab === 'overview' && (
            <OverviewTab source={logSource} health={health} sparklinePoints={sparklinePoints} />
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
          )}
          {activeTab === 'extension' && (
            <ExtensionTab
              source={logSource}
              updating={updating}
              onSave={async ({ extension_vrl, extension_enabled }) => {
                await updateLogSource({
                  id: logSource.id,
                  data: { extension_vrl, extension_enabled },
                });
                refetch();
                refetchDraftStatus();
              }}
            />
          )}
          {activeTab === 'deployments' && <DeploymentsTab deployments={deployments ?? null} />}
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
          description={`Deploy "${logSource.name}" to Vector. Incoming logs matching this source type will be parsed using the current VRL.`}
          confirmLabel={deploying ? 'Deploying…' : 'Deploy'}
          confirmIcon={deploying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
          onConfirm={handleDeploy}
          disabled={deploying}
        />
        <ConfirmDialog
          open={undeployDialogOpen}
          onOpenChange={setUndeployDialogOpen}
          title="Undeploy log source"
          description={`Remove "${logSource.name}" from Vector. Incoming logs for this source type will no longer be parsed until you redeploy.`}
          confirmLabel={undeploying ? 'Undeploying…' : 'Undeploy'}
          confirmIcon={undeploying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Power className="w-3.5 h-3.5" />}
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
          confirmIcon={updating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
          onConfirm={handleSaveVrlConfirmed}
          disabled={updating}
        />
        <ConfirmDialog
          open={publishDialogOpen}
          onOpenChange={setPublishDialogOpen}
          title="Publish log source?"
          description="Create a new version from your current draft and deploy it to Vector. The previous active version is preserved in history."
          confirmLabel={publishing ? 'Publishing…' : 'Publish'}
          confirmIcon={publishing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
          onConfirm={handlePublish}
          disabled={publishing}
        />
        <ConfirmDialog
          open={discardDraftDialogOpen}
          onOpenChange={setDiscardDraftDialogOpen}
          title="Discard draft changes?"
          description={`Reset your working copy to the active deployed version${
            draftStatus?.active_version_number ? ` (v${draftStatus.active_version_number})` : ''
          }. Any unsaved edits will be lost.`}
          confirmLabel={discarding ? 'Discarding…' : 'Discard draft'}
          confirmIcon={discarding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />}
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
          confirmIcon={updating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
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
          confirmIcon={updating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />}
          confirmTone="warn"
          onConfirm={() => {
            if (revertVersionTarget) handleRevertVersion(revertVersionTarget);
          }}
          disabled={updating}
        />
      </div>
    </TooltipProvider>
  );
}

// ============================================================================
// Hero
// ============================================================================

function LogSourceHero({
  source,
  dirty,
  health,
  deploying,
  undeploying,
  onToggleEnabled,
  onDeploy,
  onUndeploy,
  onClone,
  onViewLogs,
}: {
  source: LogSource;
  dirty: boolean;
  health: { events_last_24h?: number; events_last_hour?: number; last_event_at?: string } | null | undefined;
  deploying: boolean;
  undeploying: boolean;
  onToggleEnabled: () => void;
  onDeploy: () => void;
  onUndeploy: () => void;
  onClone: () => void;
  onViewLogs: () => void;
}) {
  const transportLabel = logSourceTransportLabel(source);
  return (
    <div className="shrink-0 border-b border-border bg-card/40">
      {/* Top band */}
      <div className="px-5 pt-4 pb-3 flex items-start gap-4">
        <div className="w-[38px] h-[38px] rounded-lg border border-border bg-card flex items-center justify-center shrink-0 mt-0.5">
          <Rss className="w-[18px] h-[18px] text-muted-foreground" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <div className="text-[17px] font-semibold tracking-[-0.01em] text-foreground whitespace-nowrap truncate">
              {source.name}
            </div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-px whitespace-nowrap">
              Feed workspace
            </span>
            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground whitespace-nowrap">
              {transportLabel} · Parser
            </span>
          </div>
          {source.description && (
            <div className="text-[11.5px] text-muted-foreground mt-1 leading-relaxed max-w-[820px]">
              {source.description}
            </div>
          )}
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            {source.deployed ? (
              <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-emerald-500 bg-emerald-500/15 rounded px-1.5 py-0.5">
                <Check className="w-3 h-3" /> DEPLOYED
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-foreground/80 bg-foreground/[0.05] border border-border rounded px-1.5 py-0.5">
                READY
              </span>
            )}
            {source.namespace && source.namespace !== 'default' && (
              <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-foreground/80 bg-foreground/[0.03] border border-border rounded px-1.5 py-0.5">
                {source.namespace}
              </span>
            )}
            {source.validated ? (
              <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-primary bg-primary/15 rounded px-1.5 py-0.5">
                <Check className="w-3 h-3" /> Validated
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-amber-500 bg-amber-500/15 rounded px-1.5 py-0.5">
                <AlertTriangle className="w-3 h-3" /> Not validated
              </span>
            )}
            {dirty && (
              <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-amber-500 bg-amber-500/15 rounded px-1.5 py-0.5">
                <Edit className="w-3 h-3" /> Unsaved VRL changes
              </span>
            )}
            {source.validation_error && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="inline-flex items-center gap-1 text-[10.5px] font-mono text-red-500 bg-red-500/15 rounded px-1.5 py-0.5 cursor-help">
                    <AlertTriangle className="w-3 h-3" /> Validation failed
                  </span>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[420px] text-[11px]">
                  {source.validation_error}
                </TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>

        {/* Live telemetry */}
        <div className="hidden md:flex items-stretch gap-5 shrink-0">
          <HeroStat value={fmtCount(health?.events_last_24h)} label="Events / 24h" />
          <div className="w-px bg-border" />
          <HeroStat value={fmtCount(health?.events_last_hour)} label="Events / 1h" />
          <div className="w-px bg-border" />
          <HeroStat
            value={health?.last_event_at ? formatUTCCompact(health.last_event_at) : '—'}
            label="Last event"
          />
        </div>
      </div>

      {/* Bottom action bar */}
      <div className="flex items-center gap-2 px-5 py-2 border-t border-border">
        <div className="flex items-center gap-2">
          <EnabledToggle checked={source.enabled} onClick={onToggleEnabled} />
          <span
            className={cn(
              'text-[10.5px] font-mono uppercase tracking-wider',
              source.enabled ? 'text-foreground/80' : 'text-muted-foreground',
            )}
          >
            {source.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        <div className="w-px h-4 bg-border mx-2" />
        <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-foreground/80" onClick={onViewLogs}>
          <Terminal className="w-3.5 h-3.5" />
          View logs
        </Button>
        <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-foreground/80" onClick={onClone}>
          <Copy className="w-3.5 h-3.5" />
          Clone
        </Button>
        <div className="flex-1" />
        {source.deployed && (
          <Button
            variant="ghost"
            size="sm"
            disabled={undeploying}
            onClick={onUndeploy}
            className="h-7 gap-1.5 text-amber-500 hover:text-amber-500 hover:bg-amber-500/10"
          >
            {undeploying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <X className="w-3.5 h-3.5" />}
            Undeploy
          </Button>
        )}
        <Button
          variant="default"
          size="sm"
          disabled={!source.validated || deploying}
          onClick={onDeploy}
          className="h-7 gap-1.5"
        >
          {deploying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
          {source.deployed ? 'Redeploy' : 'Deploy'}
        </Button>
      </div>
    </div>
  );
}

function HeroStat({ value, label }: { value: string; label: string }) {
  return (
    <div className="flex flex-col items-end justify-center">
      <div className="font-mono text-[14px] text-foreground tabular-nums whitespace-nowrap">{value}</div>
      <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground whitespace-nowrap">
        {label}
      </div>
    </div>
  );
}

function EnabledToggle({ checked, onClick }: { checked: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={checked}
      className={cn(
        'w-[30px] h-[17px] rounded-full flex items-center transition-colors relative shrink-0',
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
  );
}

// Visual-only sibling of EnabledToggle for read-only contexts. Avoids the focusable
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
          'absolute w-[13px] h-[13px] rounded-full bg-white/80 shadow',
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

// ============================================================================
// Draft banner
// ============================================================================

function DraftBanner({
  show,
  activeVersion,
  publishing,
  discarding,
  validated,
  onPublish,
  onDiscard,
}: {
  show: boolean;
  activeVersion: number | undefined;
  publishing: boolean;
  discarding: boolean;
  validated: boolean;
  onPublish: () => void;
  onDiscard: () => void;
}) {
  if (!show) return null;
  return (
    <div className="shrink-0 flex items-center justify-between gap-3 px-5 py-2 border-b border-border bg-amber-500/10">
      <div className="flex items-start gap-2 min-w-0">
        <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0 mt-0.5" />
        <div className="text-[11.5px] text-amber-600 dark:text-amber-400 leading-snug">
          <span className="font-medium">Unpublished changes</span>
          <span className="text-amber-600/80 dark:text-amber-400/80 ml-2">
            Working copy differs from deployed version
            {activeVersion ? ` (v${activeVersion})` : ''}. Changes won't affect live parsing until published.
          </span>
        </div>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <Button
          variant="outline"
          size="sm"
          className="h-7 text-[11.5px]"
          disabled={discarding}
          onClick={onDiscard}
        >
          {discarding ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <RotateCcw className="w-3 h-3 mr-1" />}
          Discard draft
        </Button>
        <Button
          size="sm"
          className="h-7 text-[11.5px] bg-amber-600 hover:bg-amber-700 text-white"
          disabled={publishing || !validated}
          onClick={onPublish}
        >
          {publishing ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Rocket className="w-3 h-3 mr-1" />}
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
    <div className="shrink-0 flex items-center gap-0 px-4 border-b border-border bg-card/40">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onChange(t.id)}
          className={cn(
            'relative h-9 px-3 text-[10px] font-medium uppercase tracking-[0.12em] transition-colors',
            active === t.id ? 'text-foreground' : 'text-muted-foreground hover:text-foreground/80',
          )}
        >
          {t.label}
          {active === t.id && <span className="absolute left-0 right-0 -bottom-px h-[2px] bg-primary rounded-full" />}
        </button>
      ))}
    </div>
  );
}

// ============================================================================
// LSCard / LSRow primitives
// ============================================================================

function LSCard({
  title,
  eyebrow,
  action,
  children,
  className,
}: {
  title: string;
  eyebrow?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('rounded-lg border border-border bg-card overflow-hidden', className)}>
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
        {eyebrow && (
          <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/70">{eyebrow}</span>
        )}
        <div className="text-[11.5px] font-medium text-foreground">{title}</div>
        <div className="flex-1" />
        {action}
      </div>
      <div>{children}</div>
    </div>
  );
}

function LSRow({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start gap-4 px-4 py-2.5 border-b border-border last:border-b-0">
      <div className="w-[140px] text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground shrink-0 pt-[1px]">
        {label}
      </div>
      <div className={cn('flex-1 text-[12px]', mono ? 'font-mono text-foreground' : 'text-foreground')}>{children}</div>
    </div>
  );
}

// ============================================================================
// Overview tab
// ============================================================================

function OverviewTab({
  source,
  health,
  sparklinePoints,
}: {
  source: LogSource;
  health:
    | {
        health_status?: string;
        error_rate_24h?: number | null;
        events_last_24h?: number;
        events_last_hour?: number;
        last_event_at?: string | null;
      }
    | null
    | undefined;
  sparklinePoints: number[];
}) {
  const isLive = source.deployed && (sparklinePoints.length > 0 || (health?.events_last_24h ?? 0) > 0);
  const errRate = health?.error_rate_24h;
  return (
    <div className="p-4 space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <LSCard eyebrow="About" title="Feed details">
          <LSRow label="Description">
            <div className="text-foreground/80 leading-relaxed">{source.description || '—'}</div>
          </LSRow>
          <LSRow label="Category" mono>
            <span className="text-foreground">{source.category || '—'}</span>
          </LSRow>
          <LSRow label="Source type" mono>
            <span className="text-primary">{effectiveSourceType(source)}</span>
          </LSRow>
          <LSRow label="Vendor">
            <span className="text-foreground">{source.vendor || '—'}</span>
            {source.product && (
              <>
                <span className="text-muted-foreground/70 mx-2">·</span>
                <span className="text-foreground/80">{source.product}</span>
              </>
            )}
          </LSRow>
          <LSRow label="Namespace" mono>
            <span className="text-foreground/80">{source.namespace || 'default'}</span>
          </LSRow>
          <LSRow label="Created" mono>
            <span className="text-foreground/80">{formatUTCCompact(source.created_at)}</span>
          </LSRow>
          <LSRow label="Updated" mono>
            <span className="text-foreground/80">{formatUTCCompact(source.updated_at)}</span>
          </LSRow>
        </LSCard>

        <LSCard
          eyebrow="Health"
          title="Feed health"
          action={
            isLive && (
              <span className="inline-flex items-center gap-1.5 text-[10px] font-mono text-emerald-500">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                LIVE
              </span>
            )
          }
        >
          <LSRow label="Status">
            {health?.health_status === 'healthy' ? (
              <span className="inline-flex items-center gap-1.5 text-emerald-500">
                <Check className="w-3.5 h-3.5" />
                <span className="text-[12px]">Healthy</span>
              </span>
            ) : health?.health_status === 'stale' ? (
              <span className="inline-flex items-center gap-1.5 text-amber-500">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span className="text-[12px]">Stale — no recent events</span>
              </span>
            ) : health?.health_status === 'error' ? (
              <span className="inline-flex items-center gap-1.5 text-red-500">
                <XCircle className="w-3.5 h-3.5" />
                <span className="text-[12px]">Errors detected</span>
              </span>
            ) : !source.deployed ? (
              <span className="text-foreground/80 text-[12px]">Ready to deploy</span>
            ) : (
              <span className="text-muted-foreground text-[12px]">No data yet</span>
            )}
          </LSRow>
          <LSRow label="Error rate" mono>
            {errRate == null ? (
              <span className="text-muted-foreground">—</span>
            ) : (
              <span
                className={cn(
                  errRate > 0.01 ? 'text-amber-500' : errRate > 0 ? 'text-foreground/80' : 'text-emerald-500',
                )}
              >
                {(errRate * 100).toFixed(2)}%
              </span>
            )}
          </LSRow>
          <LSRow label="Events (24h)" mono>
            <span className="text-foreground">{fmtCount(health?.events_last_24h)}</span>
          </LSRow>
          <LSRow label="Events (1h)" mono>
            <span className="text-foreground">{fmtCount(health?.events_last_hour)}</span>
          </LSRow>
          <LSRow label="Last event" mono>
            <span className="text-foreground/80">
              {health?.last_event_at ? formatUTCCompact(health.last_event_at) : '—'}
            </span>
          </LSRow>
          <LSRow label="Deployed" mono>
            <span className="text-foreground/80">{source.deployed_at ? formatUTCCompact(source.deployed_at) : '—'}</span>
          </LSRow>
        </LSCard>
      </div>

      <Sparkline points={sparklinePoints} isLive={isLive} sourceDeployed={source.deployed} />
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
      <LSCard eyebrow="Live" title="Event volume">
        <div className="flex flex-col items-center justify-center py-10 gap-2 text-muted-foreground">
          <Rss className="w-5 h-5 opacity-40" />
          <div className="text-[11.5px]">No event volume recorded yet.</div>
          <div className="text-[10.5px] text-muted-foreground/70">
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
  const H = 110;
  const PAD_L = 44;
  const PAD_R = 12;
  const PAD_T = 6;
  const PAD_B = 22;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;
  const xAt = (i: number) => PAD_L + (i / (points.length - 1)) * innerW;
  const yAt = (v: number) => PAD_T + innerH - (v / max) * innerH;
  const d = points.map((v, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`).join(' ');
  const dFill = `${d} L${xAt(points.length - 1).toFixed(1)},${yAt(0).toFixed(1)} L${xAt(0).toFixed(1)},${yAt(0).toFixed(1)} Z`;

  return (
    <LSCard
      eyebrow={isLive ? 'Live' : 'Recent'}
      title="Event volume"
      action={
        <span className="text-[10.5px] font-mono text-muted-foreground">
          Peak <span className="text-foreground">{max.toLocaleString()}</span>{' '}
          <span className="text-muted-foreground/70">/ bucket</span>
        </span>
      }
    >
      <div className="p-2">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[110px]" preserveAspectRatio="none">
          {[0, 0.5, 1].map((f, i) => {
            const y = PAD_T + innerH - f * innerH;
            return (
              <line
                key={i}
                x1={PAD_L}
                x2={W - PAD_R}
                y1={y}
                y2={y}
                stroke="var(--border)"
                strokeWidth="1"
                strokeDasharray={i === 0 ? '' : '2,3'}
              />
            );
          })}
          <path d={dFill} fill="var(--primary)" fillOpacity="0.18" />
          <path d={d} fill="none" stroke="var(--primary)" strokeWidth="1.5" strokeOpacity="0.9" />
        </svg>
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
    <div className="p-4 space-y-4">
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
                {updating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
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
        {sourceType !== 'routed' && (
          <div className="px-4 py-3 border-b border-border last:border-b-0">
            <SourceConfigForm
              sourceType={sourceType}
              config={
                (formData.source_config as Record<string, unknown>) ||
                (source.source_config as Record<string, unknown>) ||
                {}
              }
              onConfigChange={(config) => setFormData({ ...formData, source_config: config })}
              credentialId={(formData.credential_id as string) || source.credential_id || undefined}
              onCredentialChange={(id) => setFormData({ ...formData, credential_id: id })}
              disabled={!isEditing}
            />
          </div>
        )}
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
  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Toolbar */}
      <div className="shrink-0 flex items-center gap-2 px-4 py-2 border-b border-border bg-card/40">
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
              {updating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
              Save VRL
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-[11.5px] gap-1.5"
              onClick={onValidate}
              disabled={validating}
            >
              {validating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
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
              {validating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
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
      <div className="flex-1 min-h-0 grid grid-cols-[minmax(0,1fr)_480px] divide-x divide-border">
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
            {([
              { id: 'ai', label: 'pivt', Icon: PivtIcon },
              { id: 'test', label: 'Test events', Icon: Play },
              { id: 'diag', label: 'Diagnostics', Icon: AlertTriangle },
            ] as const).map((t) => {
              const Icon = t.Icon;
              const isActive = sidePanelTab === t.id;
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
            <div className={cn('h-full', sidePanelTab === 'ai' ? 'block' : 'hidden')}>
              <LogSourceAiPanel
                parserId={source.id}
                currentVrl={currentVrl}
                onVrlUpdate={onAiVrlUpdate}
                onUndo={onUndo}
                canUndo={vrlHistory.length > 0}
              />
            </div>
            <div className={cn('h-full overflow-auto', sidePanelTab === 'test' ? 'block' : 'hidden')}>
              <ParserTestLab
                vrlCode={editedVrl || source.parser_vrl}
                sourceType={source.match_values?.[0] || source.source_type}
                currentDeployedVrl={source.parser_vrl}
              />
            </div>
            <div className={cn('h-full overflow-auto', sidePanelTab === 'diag' ? 'block' : 'hidden')}>
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

function DeploymentsTab({ deployments }: { deployments: LogSourceDeployment[] | null }) {
  if (!deployments || deployments.length === 0) {
    return (
      <div className="p-4">
        <LSCard eyebrow="History" title="Deployment history">
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
    <div className="p-4">
      <LSCard
        eyebrow="History"
        title="Deployment history"
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
                          ? 'Deployed successfully'
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
      <div className="p-4">
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
    <div className="p-4">
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
                {publishing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Rocket className="w-3 h-3" />}
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
                <span className="text-foreground/80 pr-4 flex-1 whitespace-pre">{line}</span>
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
                <span className="pr-4 flex-1 text-foreground/80 whitespace-pre">{d.text}</span>
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
                <span className="pr-4 flex-1 text-foreground/80 whitespace-pre">{d.text}</span>
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
function LogSourceAiPanel({
  parserId,
  currentVrl,
  onVrlUpdate,
  onUndo,
  canUndo,
  mode = 'parser',
  baseParserVrl,
}: {
  parserId: string;
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
  const { data: melodStatus, loading: melodStatusLoading } = useMelodStatus();
  const editParserJob = useMelodJob<MelodEditParserResponse>();
  const loading = editParserJob.loading;

  const [messages, setMessages] = useState<AiChatMessage[]>([]);
  const [input, setInput] = useState('');
  // Optional sample-log input (Play-icon toggles visibility). When non-empty,
  // each non-blank line is passed to melodEditParser as `sample_logs` so the
  // agent sees actual event shapes AND the runtime-retry loop validates the
  // proposed VRL against them.
  const [sampleLogs, setSampleLogs] = useState('');
  const [showSampleInput, setShowSampleInput] = useState(false);
  const storageKey = `melod-session-${mode}-${parserId}`;
  const [sessionId, setSessionId] = useState<string | undefined>(
    () => localStorage.getItem(storageKey) ?? undefined,
  );
  const scrollRef = useState<HTMLDivElement | null>(null);
  const [scrollEl, setScrollEl] = scrollRef;

  // Auto-scroll to bottom when messages change.
  useEffect(() => {
    if (scrollEl) scrollEl.scrollTop = scrollEl.scrollHeight;
  }, [messages, loading, scrollEl]);

  const send = async (text: string) => {
    const userMessage = text.trim();
    if (!userMessage || loading) return;
    const vrlBefore = currentVrl;
    setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: userMessage }]);

    try {
      const sampleLogsArray = sampleLogs
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const response = await editParserJob.start(() =>
        api.melodEditParser({
          parser_id: parserId,
          current_vrl: currentVrl,
          message: userMessage,
          session_id: sessionId,
          ...(sampleLogsArray.length > 0
            ? { sample_logs: sampleLogsArray }
            : {}),
          // NAN-874: only send base_parser_vrl when editing an extension overlay.
          ...(mode === 'extension' && baseParserVrl
            ? { base_parser_vrl: baseParserVrl }
            : {}),
        }),
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
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to process request',
        variant: 'destructive',
      });
      setMessages((prev) => prev.slice(0, -1));
    }
  };

  if (melodStatusLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <PivtIcon className="w-4 h-4 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (!melodStatus?.connected) {
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
          <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
            <PivtIcon className="w-3.5 h-3.5 animate-spin text-primary" />
            <span>pivt is thinking…</span>
          </div>
        )}
      </div>

      {/* Quick actions + input */}
      <div className="shrink-0 px-3 py-2 border-t border-border">
        <div className="flex items-center gap-1.5 flex-wrap mb-2">
          {AI_QUICK_ACTIONS.map((a) => (
            <button
              key={a}
              type="button"
              onClick={() => send(a)}
              disabled={loading}
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
                send(input);
              }
            }}
            rows={2}
            placeholder="Ask pivt to modify, explain, or generate tests…"
            className="flex-1 resize-none min-h-[56px] max-h-[160px] px-2.5 py-1.5 rounded-md border border-border bg-card text-[12px] focus:border-primary focus:outline-none focus-visible:ring-0"
          />
          <Button
            size="sm"
            className="h-[34px] gap-1.5 shrink-0"
            onClick={() => send(input)}
            disabled={!input.trim() || loading}
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
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
  const { toast } = useToast();
  const initialExt = source.extension_vrl ?? '';
  const [editedExt, setEditedExt] = useState(initialExt);
  const [enabled, setEnabled] = useState<boolean>(source.extension_enabled ?? false);
  const [sidePanelTab, setSidePanelTab] = useState<'ai' | 'test' | 'diag'>('test');
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
        description:
          'Draft updated. Publish a new version and redeploy to push the extension to Vector.',
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
      <div className="shrink-0 flex items-center gap-2 px-4 py-2 border-b border-border bg-card/40">
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
          {validating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
          Validate
        </Button>
        <Button
          size="sm"
          className="h-7 text-[11.5px] gap-1.5"
          onClick={handleSave}
          disabled={!dirty || updating}
        >
          {updating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
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
                {([
                  { id: 'ai', label: 'pivt', Icon: PivtIcon },
                  { id: 'test', label: 'Test events', Icon: Play },
                  { id: 'diag', label: 'Diagnostics', Icon: AlertTriangle },
                ] as const).map((t) => {
                  const Icon = t.Icon;
                  const isActive = sidePanelTab === t.id;
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
                <div className={cn('h-full', sidePanelTab === 'ai' ? 'block' : 'hidden')}>
                  <LogSourceAiPanel
                    parserId={source.id}
                    currentVrl={editedExt}
                    mode="extension"
                    baseParserVrl={source.parser_vrl}
                    onVrlUpdate={(info) => setEditedExt(info.newVrl)}
                  />
                </div>
                <div className={cn('h-full overflow-auto', sidePanelTab === 'test' ? 'block' : 'hidden')}>
                  <ParserTestLab
                    vrlCode={source.parser_vrl}
                    sourceType={effectiveSourceType(source)}
                    extensionVrl={editedExt}
                  />
                </div>
                <div className={cn('h-full overflow-auto', sidePanelTab === 'diag' ? 'block' : 'hidden')}>
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
