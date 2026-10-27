// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useSharedTenant } from '@/hooks/use-shared-tenant';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { usePipelineWorkspace } from '@/hooks/use-pipeline-workspace';
import { releaseFromRollout, summaryFromSource } from '@/lib/pipeline-model';
import { parserServingState } from '@/lib/parser-rollout';
import { PipelineList } from '@/components/pipelines/PipelineList';
import { PipelineEditor } from '@/components/pipelines/PipelineEditor';
import { PipelineReleaseReview, PipelineReleaseHistory } from '@/components/pipelines/PipelineReleases';
import { usePipePivt } from '@/components/pipelines/usePipePivt';
import { usePipeInputSummary } from '@/hooks/use-pipe-inputs';
import { Button } from '@/components/ui/button';

export function Pipelines() {
  useDocumentTitle('Pipelines');
  const shared = useSharedTenant();
  const { id } = useParams();
  if (!shared) return <div className="flex flex-col gap-3 py-4 text-[12px]" role="status"><h1 className="text-[18px] font-semibold">Pipelines</h1><p className="text-muted-foreground">This workspace manages Nano shared-lake pipelines. Manage this deployment through Log Sources.</p><Button variant="outline" className="w-fit" asChild><Link to="/ingestion/log-sources">Open Log Sources</Link></Button></div>;
  return id ? <PipelineWorkspace key={id} sourceId={id} /> : <PipelineInventory />;
}

function PipelineInventory() {
  const navigate = useNavigate();
  const { hasPermission, tenantRuntime } = useAuth();
  const sources = useQuery({ queryKey: ['pipe-sources', tenantRuntime.key], queryFn: () => api.listLogSources() });
  const inputSummary = usePipeInputSummary({ enabled: hasPermission('log_sources:view') });
  const inputCounts = useMemo(() => Object.fromEntries((inputSummary.data?.sources ?? []).map((counts) => [counts.log_source_id, counts])), [inputSummary.data]);
  const rollouts = useQuery({ queryKey: ['pipe-all-rollouts', tenantRuntime.key], queryFn: () => api.listParserRollouts({ limit: 100 }), refetchInterval: (query) => query.state.data?.some((rollout) => !rollout.terminal) ? 3000 : false });
  const pipelines = (sources.data ?? []).map((source) => {
    const ownRollouts = (rollouts.data ?? []).filter((release) => release.log_source_id === source.id);
    const tenantLive = rollouts.data?.find((release) => release.state === 'live');
    const serving = parserServingState(ownRollouts, tenantLive, undefined);
    return { ...summaryFromSource(source, ownRollouts.map(releaseFromRollout)), activeRevision: serving.tracked ? serving.servingVersion : null };
  });
  return <PipelineList pipelines={pipelines} loading={sources.isLoading} error={sources.error?.message ?? rollouts.error?.message} canCreate={hasPermission('log_sources:create')} onCreate={() => navigate('/ingestion/log-sources/wizard')} onOpen={(id) => navigate(`/ingestion/pipelines/${encodeURIComponent(id)}`)} onRetry={() => { void sources.refetch(); void rollouts.refetch(); void inputSummary.refetch(); }} inputCounts={inputSummary.isSuccess ? inputCounts : undefined} />;
}

function PipelineWorkspace({ sourceId }: { sourceId: string }) {
  const workspace = usePipelineWorkspace(sourceId);
  useBreadcrumbTitle(workspace.pipeline?.name);
  const pivt = usePipePivt(sourceId, workspace);
  const [historyOpen, setHistoryOpen] = useState(false);
  useEffect(() => {
    if (!workspace.dirty) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [workspace.dirty]);
  // In-app route changes retain drafts in tenant/user-scoped memory. Only a
  // document unload needs a warning; it would discard that transient cache.
  if (workspace.loading) return <div className="py-8 text-[12px] text-muted-foreground" role="status">Loading pipeline…</div>;
  if (!workspace.pipeline || !workspace.draft) return <div className="flex flex-col gap-3 text-[12px]" role="alert"><p>{workspace.loadError ?? 'This pipeline could not be found.'}</p><Button variant="outline" className="w-fit" onClick={workspace.retry}>Retry</Button></div>;
  return <>
    <PipelineEditor pipeline={workspace.pipeline} draft={workspace.draft} capabilities={{ ...workspace.capabilities, ai: pivt.available, aiReason: pivt.reason ?? undefined }} permissions={workspace.permissions} dirty={workspace.dirty} busy={workspace.busy} errors={workspace.errors} conflict={workspace.conflict} capabilitiesError={workspace.capabilitiesError} previewError={workspace.previewError} validation={workspace.validation} capture={workspace.capture} samples={workspace.samples} sample={workspace.frozen} preview={workspace.preview} previewPending={workspace.previewPending} canSaveSample={workspace.canSaveCaptureSample}
      onDraftChange={workspace.changeDraft} onSave={() => { void workspace.save(); }} onValidate={() => { void workspace.validate(); }} onReview={() => { void workspace.review(); }} onHistory={() => setHistoryOpen(true)} onCaptureStart={(options) => { void workspace.startCapture(options); }} onCaptureStop={() => { void workspace.stopCapture(); }} onFreeze={() => { void workspace.freeze(); }} onSampleSelect={workspace.selectSample} onPreview={() => { void workspace.runPreview(); }} onSaveSample={() => { void workspace.saveSample(); }} onLoadRecent={(limit) => { void workspace.loadRecentEvents(limit); }} onPasteSample={workspace.pasteSample} sampleNotice={workspace.sampleNotice}
      laneInputs={workspace.laneInputs} routedInputs={workspace.routedInputs} previewInput={workspace.previewInput} onPreviewInputChange={workspace.setPreviewInput}
      onReloadLatest={() => { void workspace.reloadLatest(); }} onKeepLocalEdits={() => { void workspace.keepLocalEdits(); }} onDiscardDraft={() => { void workspace.discardDraft(); }} onRetryCapabilities={workspace.retryCapabilities} onAssistant={pivt.available ? pivt.open : undefined} onSelectedStepChange={pivt.onSelectedStepChange}
      inputs={workspace.inputs} />
    <PipelineReleaseReview open={!!workspace.plan} plan={workspace.plan} canPublish={workspace.permissions.release} stale={workspace.planStale} pending={workspace.busy === 'publish'} error={workspace.errors.publish} onOpenChange={(open) => { if (!open) workspace.closeReview(); }} onPublish={(options) => { void workspace.publish(options); }} />
    <PipelineReleaseHistory open={historyOpen} pipelineName={workspace.pipeline.name} releases={workspace.releases} canRollback={workspace.permissions.release} pending={workspace.busy === 'rollback'} loadError={workspace.historyError} error={workspace.errors.rollback} unsavedEdits={workspace.dirty} savedDraft={workspace.pipeline.hasDraft} onOpenChange={setHistoryOpen} onRollback={(release, confirmed) => { if (release.versionId !== undefined) void workspace.rollback(release.versionId, confirmed); }} />

  </>;
}
