// SPDX-License-Identifier: AGPL-3.0-or-later

// Nano Pipe (NAN-4919): every log source's parser as ordered steps. Available
// on every deployment and both editions; pivt `@pipe` is the only enterprise
// piece and degrades to a disabled button with its reason in open builds.

import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { usePipelineWorkspace } from '@/hooks/use-pipeline-workspace';
import { summaryFromSource } from '@/lib/pipeline-model';
import { PipelineList } from '@/components/pipelines/PipelineList';
import { PipelineEditor } from '@/components/pipelines/PipelineEditor';
import { PipelineReleaseReview, PipelineReleaseHistory } from '@/components/pipelines/PipelineReleases';
import { usePipePivt } from '@/components/pipelines/usePipePivt';
import { Button } from '@/components/ui/button';

export function Pipelines() {
  useDocumentTitle('Pipelines');
  const { id } = useParams();
  return id ? <PipelineWorkspace key={id} sourceId={id} /> : <PipelineInventory />;
}

function PipelineInventory() {
  const navigate = useNavigate();
  const { hasPermission, user } = useAuth();
  const sources = useQuery({ queryKey: ['pipe-sources', user?.id ?? 'anonymous'], queryFn: () => api.listLogSources() });
  const pipelines = (sources.data ?? []).map((source) => summaryFromSource(source));
  return (
    <div className="h-full min-h-[480px]">
      <PipelineList
        pipelines={pipelines}
        loading={sources.isLoading}
        error={sources.error?.message}
        canCreate={hasPermission('log_sources:create')}
        onCreate={() => navigate('/ingestion/log-sources/wizard')}
        onOpen={(id) => navigate(`/ingestion/pipelines/${encodeURIComponent(id)}`)}
        onRetry={() => { void sources.refetch(); }}
      />
    </div>
  );
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
  // In-app route changes keep drafts in the in-memory query cache; only a
  // document unload needs a warning.
  if (workspace.loading) return <div className="py-8 text-[12px] text-muted-foreground" role="status">Loading pipeline…</div>;
  if (!workspace.pipeline || !workspace.draft) {
    return (
      <div className="flex flex-col gap-3 text-[12px]" role="alert">
        <p>{workspace.loadError ?? 'This pipeline could not be found.'}</p>
        <Button variant="outline" className="w-fit" onClick={workspace.retry}>Retry</Button>
      </div>
    );
  }
  return (
    <div className="h-[calc(100vh-7rem)] min-h-[560px]">
      <PipelineEditor
        pipeline={workspace.pipeline}
        draft={workspace.draft}
        capabilities={{ ...workspace.capabilities, ai: pivt.available, aiReason: pivt.reason ?? undefined }}
        permissions={workspace.permissions}
        dirty={workspace.dirty}
        imported={workspace.imported}
        busy={workspace.busy}
        errors={workspace.errors}
        conflict={workspace.conflict}
        capabilitiesError={workspace.capabilitiesError}
        previewError={workspace.previewError}
        validation={workspace.validation}
        tap={workspace.tap}
        sample={workspace.sample}
        preview={workspace.preview}
        previewPending={workspace.previewPending}
        sampleNotice={workspace.sampleNotice}
        laneInputs={workspace.laneInputs}
        routedInputs={workspace.routedInputs}
        previewInput={workspace.previewInput}
        onPreviewInputChange={workspace.setPreviewInput}
        onDraftChange={workspace.changeDraft}
        onSave={() => { void workspace.save(); }}
        onValidate={() => { void workspace.validate(); }}
        onReview={() => { void workspace.review(); }}
        onHistory={() => setHistoryOpen(true)}
        onTapStart={(options) => { void workspace.startTap(options); }}
        onTapCancel={workspace.cancelTap}
        onTapPreview={workspace.previewTapEvents}
        onPreview={() => { void workspace.runPreview(); }}
        onLoadRecent={(limit) => { void workspace.loadRecentEvents(limit); }}
        onPasteSample={workspace.pasteSample}
        onReloadLatest={() => { void workspace.reloadLatest(); }}
        onKeepLocalEdits={() => { void workspace.keepLocalEdits(); }}
        onDiscardDraft={() => { void workspace.discardDraft(); }}
        onRetryCapabilities={workspace.retryCapabilities}
        onAssistant={pivt.available ? pivt.open : undefined}
        onSelectedStepChange={pivt.onSelectedStepChange}
      />
      <PipelineReleaseReview
        open={!!workspace.plan}
        plan={workspace.plan}
        canPublish={workspace.permissions.release}
        stale={workspace.planStale}
        pending={workspace.busy === 'publish'}
        error={workspace.errors.publish}
        onOpenChange={(open) => { if (!open) workspace.closeReview(); }}
        onPublish={() => { void workspace.publish(); }}
      />
      <PipelineReleaseHistory
        open={historyOpen}
        pipelineName={workspace.pipeline.name}
        releases={workspace.releases}
        canRollback={workspace.permissions.release}
        pending={workspace.busy === 'rollback'}
        loadError={workspace.historyError}
        error={workspace.errors.rollback}
        unsavedEdits={workspace.dirty}
        savedDraft={workspace.pipeline.hasDraft}
        onOpenChange={setHistoryOpen}
        onRollback={(release, confirmed) => { void workspace.rollback(release.versionId, confirmed); }}
      />
    </div>
  );
}
