import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '../src/index.css';
import { PipelineEditor } from '@/components/pipelines/PipelineEditor';
import { PipelineList } from '@/components/pipelines/PipelineList';
import { PipelineReleaseHistory } from '@/components/pipelines/PipelineReleases';
import { usePipelineWorkspaceCore } from '@/hooks/use-pipeline-workspace-core';
import { summaryFromSource } from '@/lib/pipeline-model';
import { pipelinesTransport } from '../../nano-desktop/src/lib/ingestion';
import { pipelineFixture } from '../../nano-desktop/tests/pipelines-fixture';
const id = '00000000-0000-4000-8000-000000000001';
Object.assign(window, {
  __TAURI_INTERNALS__: {
    invoke: async (_: string, args: any) => {
      const result = pipelineFixture(args.path, args.method, args.body);
      if (!result) throw new Error(`Unhandled fixture ${args.path}`);
      return result;
    },
  },
});
document.documentElement.classList.toggle(
  'dark',
  new URLSearchParams(location.search).get('appearance') !== 'light',
);
function Fixture() {
  const [selected, setSelected] = useState(false);
  const [history, setHistory] = useState(false);
  const w = usePipelineWorkspaceCore(id, {
    api: pipelinesTransport,
    scope: 'web-fixture',
    hasPermission: () => true,
    toast: () => {},
  });
  if (!w.pipeline || !w.draft) return <p>Loading fixture…</p>;
  if (!selected)
    return (
      <PipelineList
        pipelines={[
          summaryFromSource(
            (
              pipelineFixture('/api/log-sources', 'GET', null)!.data as any[]
            )[0],
          ),
        ]}
        loading={false}
        canCreate
        onCreate={() => {}}
        onOpen={() => setSelected(true)}
        onRetry={() => {}}
      />
    );
  return (
    <>
      <div className="px-4 py-2 text-xs">
        Ingestion /{' '}
        <button onClick={() => setSelected(false)}>Pipelines</button> / Gateway
      </div>
      <div className="min-h-0 flex-1">
        <PipelineEditor
          pipeline={w.pipeline}
          draft={w.draft}
          capabilities={w.capabilities}
          permissions={w.permissions}
          dirty={w.dirty}
          samples={w.samples}
          sample={w.frozen}
          capture={w.capture}
          preview={w.preview}
          inputs={w.inputs}
          laneInputs={w.laneInputs}
          routedInputs={w.routedInputs}
          previewInput={w.previewInput}
          onPreviewInputChange={w.setPreviewInput}
          onDraftChange={w.changeDraft}
          onSave={() => void w.save()}
          onValidate={() => void w.validate()}
          onReview={() => void w.review()}
          onHistory={() => setHistory(true)}
          onCaptureStart={(o) => void w.startCapture(o)}
          onCaptureStop={() => void w.stopCapture()}
          onFreeze={() => void w.freeze()}
          onSampleSelect={w.selectSample}
          onPreview={() => void w.runPreview()}
          onPasteSample={w.pasteSample}
        />
      </div>
      <PipelineReleaseHistory
        open={history}
        pipelineName="Gateway"
        releases={w.releases}
        canRollback
        onOpenChange={setHistory}
        onRollback={() => {}}
      />
    </>
  );
}
createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={new QueryClient()}>
    <MemoryRouter>
      <main className="flex h-screen flex-col bg-background">
        <Fixture />
      </main>
    </MemoryRouter>
  </QueryClientProvider>,
);
