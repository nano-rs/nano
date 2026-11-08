// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { RotateCcw, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { DetailSheet } from '@/components/ui/detail-sheet';
import type { PipelineRelease } from '@/lib/pipeline-types';
import { formatUTC, formatUTCShort } from '@/lib/date-utils';
import { STEP_LABELS } from './pipeline-catalog';
import { PipelineLoading, PipelineNotice, PipelineStateBadge } from './PipelineCommon';
import type { PipelineReleaseHistoryProps, PipelineReleaseReviewProps } from './types';
import { cn } from '@/lib/utils';
import { Checkbox } from '@/components/ui/checkbox';

/**
 * The frozen release snapshot: the saved parser, extension and `updated_at`
 * exactly as they were when review started. Publish re-reads the source and
 * refuses if any of them moved.
 */
export function PipelineReleaseReview({ open, plan, canPublish, pending, stale, error, onOpenChange, onPublish }: PipelineReleaseReviewProps) {
  const [acknowledged, setAcknowledged] = useState<typeof plan>(null);
  const previewOnly = plan?.previewOnly ?? [];
  const needsAck = previewOnly.length > 0 && acknowledged !== plan;
  const snapshot = plan?.snapshot;
  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      size="xl"
      title="Review release"
      breadcrumb={['Pipelines', 'Release review']}
      description="Publishing makes this saved draft the active version and deploys it to Vector. Only the snapshot below is published."
      meta={
        plan && snapshot && (
          <>
            <span>edit {plan.revision}</span>
            <span>saved {snapshot.expectedUpdatedAt}</span>
            <span>active {plan.activeVersion === null ? 'none' : `v${plan.activeVersion}`}</span>
          </>
        )
      }
      footer={
        <>
          <Button variant="outline" disabled={pending} onClick={() => onOpenChange(false)}>Back to editor</Button>
          <Button
            disabled={!plan || !canPublish || !plan.validation.valid || !!stale || !!pending || needsAck}
            title={needsAck ? 'Acknowledge the preview-only steps first' : undefined}
            onClick={onPublish}
          >
            <Upload className="h-3.5 w-3.5" strokeWidth={1.5} />
            {pending ? 'Publishing…' : 'Publish release'}
          </Button>
        </>
      }
    >
      {error && <PipelineNotice title="Release was not published" tone="error">{error}</PipelineNotice>}
      {!canPublish && (
        <PipelineNotice title="Release permission required">You can inspect this release, but publishing requires log_sources:deploy.</PipelineNotice>
      )}
      {stale && (
        <PipelineNotice title="Release snapshot out of date" tone="warning">
          The saved draft changed after this review. Close it and review the latest saved draft again.
        </PipelineNotice>
      )}
      {!plan || !snapshot ? (
        <PipelineLoading label="Freezing the release snapshot…" />
      ) : (
        <div className="space-y-3">
          <PipelineNotice title={plan.validation.valid ? 'Validation passed' : 'Validation failed'} tone={plan.validation.valid ? 'neutral' : 'error'}>
            {plan.validation.errors.map((finding, index) => <p key={`error-${index}`}>{finding}</p>)}
            {plan.validation.warnings.map((finding, index) => <p key={`warning-${index}`}>{finding}</p>)}
          </PipelineNotice>
          {previewOnly.length > 0 && (
            <PipelineNotice title="Steps this deployment cannot publish" tone="warning">
              {previewOnly.map((entry) => (
                <p key={entry.kind}><span className="font-mono">{entry.kind}</span>: {entry.reason}</p>
              ))}
              <p>Publishing will be refused while these steps are enabled. Disable or remove them, or publish to see the server&apos;s answer.</p>
              <label className="mt-1 flex items-center gap-1.5 text-foreground">
                <Checkbox aria-label="Acknowledge preview-only steps" className="h-3.5 w-3.5" checked={acknowledged === plan} disabled={!!pending} onCheckedChange={(checked) => setAcknowledged(checked === true ? plan : null)} />
                I understand
              </label>
            </PipelineNotice>
          )}
          {plan.steps.length > 0 && (
            <div className="overflow-hidden rounded-md border border-border" data-testid="release-steps">
              <div className="border-b border-border px-3 py-1.5 font-mono text-[10.5px] text-muted-foreground">Steps · {plan.steps.length}</div>
              <table className="w-full text-left text-[11.5px]">
                <tbody>
                  {plan.steps.map((step, index) => (
                    <tr key={step.id} className={cn('h-6 border-b border-border last:border-0', !step.enabled && 'text-muted-foreground')}>
                      <td className="w-8 pl-3 font-mono text-[10.5px] text-muted-foreground">{index + 1}</td>
                      <td className="truncate px-2">{step.name}</td>
                      <td className="px-2 font-mono text-[10.5px] text-muted-foreground">{STEP_LABELS[step.kind]}</td>
                      <td className="pr-3 text-right font-mono text-[10.5px]">{step.enabled ? (step.condition?.trim() ? 'conditional' : 'on') : 'off'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <ConfigPane title={`Active${plan.activeVersion === null ? '' : ` · v${plan.activeVersion}`}`} code={plan.activeVrl} />
            <ConfigPane
              title="Publishing (saved parser_vrl)"
              code={[snapshot.parserVrl, ...(snapshot.extensionVrl && snapshot.extensionEnabled ? ['# Source extension (separate program)', snapshot.extensionVrl] : [])].join('\n\n')}
            />
          </div>
          <PipelineNotice title="Configuration changes affect future events only">
            Dropping, sampling and deduplicating can permanently omit events. Rollback restores configuration and does not reverse events already processed.
          </PipelineNotice>
        </div>
      )}
    </DetailSheet>
  );
}

function ConfigPane({ title, code }: { title: string; code: string }) {
  return (
    <div className="min-w-0 overflow-hidden rounded-md border border-border">
      <div className="border-b border-border px-3 py-1.5 font-mono text-[10.5px] text-muted-foreground">{title}</div>
      <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-[11px] leading-5">{code || '# Nothing published yet'}</pre>
    </div>
  );
}

export function PipelineReleaseHistory({
  open, pipelineName, releases, canRollback, pending, loadError, error, unsavedEdits = false, savedDraft = false, onOpenChange, onRollback,
}: PipelineReleaseHistoryProps) {
  const [rollback, setRollback] = useState<PipelineRelease | null>(null);
  // Freeze what the confirmation warned about; the hook refuses if it no longer matches.
  const [warnedUnsaved, setWarnedUnsaved] = useState(false);
  const replaced = [
    ...(unsavedEdits ? ['your unsaved edits in this editor'] : []),
    ...(savedDraft ? ['the saved draft that has not been published'] : []),
  ];
  return (
    <>
      <DetailSheet
        open={open}
        onOpenChange={onOpenChange}
        size="lg"
        title="Version history"
        breadcrumb={['Pipelines', pipelineName]}
        description="Published versions of this source's parser. Rollback makes the selected version active again, resets the draft to it, and deploys it."
        meta={<span>{releases.length} versions</span>}
        bodyClassName="p-0"
      >
        {(loadError || error) && (
          <div className="space-y-2 p-3">
            {loadError && <PipelineNotice title="Version history could not be loaded" tone="error">{loadError}</PipelineNotice>}
            {error && <PipelineNotice title="Rollback failed" tone="error">{error}</PipelineNotice>}
          </div>
        )}
        {releases.length === 0 ? (
          <p className="p-4 text-[11.5px] text-muted-foreground">No published versions yet.</p>
        ) : (
          <table className="w-full text-left text-[11.5px]">
            <thead className="font-mono text-[10px] uppercase text-muted-foreground">
              <tr className="h-7 border-b border-border">
                <th className="pl-4 font-medium">Version</th>
                <th className="px-2 font-medium">State</th>
                <th className="px-2 font-medium">Published / by</th>
                <th className="px-2 font-medium">Reason</th>
                <th className="pr-4"><span className="sr-only">Rollback</span></th>
              </tr>
            </thead>
            <tbody>
              {releases.map((release) => (
                <tr key={release.id} className="h-7 border-b border-border align-middle">
                  <td className="pl-4 font-mono">v{release.revision}</td>
                  <td className="px-2">{release.active ? <PipelineStateBadge state="live" /> : <span className="font-mono text-[10.5px] text-muted-foreground">previous</span>}</td>
                  <td className="px-2 font-mono text-[10.5px]">
                    <time dateTime={release.createdAt} title={formatUTC(release.createdAt)}>{formatUTCShort(release.createdAt)}</time>
                    {release.actor && <span className="ml-2 text-muted-foreground">{release.actor}</span>}
                  </td>
                  <td className="max-w-48 truncate px-2 text-[11px] text-muted-foreground" title={release.reason}>{release.reason ?? '—'}</td>
                  <td className="pr-4 text-right">
                    <Button
                      variant="ghost"
                      className="h-6 px-2 text-[11px]"
                      disabled={!canRollback || !!pending || release.active}
                      title={release.active ? 'This is the active version' : !canRollback ? 'Requires log_sources:deploy' : undefined}
                      onClick={() => { setWarnedUnsaved(unsavedEdits); setRollback(release); }}
                    >
                      <RotateCcw className="h-3 w-3" strokeWidth={1.5} />
                      Rollback
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DetailSheet>
      <ConfirmDialog
        open={open && !!rollback}
        onOpenChange={(next) => { if (!next) setRollback(null); }}
        title={`Roll back to version ${rollback?.revision ?? ''}?`}
        description="This records the selected version's parser and extension as a new active version, resets the draft to it, and deploys it to Vector. It does not restore events previously filtered, sampled or deduplicated."
        confirmLabel={replaced.length ? 'Replace and roll back' : 'Roll back'}
        variant="warning"
        loading={pending}
        onConfirm={() => {
          if (rollback && canRollback && !pending) {
            onRollback(rollback, { unsavedEdits: warnedUnsaved });
            setRollback(null);
          }
        }}
      >
        <PipelineNotice title="Draft work will be replaced" tone="warning">
          Rollback replaces {replaced.length ? replaced.join(' and ') : 'any unsaved edits and any saved-but-unpublished draft'} with version{' '}
          <span className="font-mono">{rollback?.revision ?? ''}</span>. Copy anything you want to keep before continuing.
        </PipelineNotice>
      </ConfirmDialog>
    </>
  );
}
