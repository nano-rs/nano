// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { RotateCcw, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { DetailSheet } from '@/components/ui/detail-sheet';
import type { PipelineRelease, PipelineReleasePlan } from '@/lib/pipeline-types';
import { formatUTC, formatUTCShort } from '@/lib/date-utils';
import {
  PipelineLoading,
  PipelineNotice,
  PipelineStateBadge,
} from './PipelineCommon';
import type {
  PipelineReleaseHistoryProps,
  PipelineReleaseReviewProps,
} from './types';
import { Checkbox } from '@/components/ui/checkbox';

export function PipelineReleaseReview({
  open,
  plan,
  canPublish,
  pending,
  stale,
  error,
  onOpenChange,
  onPublish,
}: PipelineReleaseReviewProps) {
  // Opt-in per plan: a new review always starts unchecked.
  const [persistChoice, setPersistChoice] = useState<{
    plan: PipelineReleasePlan;
    persist: boolean;
  } | null>(null);
  const persistCapturedSamples =
    !!plan && persistChoice?.plan === plan && persistChoice.persist;
  const capturedSampleCount = plan?.capturedSampleCount ?? 0;
  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      size="xl"
      title="Review pipeline release"
      breadcrumb={['Pipelines', 'Release review']}
      description="Publish the reviewed configuration to the tenant runtime. A queued release becomes live only after the runtime reports success."
      meta={
        plan && (
          <>
            <span>Proposed edit {plan.revision}</span>
            <span className="truncate">Plan {plan.fingerprint}</span>
          </>
        )
      }
      footer={
        <>
          <Button
            variant="outline"
            disabled={pending}
            onClick={() => onOpenChange(false)}
          >
            Back to editor
          </Button>
          <Button
            disabled={
              !plan ||
              !canPublish ||
              !plan.validation.valid ||
              !!stale ||
              !!pending
            }
            onClick={() => onPublish({ persistCapturedSamples })}
          >
            <Upload className="h-3.5 w-3.5" strokeWidth={1.5} />
            {pending ? 'Publishing…' : 'Publish release'}
          </Button>
        </>
      }
    >
      {error && (
        <PipelineNotice title="Release could not be published" tone="error">
          {error}
        </PipelineNotice>
      )}
      {!canPublish && (
        <PipelineNotice title="Release permission required">
          You can inspect this plan, but your role cannot publish it.
        </PipelineNotice>
      )}
      {stale && (
        <PipelineNotice title="Release plan out of date" tone="warning">
          Close this review and validate the current saved draft to generate a
          new plan.
        </PipelineNotice>
      )}
      {!plan ? (
        <PipelineLoading label="Preparing the exact release plan…" />
      ) : (
        <div className="space-y-3">
          <PipelineNotice
            title={
              plan.validation.valid ? 'Validation passed' : 'Validation failed'
            }
            tone={plan.validation.valid ? 'neutral' : 'error'}
          >
            {plan.validation.errors.map((finding, index) => (
              <p key={`error-${index}`}>{finding}</p>
            ))}
            {plan.validation.warnings.map((finding, index) => (
              <p key={`warning-${index}`}>{finding}</p>
            ))}
          </PipelineNotice>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <ConfigPane title="Active processing" code={plan.activeVrl} />
            <ConfigPane
              title={`Proposed processing · edit ${plan.revision}`}
              code={plan.compiledVrl}
            />
          </div>
          {capturedSampleCount > 0 && (
            <label className="flex items-start gap-2 rounded-md border border-border px-3 py-2 text-[12px]">
              <Checkbox
                className="mt-0.5 h-3.5 w-3.5"
                checked={persistCapturedSamples}
                disabled={!canPublish || !!pending}
                onCheckedChange={(checked) =>
                  setPersistChoice({ plan, persist: checked === true })
                }
              />
              <span>
                Save the{' '}
                <span className="font-mono">{capturedSampleCount}</span>{' '}
                captured events as this version&apos;s test samples
                <span className="block text-[11px] text-muted-foreground">
                  Stored with the pipeline and kept after the 10-minute capture
                  purge; they may contain sensitive data. Unchecked, this
                  version keeps the source&apos;s saved samples.
                </span>
              </span>
            </label>
          )}
          <PipelineNotice title="Configuration changes take effect on future processing">
            Dropping and sampling can permanently omit events from Nano Lake.
            Rollback restores configuration and does not reverse events already
            processed.
          </PipelineNotice>
        </div>
      )}
    </DetailSheet>
  );
}

function ConfigPane({ title, code }: { title: string; code: string }) {
  return (
    <div className="min-w-0 overflow-hidden rounded-md border border-border">
      <div className="border-b border-border bg-panel px-3 py-1.5 font-mono text-[10.5px] text-muted-foreground">
        {title}
      </div>
      <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-[11px] leading-5">
        {code || '# No processing steps'}
      </pre>
    </div>
  );
}

export function PipelineReleaseHistory({
  open,
  pipelineName,
  releases,
  canRollback,
  pending,
  loadError,
  error,
  unsavedEdits = false,
  savedDraft = false,
  onOpenChange,
  onRollback,
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
        title="Release history"
        breadcrumb={['Pipelines', pipelineName]}
        description="Observed runtime releases and audited rollback requests."
        meta={<span>{releases.length} releases</span>}
        bodyClassName="p-0"
      >
        {(loadError || error) && (
          <div className="space-y-2 p-3">
            {loadError && (
              <PipelineNotice
                title="Release history could not be loaded"
                tone="error"
              >
                {loadError}
              </PipelineNotice>
            )}
            {error && (
              <PipelineNotice title="Rollback was not requested" tone="error">
                {error}
              </PipelineNotice>
            )}
          </div>
        )}
        {releases.length === 0 ? (
          <p className="p-4 text-[11.5px] text-muted-foreground">
            No runtime release history is available for this pipeline.
          </p>
        ) : (
          <table className="w-full text-left text-[11.5px]">
            <thead className="font-mono text-[10px] uppercase text-muted-foreground">
              <tr className="h-7 border-b border-border">
                <th className="pl-4 font-medium">Revision</th>
                <th className="px-2 font-medium">State</th>
                <th className="px-2 font-medium">Timestamp / actor</th>
                <th className="pr-4">
                  <span className="sr-only">Rollback</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {releases.map((release) => (
                <tr
                  key={release.id}
                  className="border-b border-border align-top"
                >
                  <td className="py-3 pl-4 font-mono">
                    {release.revision === null ? '—' : `v${release.revision}`}
                    <div
                      className="mt-1 max-w-36 truncate text-[10px] text-muted-foreground"
                      title={release.id}
                    >
                      {release.id}
                    </div>
                  </td>
                  <td className="px-2 py-3">
                    <PipelineStateBadge state={release.state} />
                    {release.error && (
                      <p className="mt-1 max-w-56 whitespace-pre-wrap text-[10.5px] text-destructive">
                        {release.error}
                      </p>
                    )}
                  </td>
                  <td className="px-2 py-3 font-mono text-[10.5px]">
                    <time
                      dateTime={release.createdAt}
                      title={formatUTC(release.createdAt)}
                    >
                      {formatUTCShort(release.createdAt)}
                    </time>
                    {release.actor && (
                      <div className="mt-1 text-muted-foreground">
                        {release.actor}
                      </div>
                    )}
                  </td>
                  <td className="py-3 pr-4 text-right">
                    <Button
                      variant="ghost"
                      className="h-6 px-2 text-[11px]"
                      disabled={
                        !canRollback ||
                        !!pending ||
                        release.versionId === undefined
                      }
                      title={
                        release.versionId === undefined
                          ? 'No restorable version was recorded for this release'
                          : !canRollback
                            ? 'Requires release permission'
                            : undefined
                      }
                      onClick={() => {
                        setWarnedUnsaved(unsavedEdits);
                        setRollback(release);
                      }}
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
        onOpenChange={(next) => {
          if (!next) setRollback(null);
        }}
        title={`Restore version ${rollback?.revision ?? 'unknown'}?`}
        description="This requests a new audited deployment of the selected configuration. It does not restore events previously filtered or sampled out."
        confirmLabel={
          replaced.length ? 'Replace and roll back' : 'Request rollback'
        }
        variant="warning"
        loading={pending}
        onConfirm={() => {
          if (rollback && canRollback && !pending) {
            onRollback(rollback, { unsavedEdits: warnedUnsaved });
            setRollback(null);
          }
        }}
      >
        {replaced.length > 0 && (
          <PipelineNotice title="Draft changes will be replaced" tone="warning">
            Rollback replaces {replaced.join(' and ')} with version{' '}
            <span className="font-mono">{rollback?.revision ?? 'unknown'}</span>
            . Copy anything you want to keep before continuing.
          </PipelineNotice>
        )}
      </ConfirmDialog>
    </>
  );
}
