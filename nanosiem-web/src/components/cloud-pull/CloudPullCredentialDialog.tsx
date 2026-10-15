// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull → rotate a source's credential in place (NAN-3729): the AWS role
 * nano assumes, or the Entra app (and directory) it federates into. The
 * source keeps its id, its queue / hub / consumer group / checkpoint and its
 * parser lane, so nothing is skipped or re-read. Saving sends it back through
 * verification: verifying → deploying → active, the same path as a new
 * source; while it re-verifies nano pulls nothing from it and events wait in
 * the customer's queue or hub. There is no field for a key or secret.
 */

import { useEffect, useState } from 'react';
import { KeyRound } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import type { PullSource, UpdatePullSourceRequest } from '@/lib/api/pull-sources';
import {
  PULL_REVERIFY_STEPS,
  STATE_LABEL,
  pullCredentialFormOf,
  pullTarget,
  validatePullCredentialForm,
  type PullCredentialField,
  type PullCredentialForm,
} from '@/lib/cloud-pull';
import { cn } from '@/lib/utils';
import { Field, INPUT_CLS } from './CloudPullForm';

export function CloudPullCredentialDialog({ source, busy, serverError, onSubmit, onOpenChange }: {
  /** The row being edited; null closes the dialog. */
  source: PullSource | null;
  busy: boolean;
  /** A refused edit (the API's message, never a submitted value). */
  serverError?: string | null;
  onSubmit: (source: PullSource, body: UpdatePullSourceRequest) => void;
  onOpenChange: (open: boolean) => void;
}) {
  const [form, setForm] = useState<PullCredentialForm>({ roleArn: '', directoryId: '', clientId: '' });
  const [submitted, setSubmitted] = useState(false);
  useEffect(() => {
    if (source) setForm(pullCredentialFormOf(source));
    setSubmitted(false);
  }, [source]);
  if (!source) return null;

  const { errors, request, changed } = validatePullCredentialForm(source, form);
  const shown: Partial<Record<PullCredentialField, string>> = submitted ? errors : {};
  const id = (field: PullCredentialField) => `cloud-pull-credential-${field}`;
  const input = (field: PullCredentialField, placeholder: string, maxLength: number) => (
    <input id={id(field)} value={form[field]} maxLength={maxLength} disabled={busy} spellCheck={false} autoComplete="off"
      {...(shown[field] ? { 'aria-invalid': true, 'aria-describedby': `${id(field)}-error` } : {})}
      onChange={(e) => setForm((f) => ({ ...f, [field]: e.target.value }))} placeholder={placeholder} className={INPUT_CLS} />
  );
  const paused = source.state === 'paused';
  const what = source.aws ? 'role' : 'app';

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[85vh] flex-col gap-0 border-border bg-card p-0 text-foreground sm:max-w-[520px]"
        data-testid="cloud-pull-credential-dialog">
        <DialogHeader className="space-y-0.5 border-b border-border px-4 py-3 pr-10 text-left">
          <DialogTitle className="flex items-center gap-2 text-[13px] leading-5">
            <KeyRound className="h-[13px] w-[13px] shrink-0 text-primary" strokeWidth={1.5} />
            Rotate credential
          </DialogTitle>
          <DialogDescription className="truncate text-[11px]">
            <span className="text-foreground">{source.name}</span>
            {' · '}
            <span className="font-mono">{pullTarget(source)}</span>
          </DialogDescription>
        </DialogHeader>
        <form
          noValidate
          className="flex flex-col gap-3 px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
            setSubmitted(true);
            if (request && !busy) onSubmit(source, request);
          }}
        >
          {source.aws && (
            <Field id={id('roleArn')} label="Role ARN" error={shown.roleArn}
              hint={<>Same account as the queue (<span className="font-mono">{source.aws.account_id}</span>), with nano's trust policy and ExternalId.</>}>
              {input('roleArn', `arn:aws:iam::${source.aws.account_id}:role/nano-pull`, 2048)}
            </Field>
          )}
          {source.azure && (
            <div className="grid grid-cols-2 gap-3">
              <Field id={id('directoryId')} label="Directory (tenant) ID" error={shown.directoryId}>
                {input('directoryId', '00000000-0000-0000-0000-000000000000', 36)}
              </Field>
              <Field id={id('clientId')} label="App (client) ID" error={shown.clientId}
                hint="Needs nano's federated credential and both role assignments.">
                {input('clientId', '00000000-0000-0000-0000-000000000000', 36)}
              </Field>
            </div>
          )}

          <div className="rounded-md border border-border px-3 py-2 text-[11.5px] text-muted-foreground space-y-1.5" data-testid="cloud-pull-reverify-note">
            <div className="text-foreground">
              {paused
                ? 'Saving keeps this source paused. It re-verifies with the new credential when you resume it.'
                : `Saving re-verifies this source with the new ${what} before it pulls again.`}
            </div>
            {!paused && (
              <ol className="flex items-center gap-1 font-mono text-[10.5px]" aria-label="Re-verification steps" data-testid="cloud-pull-reverify-steps">
                <li className="text-foreground">{STATE_LABEL[source.state] ?? source.state}</li>
                {PULL_REVERIFY_STEPS.map((step) => (
                  <li key={step} className={cn('flex items-center gap-1', step === 'active' && 'text-emerald-500')}>
                    <span aria-hidden>→</span>{STATE_LABEL[step]}
                  </li>
                ))}
              </ol>
            )}
            <div>
              While it re-verifies nano pulls nothing from it; events wait in your {source.aws ? 'queue' : 'event hub'} and none
              are skipped. Keep the old {what} working until the row shows <span className="font-mono">active</span>, then remove it.
            </div>
          </div>

          {serverError && <div className="text-[11px] text-red-500" role="alert" data-testid="cloud-pull-credential-error">{serverError}</div>}

          <div className="flex items-center justify-end gap-2 border-t border-border -mx-4 px-4 pt-2.5">
            <Button type="button" variant="ghost" size="sm" className="h-7 text-[11.5px]" disabled={busy} onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" size="sm" className="h-7 text-[11.5px]" disabled={busy || !changed}>
              {busy ? 'Saving…' : 'Save and re-verify'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
