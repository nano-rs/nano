// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull → add an Azure Event Hubs source (NAN-3604). The tenant names its
 * Entra directory and app, the hub nano reads and the blob container that
 * holds the consumer checkpoints. Sign-in is the app's federated identity
 * credential: there is no field for a secret, connection string or SAS key.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import type { CreateAzurePullSourceRequest } from '@/lib/api/pull-sources';
import {
  AZURE_DEFAULT_CONSUMER_GROUP,
  EMPTY_AZURE_PULL_FORM,
  azureBlobUrl,
  azureNamespaceHost,
  validateAzurePullForm,
  type AzurePullField,
  type AzurePullForm,
} from '@/lib/cloud-pull';
import { Field, INPUT_CLS, LaneInput } from './CloudPullForm';

export function CloudPullAzureForm({ lanes, busy, serverError, onServerErrorClear, onSubmit, onCancel }: {
  /** Enrolled lane slugs; null when they could not be listed (free text instead). */
  lanes: string[] | null;
  busy: boolean;
  /** A refused create, mapped by `azureCreateError`: shown on its field when it names one. */
  serverError?: { field?: AzurePullField; message: string } | null;
  /** Called on the first edit after a refusal, so a stale message does not linger. */
  onServerErrorClear?: () => void;
  onSubmit: (request: CreateAzurePullSourceRequest) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState<AzurePullForm>(EMPTY_AZURE_PULL_FORM);
  const [submitted, setSubmitted] = useState(false);
  const { errors, request } = validateAzurePullForm(form);
  const shown: Partial<Record<AzurePullField, string>> = submitted ? { ...errors } : {};
  if (serverError?.field && !shown[serverError.field]) shown[serverError.field] = serverError.message;
  const set = (field: AzurePullField, value: string) => {
    if (serverError) onServerErrorClear?.();
    setForm((f) => ({ ...f, [field]: value }));
  };
  const id = (field: AzurePullField) => `cloud-pull-azure-${field}`;
  const errorProps = (field: AzurePullField) =>
    shown[field] ? { 'aria-invalid': true, 'aria-describedby': `${id(field)}-error` } : {};
  const input = (field: AzurePullField, placeholder: string, maxLength: number) => (
    <input id={id(field)} value={form[field]} maxLength={maxLength} disabled={busy} spellCheck={false} autoComplete="off"
      {...errorProps(field)} onChange={(e) => set(field, e.target.value)} placeholder={placeholder} className={INPUT_CLS} />
  );

  const host = azureNamespaceHost(form.namespace);
  const blobUrl = azureBlobUrl(form.checkpointAccount, form.checkpointContainer);

  return (
    <form
      className="rounded-md border border-border p-3 space-y-3"
      data-testid="cloud-pull-azure-form"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        setSubmitted(true);
        if (request && !busy) onSubmit(request);
      }}
    >
      <div className="grid grid-cols-12 gap-3">
        <Field id={id('name')} label="Name" error={shown.name} className="col-span-12 md:col-span-4">
          <input id={id('name')} value={form.name} maxLength={100} disabled={busy} {...errorProps('name')}
            onChange={(e) => set('name', e.target.value)} placeholder="entra sign-ins" className={INPUT_CLS} />
        </Field>
        <Field id={id('sourceSlug')} label="Lane" error={shown.sourceSlug} className="col-span-12 md:col-span-4"
          hint="The source the pulled events are parsed as.">
          <LaneInput id={id('sourceSlug')} lanes={lanes} value={form.sourceSlug} busy={busy}
            invalid={errorProps('sourceSlug')} placeholder="azure_signin" onChange={(v) => set('sourceSlug', v)} />
        </Field>
        <Field id={id('consumerGroup')} label="Consumer group (optional)" error={shown.consumerGroup} className="col-span-12 md:col-span-4"
          hint={<>Empty uses <span className="font-mono">{AZURE_DEFAULT_CONSUMER_GROUP}</span>. A group only nano reads is better.</>}>
          {input('consumerGroup', 'nano', 50)}
        </Field>

        <Field id={id('directoryId')} label="Directory (tenant) ID" error={shown.directoryId} className="col-span-12 md:col-span-4"
          hint="The Entra directory of the app registration.">
          {input('directoryId', '00000000-0000-0000-0000-000000000000', 36)}
        </Field>
        <Field id={id('clientId')} label="Application (client) ID" error={shown.clientId} className="col-span-12 md:col-span-4"
          hint="The app with the federated credential.">
          {input('clientId', '00000000-0000-0000-0000-000000000000', 36)}
        </Field>
        <Field id={id('subscriptionId')} label="Subscription ID" error={shown.subscriptionId} className="col-span-12 md:col-span-4"
          hint="The subscription of the Event Hubs namespace.">
          {input('subscriptionId', '00000000-0000-0000-0000-000000000000', 36)}
        </Field>

        <Field id={id('namespace')} label="Event Hubs namespace" error={shown.namespace} className="col-span-12 md:col-span-6"
          hint={<span className="font-mono" data-testid="cloud-pull-azure-host">{host ?? `<namespace>.servicebus.windows.net`}</span>}>
          {input('namespace', 'acme-logs', 80)}
        </Field>
        <Field id={id('eventHub')} label="Event hub" error={shown.eventHub} className="col-span-12 md:col-span-6">
          {input('eventHub', 'insights-logs-signinlogs', 256)}
        </Field>

        <Field id={id('checkpointAccount')} label="Checkpoint storage account" error={shown.checkpointAccount} className="col-span-12 md:col-span-6"
          hint={blobUrl
            ? <span className="font-mono" data-testid="cloud-pull-azure-blob">{blobUrl}</span>
            : 'Where nano keeps its read position. Yours, with Storage Blob Data Contributor for the app.'}>
          {input('checkpointAccount', 'acmenanocheckpoints', 24)}
        </Field>
        <Field id={id('checkpointContainer')} label="Checkpoint container" error={shown.checkpointContainer} className="col-span-12 md:col-span-6">
          {input('checkpointContainer', 'nano-checkpoints', 63)}
        </Field>
      </div>
      {serverError && !serverError.field && (
        <div className="text-[11px] text-red-500" role="alert" data-testid="cloud-pull-server-error">{serverError.message}</div>
      )}
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10.5px] text-muted-foreground" data-testid="cloud-pull-provider">provider azure_event_hubs</span>
        <span className="text-[10.5px] text-muted-foreground">· federated credential, no secret</span>
        <span className="flex-1" />
        <Button type="button" variant="outline" size="sm" className="h-7 text-[11.5px]" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button type="submit" size="sm" className="h-7 text-[11.5px]" disabled={busy}>{busy ? 'Adding…' : 'Add source'}</Button>
      </div>
    </form>
  );
}
