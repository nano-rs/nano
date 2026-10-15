// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull → add a GCP Pub/Sub source (NAN-3598). The tenant names the
 * subscription; nano reads it as the tenant's service account once the
 * subscriber role is bound on that subscription. No key is asked for or sent.
 */

import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import type { CreateGcpPullSourceRequest } from '@/lib/api/pull-sources';
import {
  EMPTY_GCP_PULL_FORM,
  GCP_ACK_DEADLINE,
  GCP_DEFAULT_SOURCE_SLUG,
  defaultGcpSourceSlug,
  GCP_SUBSCRIPTION_FORMAT,
  validateGcpPullForm,
  type GcpPullField,
  type GcpPullForm,
} from '@/lib/cloud-pull';
import { Field, INPUT_CLS, LaneInput } from './CloudPullForm';

export function CloudPullGcpForm({ lanes, busy, serverError, initialSubscription = '', ackBounds = GCP_ACK_DEADLINE,
  defaultSourceSlug = GCP_DEFAULT_SOURCE_SLUG, onSubmit, onCancel }: {
  /** Enrolled lane slugs; null when they could not be listed (free text instead). */
  lanes: string[] | null;
  /**
   * NAN-3658: the lane preselected when it is deployed (the setup's
   * `default_source_slug`, `gcp_audit`). Not deployed: nothing is
   * preselected and the operator picks the parser explicitly.
   */
  defaultSourceSlug?: string;
  busy: boolean;
  serverError?: string | null;
  /** Prefilled from the setup panel's subscription field. */
  initialSubscription?: string;
  /** From the setup response; defaults to the server's 10-600 s. */
  ackBounds?: { min: number; max: number };
  onSubmit: (request: CreateGcpPullSourceRequest) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState<GcpPullForm>(() => ({
    ...EMPTY_GCP_PULL_FORM, subscription: initialSubscription, sourceSlug: defaultGcpSourceSlug(lanes, defaultSourceSlug),
  }));
  const [slugTouched, setSlugTouched] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  // The lanes may arrive after the form opens: preselect the default then, unless the operator chose already.
  const preselect = defaultGcpSourceSlug(lanes, defaultSourceSlug);
  useEffect(() => {
    if (!slugTouched && preselect) setForm((f) => (f.sourceSlug ? f : { ...f, sourceSlug: preselect }));
  }, [preselect, slugTouched]);
  const noDefault = lanes !== null && !preselect;
  const { errors, request } = validateGcpPullForm(form, ackBounds);
  const shown = submitted ? errors : {};
  const set = (field: GcpPullField, value: string) => setForm((f) => ({ ...f, [field]: value }));
  const id = (field: GcpPullField) => `cloud-pull-gcp-${field}`;
  const errorProps = (field: GcpPullField) =>
    shown[field] ? { 'aria-invalid': true, 'aria-describedby': `${id(field)}-error` } : {};

  return (
    <form
      className="rounded-md border border-border p-3 space-y-3"
      data-testid="cloud-pull-gcp-form"
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
            onChange={(e) => set('name', e.target.value)} placeholder="prod audit logs" className={INPUT_CLS} />
        </Field>
        <Field id={id('sourceSlug')} label="Lane" error={shown.sourceSlug} className="col-span-12 md:col-span-4"
          hint={noDefault
            ? <span data-testid="cloud-pull-gcp-no-default">No <span className="font-mono">{defaultSourceSlug}</span> parser is deployed on this tenant. Choose the parser the events are in.</span>
            : 'The source the pulled events are parsed as.'}>
          <LaneInput id={id('sourceSlug')} lanes={lanes} value={form.sourceSlug} busy={busy}
            invalid={errorProps('sourceSlug')} placeholder={defaultSourceSlug}
            onChange={(v) => { setSlugTouched(true); set('sourceSlug', v); }} />
        </Field>
        <Field id={id('ackDeadline')} label="Ack deadline (optional)" error={shown.ackDeadline} className="col-span-12 md:col-span-4"
          hint={`Seconds, ${ackBounds.min}-${ackBounds.max}. Empty uses the default.`}>
          <input id={id('ackDeadline')} value={form.ackDeadline} inputMode="numeric" disabled={busy} {...errorProps('ackDeadline')}
            onChange={(e) => set('ackDeadline', e.target.value)} placeholder="60" className={INPUT_CLS} />
        </Field>
        <Field id={id('subscription')} label="Subscription" error={shown.subscription} className="col-span-12"
          hint={<>The full resource name, <span className="font-mono">{GCP_SUBSCRIPTION_FORMAT}</span>.</>}>
          <input id={id('subscription')} value={form.subscription} maxLength={512} disabled={busy} spellCheck={false}
            {...errorProps('subscription')} onChange={(e) => set('subscription', e.target.value)}
            placeholder="projects/acme-logging/subscriptions/nano-audit" className={INPUT_CLS} />
        </Field>
      </div>
      {serverError && <div className="text-[11px] text-red-500" role="alert" data-testid="cloud-pull-server-error">{serverError}</div>}
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10.5px] text-muted-foreground" data-testid="cloud-pull-provider">provider gcp_pubsub</span>
        <span className="flex-1" />
        <Button type="button" variant="outline" size="sm" className="h-7 text-[11.5px]" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button type="submit" size="sm" className="h-7 text-[11.5px]" disabled={busy}>{busy ? 'Adding…' : 'Add source'}</Button>
      </div>
    </form>
  );
}
