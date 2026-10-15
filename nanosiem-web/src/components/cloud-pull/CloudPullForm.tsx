// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull → add an AWS source (NAN-3596). The tenant names the role nano
 * assumes and the queue it reads; nano supplies the ExternalId. There is no
 * field for an ExternalId, endpoint or key, and none is ever sent.
 */

import { useState, type ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { CreateAwsPullSourceRequest } from '@/lib/api/pull-sources';
import {
  AWS_COMMERCIAL_REGIONS,
  EMPTY_AWS_PULL_FORM,
  parseQueueArn,
  validateAwsPullForm,
  type AwsPullField,
  type AwsPullForm,
} from '@/lib/cloud-pull';

export const INPUT_CLS =
  'h-8 w-full rounded-md border border-input bg-background px-2.5 font-mono text-[12px] text-foreground focus:border-primary focus:outline-none disabled:opacity-50';

export function Field({ id, label, hint, error, className, children }: {
  id: string; label: string; hint?: ReactNode; error?: string; className?: string; children: ReactNode;
}) {
  return (
    <div className={className}>
      <label className="block text-[10.5px] font-medium text-foreground/80 mb-1.5" htmlFor={id}>{label}</label>
      {children}
      {error ? (
        <div className="mt-1 text-[10.5px] text-red-500" id={`${id}-error`} role="alert">{error}</div>
      ) : hint ? (
        <div className="mt-1 text-[10.5px] text-muted-foreground">{hint}</div>
      ) : null}
    </div>
  );
}

/** The lane picker: enrolled slugs as a select, or free text when they could not be listed. */
export function LaneInput({ id, lanes, value, busy, invalid, placeholder, onChange }: {
  id: string;
  lanes: string[] | null;
  value: string;
  busy: boolean;
  invalid: Record<string, unknown>;
  placeholder: string;
  onChange: (value: string) => void;
}) {
  return lanes && lanes.length > 0 ? (
    <Select value={value} onValueChange={onChange} disabled={busy}>
      <SelectTrigger id={id} className="h-8 font-mono" {...invalid}>
        <SelectValue placeholder="Select a lane" />
      </SelectTrigger>
      <SelectContent>
        {lanes.map((slug) => (
          <SelectItem key={slug} value={slug} className="font-mono text-[12px]">{slug}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  ) : (
    <input id={id} value={value} maxLength={100} disabled={busy} {...invalid}
      onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={INPUT_CLS} />
  );
}

export function CloudPullForm({ lanes, busy, serverError, onSubmit, onCancel }: {
  /** Enrolled lane slugs; null when they could not be listed (free text instead). */
  lanes: string[] | null;
  busy: boolean;
  serverError?: string | null;
  onSubmit: (request: CreateAwsPullSourceRequest) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState<AwsPullForm>(EMPTY_AWS_PULL_FORM);
  const [regionTouched, setRegionTouched] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const { errors, request } = validateAwsPullForm(form);
  const shown = submitted ? errors : {};
  const set = (field: AwsPullField, value: string) => setForm((f) => ({ ...f, [field]: value }));
  const id = (field: AwsPullField) => `cloud-pull-${field}`;
  const errorProps = (field: AwsPullField) =>
    shown[field] ? { 'aria-invalid': true, 'aria-describedby': `${id(field)}-error` } : {};

  return (
    <form
      className="rounded-md border border-border p-3 space-y-3"
      data-testid="cloud-pull-form"
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
            onChange={(e) => set('name', e.target.value)} placeholder="prod cloudtrail" className={INPUT_CLS} />
        </Field>
        <Field id={id('sourceSlug')} label="Lane" error={shown.sourceSlug} className="col-span-12 md:col-span-4"
          hint="The source the pulled events are parsed as.">
          <LaneInput id={id('sourceSlug')} lanes={lanes} value={form.sourceSlug} busy={busy}
            invalid={errorProps('sourceSlug')} placeholder="aws_cloudtrail" onChange={(v) => set('sourceSlug', v)} />
        </Field>
        <Field id={id('region')} label="Region" error={shown.region} className="col-span-12 md:col-span-4">
          <Select value={form.region} onValueChange={(v) => { setRegionTouched(true); set('region', v); }} disabled={busy}>
            <SelectTrigger id={id('region')} className="h-8 font-mono" {...errorProps('region')}>
              <SelectValue placeholder="Select a region" />
            </SelectTrigger>
            <SelectContent>
              {AWS_COMMERCIAL_REGIONS.map((r) => (
                <SelectItem key={r} value={r} className="font-mono text-[12px]">{r}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field id={id('roleArn')} label="Role ARN" error={shown.roleArn} className="col-span-12 md:col-span-6"
          hint="The role nano assumes. Its trust policy names nano's role and your ExternalId.">
          <input id={id('roleArn')} value={form.roleArn} disabled={busy} spellCheck={false} {...errorProps('roleArn')}
            onChange={(e) => set('roleArn', e.target.value)} placeholder="arn:aws:iam::123456789012:role/nano-pull" className={INPUT_CLS} />
        </Field>
        <Field id={id('queueArn')} label="Queue ARN" error={shown.queueArn} className="col-span-12 md:col-span-6"
          hint="Same account as the role.">
          <input id={id('queueArn')} value={form.queueArn} disabled={busy} spellCheck={false} {...errorProps('queueArn')}
            onChange={(e) => {
              const value = e.target.value;
              setForm((f) => {
                const queue = parseQueueArn(value.trim());
                // The queue names its region; fill it until the user picks one.
                return { ...f, queueArn: value, region: !regionTouched && queue ? queue.region : f.region };
              });
            }}
            placeholder="arn:aws:sqs:us-east-1:123456789012:nano-pull" className={INPUT_CLS} />
        </Field>
        <Field id={id('bucket')} label="Bucket (optional)" error={shown.bucket} className="col-span-12 md:col-span-6"
          hint="Set when the queue carries S3 event notifications; leave empty when messages are the events.">
          <input id={id('bucket')} value={form.bucket} maxLength={63} disabled={busy} spellCheck={false} {...errorProps('bucket')}
            onChange={(e) => set('bucket', e.target.value)} placeholder="org-cloudtrail-logs" className={INPUT_CLS} />
        </Field>
        <Field id={id('prefix')} label="Prefix (optional)" error={shown.prefix} className="col-span-12 md:col-span-6">
          <input id={id('prefix')} value={form.prefix} maxLength={1024} disabled={busy} spellCheck={false} {...errorProps('prefix')}
            onChange={(e) => set('prefix', e.target.value)} placeholder="AWSLogs/" className={INPUT_CLS} />
        </Field>
      </div>
      {serverError && <div className="text-[11px] text-red-500" role="alert" data-testid="cloud-pull-server-error">{serverError}</div>}
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10.5px] text-muted-foreground" data-testid="cloud-pull-provider">
          provider {form.bucket.trim() ? 'aws_s3_sqs' : 'aws_sqs'}
        </span>
        <span className="flex-1" />
        <Button type="button" variant="outline" size="sm" className="h-7 text-[11.5px]" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button type="submit" size="sm" className="h-7 text-[11.5px]" disabled={busy}>{busy ? 'Adding…' : 'Add source'}</Button>
      </div>
    </form>
  );
}
