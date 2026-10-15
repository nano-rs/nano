// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull → AWS setup (NAN-3596): what the tenant creates in its own AWS
 * account before adding a source. The role trusts nano's IAM role with the
 * tenant's ExternalId; nano never asks for keys.
 */

import { Download, ExternalLink } from 'lucide-react';
import { CopyButton } from '@/components/add-data/CopyButton';
import type { PullSourceAwsSetup } from '@/lib/api/pull-sources';
import { safeQuickCreateUrl } from '@/lib/cloud-pull';

export function KeyRow({ label, value, copyLabel, meta }: { label: string; value: string; copyLabel: string; meta?: string }) {
  return (
    <div className="grid grid-cols-[120px_minmax(0,1fr)_auto] items-center gap-2 px-3 min-h-7 py-1 border-b border-border/60">
      <span className="text-[11px] text-muted-foreground">{label}</span>
      <span className="font-mono text-[11.5px] text-foreground truncate" title={value}>
        {value}
        {meta && <span className="ml-2 text-[10.5px] text-muted-foreground">{meta}</span>}
      </span>
      <CopyButton text={value} aria-label={copyLabel} />
    </div>
  );
}

function PolicyBlock({ title, policy, testId }: { title: string; policy: Record<string, unknown>; testId: string }) {
  const text = JSON.stringify(policy, null, 2);
  return (
    <div className="min-w-0 rounded-md border border-border overflow-hidden">
      <div className="flex items-center h-7 px-2.5 border-b border-border bg-card/60">
        <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{title}</span>
        <span className="flex-1" />
        <CopyButton text={text} aria-label={`Copy ${title.toLowerCase()}`} className="h-5" />
      </div>
      <pre data-testid={testId} className="max-h-56 overflow-auto px-2.5 py-2 font-mono text-[10.5px] leading-[1.5] text-foreground/90 bg-background">
        {text}
      </pre>
    </div>
  );
}

function downloadTemplate(template: PullSourceAwsSetup['cloudformation_template']) {
  // The API returns the template as a JSON object; a string (YAML or JSON) is passed through.
  const text = typeof template === 'string' ? template : JSON.stringify(template, null, 2);
  const json = text.trimStart().startsWith('{');
  const blob = new Blob([text], { type: json ? 'application/json' : 'application/x-yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = json ? 'nano-cloud-pull.json' : 'nano-cloud-pull.yaml';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

const ACTION_CLS =
  'inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border bg-card text-[11.5px] text-foreground/90 hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary';

export function CloudPullSetup({ setup }: { setup: PullSourceAwsSetup }) {
  const launchUrl = safeQuickCreateUrl(setup.quick_create_url);
  return (
    <div className="space-y-3" data-testid="cloud-pull-setup">
      <div className="rounded-md border border-border overflow-hidden [&>div:last-child]:border-b-0">
        <KeyRow label="Nano principal (IAM role)" value={setup.nano_principal_arn} copyLabel="Copy nano role ARN" />
        <KeyRow label="ExternalId" value={setup.external_id} copyLabel="Copy ExternalId" meta={`v${setup.external_id_version}`} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <PolicyBlock title="Trust policy" policy={setup.trust_policy} testId="cloud-pull-trust-policy" />
        <PolicyBlock title="Permission policy" policy={setup.permission_policy_template} testId="cloud-pull-permission-policy" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {setup.cloudformation_template && (
          <button type="button" className={ACTION_CLS} onClick={() => downloadTemplate(setup.cloudformation_template)}>
            <Download className="w-3 h-3" strokeWidth={1.5} /> Download CloudFormation template
          </button>
        )}
        {launchUrl && (
          <a href={launchUrl} target="_blank" rel="noopener noreferrer" className={ACTION_CLS}>
            <ExternalLink className="w-3 h-3" strokeWidth={1.5} /> Launch stack
          </a>
        )}
      </div>
      <ul className="space-y-0.5 text-[11px] text-muted-foreground leading-relaxed list-disc pl-4">
        <li>
          Give the queue a dead-letter queue (a redrive policy). Messages nano cannot process move there instead of
          retrying forever.
        </li>
        <li>
          Send S3 event notifications directly to the SQS queue, or through SNS with{' '}
          <span className="font-mono">RawMessageDelivery</span> on. Wrapped SNS envelopes are not read.
        </li>
        <li>
          Scope the permission policy to your queue and bucket. The role and the queue must be in the same AWS account.
        </li>
      </ul>
    </div>
  );
}
