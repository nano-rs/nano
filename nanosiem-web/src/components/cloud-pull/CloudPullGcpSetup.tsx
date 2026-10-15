// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull → GCP setup (NAN-3598): the IAM binding the tenant adds on its
 * Pub/Sub subscription before adding a source. nano reads as the tenant's own
 * service account; no key is created or exchanged. The role is bound on the
 * subscription, never on the project.
 */

import { CopyButton } from '@/components/add-data/CopyButton';
import type { PullSourceGcpSetup } from '@/lib/api/pull-sources';
import { gcpSubscriptionProblem } from '@/lib/cloud-pull';
import { KeyRow } from './CloudPullSetup';

export function CommandBlock({ title, command, testId, wrap = false }: { title: string; command: string; testId: string; wrap?: boolean }) {
  return (
    <div className="min-w-0 rounded-md border border-border overflow-hidden">
      <div className="flex items-center h-7 px-2.5 border-b border-border bg-card/60">
        <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{title}</span>
        <span className="flex-1" />
        <CopyButton text={command} aria-label={`Copy ${title.toLowerCase()}`} className="h-5" />
      </div>
      <pre data-testid={testId} className={`${wrap ? 'whitespace-pre-wrap break-all' : 'overflow-x-auto whitespace-pre'} [font-variant-ligatures:none] px-2.5 py-2 font-mono text-[10.5px] leading-[1.5] text-foreground/90 bg-background`}>
        {command}
      </pre>
    </div>
  );
}

export function CloudPullGcpSetup({ setup, subscription, onSubscriptionChange, subscriptionError }: {
  setup: PullSourceGcpSetup;
  /** Optional: a subscription to fill the commands with. */
  subscription: string;
  onSubscriptionChange: (value: string) => void;
  /** The server's refusal of `subscription` (400), shown inline. */
  subscriptionError?: string | null;
}) {
  const trimmed = subscription.trim();
  const problem = trimmed ? gcpSubscriptionProblem(trimmed) : null;
  const shownError = problem ?? subscriptionError ?? null;
  return (
    <div className="space-y-3" data-testid="cloud-pull-gcp-setup">
      <div className="rounded-md border border-border overflow-hidden [&>div:last-child]:border-b-0">
        <KeyRow label="Service account" value={setup.service_account} copyLabel="Copy service account" />
        <KeyRow label="Role" value={setup.role} copyLabel="Copy role" meta="on the subscription, not the project" />
        <KeyRow label="Subscription format" value={setup.subscription_format} copyLabel="Copy subscription format" />
      </div>
      <div>
        <label htmlFor="cloud-pull-gcp-setup-subscription" className="block text-[10.5px] font-medium text-foreground/80 mb-1.5">
          Fill the commands for a subscription (optional)
        </label>
        <input
          id="cloud-pull-gcp-setup-subscription"
          value={subscription}
          maxLength={512}
          spellCheck={false}
          aria-invalid={shownError ? true : undefined}
          aria-describedby={shownError ? 'cloud-pull-gcp-setup-subscription-error' : undefined}
          onChange={(e) => onSubscriptionChange(e.target.value)}
          placeholder="projects/acme-logging/subscriptions/nano-audit"
          className="h-8 w-full max-w-[560px] rounded-md border border-input bg-background px-2.5 font-mono text-[12px] text-foreground focus:border-primary focus:outline-none"
        />
        {shownError && (
          <div className="mt-1 text-[10.5px] text-red-500" id="cloud-pull-gcp-setup-subscription-error" role="alert">{shownError}</div>
        )}
      </div>
      <div className="space-y-2">
        <CommandBlock title="Grant" command={setup.gcloud_command} testId="cloud-pull-gcp-command" />
        <CommandBlock title="Verify" command={setup.verify_command} testId="cloud-pull-gcp-verify" />
      </div>
      <ul className="space-y-0.5 text-[11px] text-muted-foreground leading-relaxed list-disc pl-4">
        <li>
          Grant <span className="font-mono">{setup.role}</span> on the subscription only. A project-level grant would let nano
          read every subscription in the project.
        </li>
        <li>
          nano reads as <span className="font-mono">{setup.member}</span>. No service account key is created or shared.
        </li>
        <li>
          Give the subscription a dead-letter topic. Messages nano cannot process move there instead of being redelivered
          forever.
        </li>
      </ul>
    </div>
  );
}
