// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cloud pull → Azure setup (NAN-3604): keyless Entra federation. The tenant
 * adds a federated identity credential that trusts nano's issuer to its own
 * app registration, grants that app read on the event hub and write on a
 * checkpoint container it owns, and streams its logs to the hub. No client
 * secret, certificate or SAS key is asked for, shown or stored.
 */

import type { ReactNode } from 'react';
import type { PullSourceAzureSetup } from '@/lib/api/pull-sources';
import { CommandBlock } from './CloudPullGcpSetup';
import { KeyRow } from './CloudPullSetup';

const EVENT_HUB_ROLE = 'Azure Event Hubs Data Receiver';
const CHECKPOINT_ROLE = 'Storage Blob Data Contributor';

function Step({ n, title, children }: { n: number; title: ReactNode; children: ReactNode }) {
  return (
    <li className="grid grid-cols-[20px_minmax(0,1fr)] gap-x-2" data-testid={`azure-step-${n}`}>
      <span className="mt-px inline-flex items-center justify-center h-4 w-4 rounded-sm border border-border font-mono text-[10px] text-muted-foreground tabular-nums">
        {n}
      </span>
      <div className="min-w-0 space-y-1.5">
        <div className="text-[12px] font-medium text-foreground leading-4">{title}</div>
        {children}
      </div>
    </li>
  );
}

function Note({ children, testId }: { children: ReactNode; testId?: string }) {
  return <p className="text-[11px] text-muted-foreground leading-relaxed break-words" data-testid={testId}>{children}</p>;
}

function Command({ id, title, command }: { id: string; title: string; command: string | undefined }) {
  return command ? <CommandBlock title={title} command={command} testId={`azure-command-${id}`} wrap /> : null;
}

export function CloudPullAzureSetup({ setup }: { setup: PullSourceAzureSetup }) {
  const role = (scope: string, fallback: string) => setup.app_permissions?.find((p) => p.scope === scope)?.role ?? fallback;
  const c = setup.commands;
  return (
    <div className="space-y-3" data-testid="cloud-pull-azure-setup">
      <Note>
        nano signs in as your own Entra app registration through a federated identity credential. No client secret,
        certificate or SAS key is asked for or stored, and none is ever sent to nano.
      </Note>
      <ol className="space-y-4">
        <Step n={1} title="Add a federated identity credential to your app registration">
          <div className="rounded-md border border-border overflow-hidden [&>div:last-child]:border-b-0">
            <KeyRow label="Issuer" value={setup.issuer} copyLabel="Copy issuer" />
            <KeyRow label="Subject" value={setup.subject} copyLabel="Copy subject" />
            <KeyRow label="Audience" value={setup.audience} copyLabel="Copy audience" />
            <KeyRow label="Name" value={setup.federated_credential_name} copyLabel="Copy credential name" meta="suggested" />
          </div>
          <Note>
            App registrations → your app → Certificates &amp; secrets → Federated credentials → Other issuer. The subject is
            the same for every source this tenant adds. Reusing an app? Skip the first two commands.
          </Note>
          <Command id="app_registration" title="App registration" command={c.app_registration} />
          <Command id="service_principal" title="Service principal" command={c.service_principal} />
          <Command id="federated_credential" title="Federated credential" command={c.federated_credential} />
        </Step>
        <Step n={2} title={<>Grant <span className="font-mono">{role('event_hub', EVENT_HUB_ROLE)}</span> on the event hub</>}>
          <Note>Scope the assignment to the event hub, not the namespace or subscription. It only allows reading.</Note>
          <Command id="role_event_hub" title="Event hub role" command={c.role_event_hub} />
        </Step>
        <Step n={3} title={<>Grant <span className="font-mono">{role('checkpoint_container', CHECKPOINT_ROLE)}</span> on a checkpoint container you own</>}>
          <Note>
            Event Hubs consumers keep their read position in blob storage. nano writes it to your container in the standard
            layout, so any other Event Hubs client can read it.
          </Note>
          <Command id="checkpoint_container" title="Checkpoint container" command={c.checkpoint_container} />
          <Command id="role_checkpoint" title="Checkpoint role" command={c.role_checkpoint} />
        </Step>
        <Step n={4} title="Create a dedicated consumer group">
          <Note>
            Another reader on the same group competes with nano for partitions. Use a group only nano reads; an empty
            consumer group on the source means <span className="font-mono">{setup.default_consumer_group ?? '$Default'}</span>.
          </Note>
          <Command id="consumer_group" title="Consumer group" command={c.consumer_group} />
        </Step>
        <Step n={5} title="Stream logs to the event hub">
          <Note>
            Monitor → Activity log → Export Activity Logs, and Entra ID → Diagnostic settings{' '}
            (<span className="font-mono">SignInLogs</span>, <span className="font-mono">AuditLogs</span>) → Stream to an
            event hub. Pick this namespace and hub.
          </Note>
          {c.diagnostic_settings_hint && <Note testId="azure-diagnostic-hint">{c.diagnostic_settings_hint}</Note>}
          {setup.endpoints && (
            <div className="rounded-md border border-border overflow-hidden [&>div:last-child]:border-b-0" data-testid="azure-endpoints">
              <KeyRow label="Event Hubs (AMQPS)" value={setup.endpoints.event_hubs} copyLabel="Copy Event Hubs endpoint" meta="nano connects out" />
              <KeyRow label="Checkpoints (HTTPS)" value={setup.endpoints.checkpoint_blob} copyLabel="Copy checkpoint endpoint" />
            </div>
          )}
        </Step>
      </ol>
    </div>
  );
}
