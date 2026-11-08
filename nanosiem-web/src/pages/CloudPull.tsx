// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Log Sources → Cloud pull (route /ingestion/log-sources/cloud-pull).
 *
 * Main's page (NAN-3596) drove the hosted keyless pull broker. On the
 * ClickHouse product Vector reads cloud queues and brokers through source
 * configurations with customer-owned credentials. NAN-4941 makes this tab
 * their single home: the pull sources (AWS S3 via SQS, SQS, GCP Pub/Sub, Azure
 * Event Hubs, Kafka) with create / deploy / undeploy / delete, and the
 * credentials they read with, entered, rotated, rolled back and shown masked
 * in place. The retired Source Configs and Credentials pages redirect here.
 */

import { CloudDownload } from 'lucide-react';

import { LogSourcesPageHeader, LogSourcesPageShell } from '@/components/add-data/LogSourcesPageShell';
import { CLOUD_CREDENTIAL_PROVIDERS, CredentialsManager } from '@/components/credentials/CredentialsManager';
import { SourceConfigsPanel } from '@/components/source-configs/SourceConfigsPanel';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { PULL_CONFIG_TYPES } from '@/lib/cloud-pull';
import { CONNECTOR_CREDENTIAL_PROVIDERS } from '@/components/credentials/connector-credentials';

export function CloudPull() {
  useDocumentTitle('Cloud pull');
  const { hasPermission } = useAuth();
  const canSources = hasPermission('source_configs:view');
  const canCredentials = hasPermission('credentials:view');
  // A credentials-only role (no log_sources:view) lands here from the nav and
  // from old /ingestion/credentials links: show it every credential it can
  // manage, connector ones included (NAN-4941 review). With feed access those
  // live on Pull feeds next to their feeds.
  const credentialProviders = hasPermission('log_sources:view')
    ? CLOUD_CREDENTIAL_PROVIDERS
    : [...CLOUD_CREDENTIAL_PROVIDERS, ...CONNECTOR_CREDENTIAL_PROVIDERS];

  return (
    <LogSourcesPageShell active="cloud-pull" testId="cloud-pull-page">
      <LogSourcesPageHeader
        icon={CloudDownload}
        title="Cloud pull"
        meta={<span>AWS S3 · SQS · GCP Pub/Sub · Azure Event Hubs · Kafka</span>}
      />

      <div className="px-5 py-4 space-y-4" data-testid="cloud-pull-region">
        <div className="text-[11.5px] text-muted-foreground max-w-[760px] leading-relaxed">
          Vector reads cloud queues and brokers with credentials you own. A pull source delivers into the
          log sources its routing rules name; deploy it to start reading.
        </div>
        {canSources && (
          <SourceConfigsPanel
            types={PULL_CONFIG_TYPES}
            title="Pull sources"
            description="Queues, subscriptions, hubs and topics Vector reads from. Open one to edit its connection and routing."
            addLabel="Add cloud pull"
            testId="cloud-pull-sources"
          />
        )}
        {canCredentials && (
          <CredentialsManager
            providers={credentialProviders}
            addProviders={CLOUD_CREDENTIAL_PROVIDERS}
            title={credentialProviders === CLOUD_CREDENTIAL_PROVIDERS ? 'Cloud credentials' : 'Credentials'}
          />
        )}
        {!canSources && !canCredentials && (
          <div className="text-[12px] text-muted-foreground">You need source_configs:view or credentials:view to see cloud pull.</div>
        )}
      </div>
    </LogSourcesPageShell>
  );
}

export default CloudPull;
