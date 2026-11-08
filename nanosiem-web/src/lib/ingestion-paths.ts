// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4941: Log Sources is the single home for ingestion. Every ingestion
 * surface lives under `/ingestion/log-sources`; the retired Source Configs,
 * Credentials and Pull feeds pages redirect here (App.tsx).
 */

import { CLOUD_PULL_PATH } from './cloud-pull';
import { INGEST_CREDENTIALS_PATH } from './add-data-sources';
import { isConnectorProvider } from '@/components/credentials/connector-credentials';

export { CLOUD_PULL_PATH, INGEST_CREDENTIALS_PATH };

export const LOG_SOURCES_PATH = '/ingestion/log-sources';
export const PULL_FEEDS_PATH = '/ingestion/log-sources/pull-feeds';
export const REPOSITORIES_PATH = '/ingestion/log-sources/repositories';

/** A source configuration (pull transport or push listener) detail page. */
export function sourceConfigPath(id: string): string {
  return `/ingestion/log-sources/inputs/${encodeURIComponent(id)}`;
}

/** Push listener transports: their configs are routing profiles over Vector's listeners. */
export const LISTENER_CONFIG_TYPES = ['http', 'vector', 'otlp', 'splunk_hec'] as const;

export function isListenerConfigType(type: string): boolean {
  return (LISTENER_CONFIG_TYPES as readonly string[]).includes(type);
}

/**
 * Where the Ingestion nav lands: Log sources, or for a viewer without
 * `log_sources:view` the first Log Sources tab they can open. A
 * credentials-only role lands on Cloud pull, whose credential section then
 * lists every credential, connector ones included (pages/CloudPull.tsx).
 */
export function ingestionHomeFor(hasPermission: (permission: string) => boolean): string {
  if (hasPermission('log_sources:view')) return LOG_SOURCES_PATH;
  if (hasPermission('source_configs:view') || hasPermission('credentials:view')) return CLOUD_PULL_PATH;
  if (hasPermission('parsers:view')) return REPOSITORIES_PATH;
  return LOG_SOURCES_PATH;
}

/** Where a credential deep link lands, once its provider is known. */
export function credentialTarget(provider: string | null, params: { add?: string | null; cred?: string | null }): string {
  const home = provider && isConnectorProvider(provider) ? PULL_FEEDS_PATH : CLOUD_PULL_PATH;
  const query = new URLSearchParams();
  // Connector credentials are entered with their feed; only cloud ones have an add form.
  if (params.add && home === CLOUD_PULL_PATH) query.set('add', params.add);
  if (params.cred) query.set('cred', params.cred);
  const qs = query.toString();
  return qs ? `${home}?${qs}` : home;
}

