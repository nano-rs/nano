// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4914: credentials-store providers that hold a connector pull feed's
 * vendor secret. Their fields come from the bundled connector spec
 * (`/api/connector-specs`): the rotate form renders exactly those fields, and
 * a Google Workspace credential is rotated by pasting the new service-account
 * key JSON (the API keeps only its client email and private key).
 */

import type { ConnectorSpecInfo } from '@/lib/api/connector-feeds';

export const CONNECTOR_CREDENTIAL_PROVIDERS = ['okta', 'google_workspace', 'slack', 'saas_api'] as const;

export function isConnectorProvider(provider: string): boolean {
  return (CONNECTOR_CREDENTIAL_PROVIDERS as readonly string[]).includes(provider);
}

/** Input fields for a provider: `credentials_json` for Google Workspace,
 *  else the union of the credential fields of every spec on that provider. */
export function connectorSecretFields(provider: string, specs: ConnectorSpecInfo[]): string[] {
  if (provider === 'google_workspace') return ['credentials_json'];
  const fields = new Set<string>();
  for (const s of specs) {
    if (s.credential_provider === provider) s.credential_fields.forEach((f) => fields.add(f));
  }
  return [...fields].sort();
}

export function connectorSecretsValid(fields: string[], values: Record<string, string>): boolean {
  return fields.length > 0 && fields.every((f) => (values[f] ?? '').trim() !== '');
}

/** The rotate payload: exactly the rendered fields, trimmed (a key JSON or
 *  PEM keeps its inner whitespace). */
export function connectorSecretsPayload(fields: string[], values: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of fields) out[f] = f === 'credentials_json' ? values[f] ?? '' : (values[f] ?? '').trim();
  return out;
}
