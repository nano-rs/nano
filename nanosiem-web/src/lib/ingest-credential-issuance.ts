// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Issue an ingest token for one source (main's NAN-2593 module, re-backed for
 * the ClickHouse product by NAN-4922).
 *
 * Main's hosted flow sealed a platform-minted token to a browser key pair and
 * polled for it. Here the SIEM API mints the token itself
 * (`POST /api/ingest-tokens`, NAN-4907) and returns it once over TLS, bound to
 * the source: there is nothing to poll and no envelope to open. The token
 * lives only in the caller's component state, never in React Query or storage.
 */

import type { IngestToken, IssuedIngestToken } from '@/lib/api/ingest-tokens';

export interface IssuanceClient {
  create(name: string, sourceId: string): Promise<IssuedIngestToken>;
}

export interface IssuanceInput {
  /** Token name (unique per deployment). */
  label: string;
  /** The protocol the sender will use; any token works on all three. */
  protocol: string;
  /** The log source the token is bound to (it decides every event's source). */
  logSourceId: string;
  /** The source's route key, for display. */
  sourceSlug: string;
}

export interface IssuedCredential {
  /** Stable id for the on-screen card (the credential id). */
  requestId: string;
  credentialId: string;
  label: string;
  protocol: string;
  sourceSlugs: string[];
  /** `nit_` + 8 characters: all that is ever shown again. */
  tokenPrefix: string;
  /** The plaintext token. Show it once; never store it. */
  token: string;
}

export async function issueIngestCredential(client: IssuanceClient, input: IssuanceInput): Promise<IssuedCredential> {
  const issued = await client.create(input.label, input.logSourceId);
  const credential: IngestToken = issued.credential;
  return {
    requestId: credential.credential_id,
    credentialId: credential.credential_id,
    label: credential.name,
    protocol: input.protocol,
    sourceSlugs: [credential.route_key ?? input.sourceSlug].filter(Boolean),
    tokenPrefix: credential.token_prefix,
    token: issued.token,
  };
}
