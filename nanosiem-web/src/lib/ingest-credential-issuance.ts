// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Issue → poll → reveal once → open (NAN-2593, design §4).
 *
 * 1. Make an ephemeral reveal key pair in the browser (X25519, P-256 fallback).
 * 2. `POST /api/log-sources/ingest-credentials` with the raw public key.
 * 3. Poll `GET …/requests/{id}` until `sealed_token_ready` (the platform has
 *    minted the token and sealed it to our key) or the request is rejected.
 * 4. `POST …/requests/{id}/reveal` exactly once; the server clears the
 *    ciphertext in the same transaction.
 * 5. Open the envelope locally and hand the plaintext to the caller.
 *
 * Nothing here uses React Query or storage: the key pair and the token live
 * in local variables, and the key pair is dropped when this returns.
 */

import type {
  IngestCredentialReveal,
  IngestCredentialRequestInput,
  TenantIngestCredentialRequest,
} from '@/lib/api/types';
import { generateRevealKeyPair, openSealedToken, type RevealKeyPair } from '@/lib/credential-seal';
import { describeRefusal, refusalCode, type IngestCredentialProblem } from '@/lib/ingest-credential-errors';

export type IssuancePhase = 'keygen' | 'requesting' | 'waiting' | 'revealing' | 'opening';

export interface IssuanceClient {
  requestIngestCredential(input: IngestCredentialRequestInput): Promise<TenantIngestCredentialRequest>;
  getIngestCredentialRequest(requestId: string): Promise<IngestCredentialReveal>;
  revealIngestCredential(requestId: string): Promise<IngestCredentialReveal>;
}

export type IssuanceInput = Omit<IngestCredentialRequestInput, 'reveal_public_key' | 'reveal_key_alg'>;

export interface IssuedCredential {
  requestId: string;
  credentialId: string | null;
  label: string;
  protocol: string;
  sourceSlugs: string[];
  /** The plaintext token. Show it once; never store it. */
  token: string;
}

/** A refusal or terminal state the UI explains with `problem`. */
export class IssuanceError extends Error {
  constructor(public problem: IngestCredentialProblem, public requestId?: string) {
    super(problem.detail);
    this.name = 'IssuanceError';
  }
}

export class IssuanceAborted extends Error {
  constructor(public requestId?: string) {
    super('issuance cancelled');
    this.name = 'IssuanceAborted';
  }
}

export interface IssuanceOptions {
  signal?: AbortSignal;
  onPhase?: (phase: IssuancePhase, request?: TenantIngestCredentialRequest) => void;
  /** First poll delay; doubles up to `maxPollMs`. */
  pollMs?: number;
  maxPollMs?: number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  generateKeyPair?: () => Promise<RevealKeyPair>;
  open?: typeof openSealedToken;
}

function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new IssuanceAborted());
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new IssuanceAborted());
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function rejection(status: IngestCredentialReveal, requestId: string): IssuanceError {
  const code = refusalCode(status.disposition);
  const problem = describeRefusal(code, status.disposition ?? `request ${status.state}`);
  return new IssuanceError(code === 'unknown' ? { ...problem, title: `Request ${status.state}`, terminal: true } : problem, requestId);
}

export async function issueIngestCredential(
  client: IssuanceClient,
  input: IssuanceInput,
  options: IssuanceOptions = {},
): Promise<IssuedCredential> {
  const { signal, onPhase } = options;
  const sleep = options.sleep ?? abortableSleep;
  const maxPollMs = options.maxPollMs ?? 5000;
  let pollMs = options.pollMs ?? 1000;
  const check = (requestId?: string) => {
    if (signal?.aborted) throw new IssuanceAborted(requestId);
  };

  onPhase?.('keygen');
  let keyPair: RevealKeyPair | null = await (options.generateKeyPair ?? generateRevealKeyPair)();
  try {
    check();
    onPhase?.('requesting');
    const request = await client.requestIngestCredential({
      ...input,
      reveal_public_key: keyPair.publicKeyB64u,
      reveal_key_alg: keyPair.alg,
    });
    const requestId = request.id;
    onPhase?.('waiting', request);

    for (;;) {
      check(requestId);
      const status = await client.getIngestCredentialRequest(requestId);
      if (status.state === 'rejected' || status.state === 'revoked') throw rejection(status, requestId);
      if (status.revealed_at) throw new IssuanceError(describeRefusal('already_revealed'), requestId);
      if (status.state === 'issued' && !status.sealed_token_ready) {
        // Issued, never revealed, no ciphertext left: the 10-minute window lapsed.
        throw new IssuanceError(describeRefusal('sealed_token_expired'), requestId);
      }
      if (status.sealed_token_ready) {
        check(requestId);
        onPhase?.('revealing', request);
        const revealed = await client.revealIngestCredential(requestId);
        if (!revealed.sealed_token) {
          if (revealed.state === 'rejected' || revealed.state === 'revoked') throw rejection(revealed, requestId);
          // Not sealed after all (a race with the fulfilment worker): keep polling.
          await sleep(pollMs, signal).catch((e) => { throw e instanceof IssuanceAborted ? new IssuanceAborted(requestId) : e; });
          continue;
        }
        onPhase?.('opening', request);
        const token = await (options.open ?? openSealedToken)({
          sealed: revealed.sealed_token,
          keyPair,
          requestId: revealed.request_id,
          tenantId: revealed.tenant_id,
        });
        return {
          requestId,
          credentialId: revealed.credential_id ?? null,
          label: revealed.label || request.label,
          protocol: revealed.protocol || request.protocol,
          sourceSlugs: revealed.source_slugs?.length ? revealed.source_slugs : request.source_slugs ?? [],
          token,
        };
      }
      await sleep(pollMs, signal).catch((e) => { throw e instanceof IssuanceAborted ? new IssuanceAborted(requestId) : e; });
      pollMs = Math.min(pollMs * 2, maxPollMs);
    }
  } finally {
    // Drop the only reference to the private key.
    keyPair = null;
  }
}
