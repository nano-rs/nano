// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2593: issue → poll → reveal once → open, against a fake SIEM API that seals like the platform. */
import { describe, expect, it, vi } from 'vitest';
import type { IngestCredentialRequestInput, IngestCredentialReveal, TenantIngestCredentialRequest } from '@/lib/api/types';
import { sealToRevealKey } from './credential-seal.fixture';
import { IssuanceAborted, IssuanceError, issueIngestCredential, type IssuanceClient } from './ingest-credential-issuance';

const REQUEST = '0f6f5a1e-7c2b-4d1a-8e3f-2a9b8c7d6e5f';
const TENANT = 'b464ceb9-28a6-4249-8e29-3489627ac5f6';
const TOKEN = 'nano_tok_0123456789abcdefghijklmnopqrstuv';

function fakeServer(opts: { pendingPolls?: number; reject?: string; tokenFor?: string } = {}) {
  let input: IngestCredentialRequestInput | null = null;
  let polls = 0;
  let sealed: string | null = null;
  let revealed = false;
  const base = (): IngestCredentialReveal => ({
    request_id: REQUEST, tenant_id: TENANT, state: 'pending', kind: 'source', protocol: input!.protocol,
    label: input!.label, source_slugs: input!.source_slugs, sealed_token_ready: false, sealed_token: null,
  });
  const client: IssuanceClient = {
    requestIngestCredential: vi.fn(async (i: IngestCredentialRequestInput) => {
      input = i;
      return { id: REQUEST, protocol: i.protocol, label: i.label, state: 'pending', requested_by: 'user_x', requested_at: '', updated_at: '',
        kind: 'source', source_slugs: i.source_slugs, restricted_sources_acknowledged: false, sealed_token_ready: false } as TenantIngestCredentialRequest;
    }),
    getIngestCredentialRequest: vi.fn(async () => {
      polls += 1;
      if (opts.reject) return { ...base(), state: 'rejected', disposition: opts.reject };
      if (polls <= (opts.pendingPolls ?? 2)) return base();
      sealed ??= sealToRevealKey(input!.reveal_public_key, TOKEN, REQUEST, opts.tokenFor ?? TENANT);
      return { ...base(), state: 'issued', credential_id: 'cred-1', sealed_token_ready: !revealed, revealed_at: revealed ? 'now' : null };
    }),
    revealIngestCredential: vi.fn(async () => {
      if (revealed) throw new Error('Gone: already_revealed: gone');
      revealed = true;
      return { ...base(), state: 'issued', credential_id: 'cred-1', sealed_token_ready: false, sealed_token: sealed, revealed_at: 'now' };
    }),
  };
  return { client, input: () => input };
}

const noSleep = async () => {};

describe('issueIngestCredential (NAN-2593)', () => {
  it('sends only a public key, polls until sealed, reveals exactly once and opens the token', async () => {
    const server = fakeServer({ pendingPolls: 3 });
    const phases: string[] = [];
    const out = await issueIngestCredential(
      server.client,
      { protocol: 'hec', label: 'fw-hec', kind: 'source', source_slugs: ['palo_alto_traffic'] },
      { sleep: noSleep, onPhase: (p) => phases.push(p) },
    );
    expect(out).toMatchObject({ requestId: REQUEST, credentialId: 'cred-1', token: TOKEN, protocol: 'hec', sourceSlugs: ['palo_alto_traffic'] });
    const sent = server.input()!;
    expect(sent.reveal_key_alg).toBe('x25519');
    expect(sent.reveal_public_key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(sent)).not.toMatch(/private|pkcs8|"d":/);
    expect(server.client.getIngestCredentialRequest).toHaveBeenCalledTimes(4);
    expect(server.client.revealIngestCredential).toHaveBeenCalledTimes(1);
    expect(phases).toEqual(['keygen', 'requesting', 'waiting', 'revealing', 'opening']);
  });

  it('backs off between polls up to the cap', async () => {
    const server = fakeServer({ pendingPolls: 5 });
    const waits: number[] = [];
    await issueIngestCredential(server.client, { protocol: 'hec', label: 'l', source_slugs: ['s'] }, {
      pollMs: 500, maxPollMs: 2000, sleep: async (ms) => { waits.push(ms); },
    });
    expect(waits).toEqual([500, 1000, 2000, 2000, 2000]);
  });

  it('surfaces a rejected request with its reason code', async () => {
    const server = fakeServer({ reject: 'source_restricted: requester cannot see source' });
    const err = await issueIngestCredential(server.client, { protocol: 'hec', label: 'l', source_slugs: ['s'] }, { sleep: noSleep })
      .catch((e) => e);
    expect(err).toBeInstanceOf(IssuanceError);
    expect((err as IssuanceError).problem.code).toBe('source_restricted');
    expect(server.client.revealIngestCredential).not.toHaveBeenCalled();
  });

  it('refuses a token sealed for another tenant', async () => {
    const server = fakeServer({ pendingPolls: 0, tokenFor: 'c575dfca-39b7-435a-9f3a-459a738bd607' });
    await expect(issueIngestCredential(server.client, { protocol: 'hec', label: 'l', source_slugs: ['s'] }, { sleep: noSleep }))
      .rejects.toThrow(/did not open/);
  });

  it('stops polling when cancelled and reports the request id', async () => {
    const server = fakeServer({ pendingPolls: 1000 });
    const controller = new AbortController();
    const err = await issueIngestCredential(server.client, { protocol: 'hec', label: 'l', source_slugs: ['s'] }, {
      signal: controller.signal,
      sleep: async () => { controller.abort(); },
    }).catch((e) => e);
    expect(err).toBeInstanceOf(IssuanceAborted);
    expect((err as IssuanceAborted).requestId).toBe(REQUEST);
    expect(server.client.revealIngestCredential).not.toHaveBeenCalled();
  });

  it('treats an issued request with no ciphertext left as expired', async () => {
    const server = fakeServer();
    (server.client.getIngestCredentialRequest as ReturnType<typeof vi.fn>).mockImplementation(async () => ({
      request_id: REQUEST, tenant_id: TENANT, state: 'issued', kind: 'source', protocol: 'hec', label: 'l', source_slugs: ['s'],
      sealed_token_ready: false, revealed_at: null,
    }));
    const err = await issueIngestCredential(server.client, { protocol: 'hec', label: 'l', source_slugs: ['s'] }, { sleep: noSleep }).catch((e) => e);
    expect((err as IssuanceError).problem.code).toBe('sealed_token_expired');
  });
});
