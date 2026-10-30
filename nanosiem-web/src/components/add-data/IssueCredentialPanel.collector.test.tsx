// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-2597: the Issue step for a collector credential (one token, many
 * sources, aliases). Same harness as the NAN-2593 suite: a fake SIEM API seals
 * the token to the browser's real WebCrypto public key.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { IngestCredentialRequestInput, SenderTemplateCatalog, TenantIngestEndpoint } from '@/lib/api/types';
import { sealToRevealKey } from '@/lib/credential-seal.fixture';
import { IssueCredentialPanel } from './IssueCredentialPanel';

const TENANT = 'b464ceb9-28a6-4249-8e29-3489627ac5f6';
const HOST = `${TENANT}.ingest.nano.rs`;

const state = vi.hoisted(() => ({
  permissions: new Set<string>(['log_sources:deploy', 'log_sources:view']),
  restricted: [] as Array<{ source_type: string }>,
  requests: [] as IngestCredentialRequestInput[],
  sealed: new Map<string, string>(),
  revealed: new Set<string>(),
  tokens: [] as string[],
  refuseWith: null as string | null,
  verdict: null as string | null,
  prechecks: [] as Array<{ kind: string; source_slugs: string[] }>,
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user_me' }, hasPermission: (p: string) => state.permissions.has(p) }),
}));

vi.mock('@/lib/api', () => {
  class ApiClientError extends Error {
    constructor(message: string, public code: string, public details?: unknown, public status?: number) {
      super(message);
    }
  }
  const requestId = (n: number) => `0f6f5a1e-7c2b-4d1a-8e3f-${String(n).padStart(12, '0')}`;
  const reveal = (id: string, extra: object = {}) => {
    const input = state.requests[Number(id.slice(-12)) - 1];
    return {
      request_id: id, tenant_id: TENANT, state: 'issued', kind: input.kind ?? 'source', protocol: input.protocol, label: input.label,
      source_slugs: input.source_slugs, credential_id: `cred-${id.slice(-2)}`, sealed_token_ready: !state.revealed.has(id),
      revealed_at: state.revealed.has(id) ? '2026-09-22T00:00:00Z' : null, sealed_token: null, ...extra,
    };
  };
  return {
    ApiClientError,
    api: {
      sourceScopes: { listRestricted: vi.fn(async () => ({ restricted: state.restricted })) },
      precheckIngestCredential: vi.fn(async (input: { kind: string; source_slugs: string[] }) => {
        state.prechecks.push(input);
        const v = state.verdict;
        return {
          verdict: v, allowed: v === null, needs_acknowledgement: v === 'restricted_sources_unacknowledged',
          blocked: v !== null && v !== 'restricted_sources_unacknowledged',
        };
      }),
      // The server's exact catalog (kept in lockstep by a Rust test).
      getSenderTemplates: vi.fn(async (): Promise<SenderTemplateCatalog> =>
        (await import('@/lib/sender-templates.fixture.json')).default as SenderTemplateCatalog),
      requestIngestCredential: vi.fn(async (input: IngestCredentialRequestInput) => {
        if (state.refuseWith) throw new ApiClientError(state.refuseWith, 'FORBIDDEN', undefined, 403);
        state.requests.push(input);
        const id = requestId(state.requests.length);
        const token = `nano_tok_${state.requests.length}_abcdefghijklmnopqrstuvwxyz0123456789`;
        state.tokens.push(token);
        state.sealed.set(id, sealToRevealKey(input.reveal_public_key, token, id, TENANT));
        return { id, protocol: input.protocol, label: input.label, state: 'pending', requested_by: 'user_me', requested_at: '',
          updated_at: '', kind: input.kind ?? 'source', source_slugs: input.source_slugs, restricted_sources_acknowledged: false, sealed_token_ready: false };
      }),
      getIngestCredentialRequest: vi.fn(async (id: string) => reveal(id)),
      revealIngestCredential: vi.fn(async (id: string) => {
        if (state.revealed.has(id)) throw new ApiClientError('Gone: already_revealed: gone', 'GONE', undefined, 410);
        state.revealed.add(id);
        return reveal(id, { sealed_token: state.sealed.get(id), sealed_token_ready: false });
      }),
    },
  };
});

import { api } from '@/lib/api';

const endpoint: TenantIngestEndpoint = {
  hostname: HOST, base_url: `https://${HOST}`, hec_url: `https://${HOST}/services/collector/event`,
  otlp_logs_url: `https://${HOST}/v1/logs`, otlp_traces_url: `https://${HOST}/v1/traces`, otlp_metrics_url: `https://${HOST}/v1/metrics`,
  otlp_telemetry_ingested: false, nano_https_url: `https://${HOST}/ingest`, hec_health_url: `https://${HOST}/services/collector/health`,
  endpoint_state: 'ready', sources: [], credential_issuance: { managed_by_platform: false, reason: '', detail: '' },
  ingress_contract: {
    version: 2, credential_kinds: ['source', 'collector'], collector_credentials: true,
    source_declarations: ['hec:event.sourcetype', 'otlp_http:resource.nano.source'],
  },
};
const V1_ENDPOINT: TenantIngestEndpoint = {
  ...endpoint,
  ingress_contract: { version: 1, credential_kinds: ['source'], collector_credentials: false, source_declarations: [] },
};
type Src = { slug: string; protocols: Array<'hec' | 'nano_https' | 'otlp_http'>; enrolled: boolean };
const PA: Src = { slug: 'palo_alto_traffic', protocols: ['hec', 'nano_https'], enrolled: true };
const OKTA: Src = { slug: 'okta', protocols: ['hec', 'nano_https'], enrolled: true };
const WIN: Src = { slug: 'windows_security', protocols: ['hec'], enrolled: true };

let client: QueryClient;
function renderPanel(sources: Src[] = [PA, OKTA], ep: TenantIngestEndpoint = endpoint) {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <IssueCredentialPanel endpoint={ep} collectorSources={sources} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const writeText = vi.fn(async (text: string) => { void text; });

beforeEach(() => {
  state.permissions = new Set(['log_sources:deploy', 'log_sources:view']);
  state.restricted = [];
  state.requests = [];
  state.sealed.clear();
  state.revealed.clear();
  state.tokens = [];
  state.refuseWith = null;
  state.verdict = null;
  state.prechecks = [];
  writeText.mockClear();
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
  vi.mocked(api.revealIngestCredential).mockClear();
});
afterEach(cleanup);

async function issue() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /issue (another )?credential/i }));
  });
}

describe('IssueCredentialPanel, collector (NAN-2597)', () => {
  it('issues one token for the allowlist with prefilled and edited aliases, and fills collector snippets', async () => {
    renderPanel();
    expect(screen.getByTestId('collector-source-count').textContent).toBe('2');
    expect(screen.getAllByRole('radio').map((r) => r.textContent)).toEqual(['HEC', 'HTTPS JSON']);
    expect((screen.getByLabelText('Label') as HTMLInputElement).value).toBe('collector-hec');
    const pa = screen.getByTestId('collector-source-palo_alto_traffic');
    expect(pa.textContent).toContain('pan:traffic');
    // Add an alias of our own, remove a prefilled one.
    const input = within(pa).getByLabelText('Add alias for palo_alto_traffic');
    fireEvent.change(input, { target: { value: 'pan_traffic_v2' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    fireEvent.click(within(screen.getByTestId('collector-source-okta')).getByRole('button', { name: 'Remove alias OktaIM2:log' }));

    await issue();
    await screen.findByLabelText('Ingest token');
    expect(state.requests[0]).toMatchObject({
      kind: 'collector', protocol: 'hec', label: 'collector-hec',
      source_slugs: ['palo_alto_traffic', 'okta'],
      source_aliases: { 'pan:traffic': 'palo_alto_traffic', pan_traffic_v2: 'palo_alto_traffic' },
    });
    expect(state.requests[0].log_source_id).toBeUndefined();

    // Collector templates only, with the allowlist and the revealed token.
    const tabs = within(await screen.findByTestId('sender-snippets')).getAllByRole('tab').map((t) => t.textContent);
    expect(tabs).toEqual(['curl', 'Vector', 'Fluent Bit', 'OpenTelemetry Collector', 'Cribl Stream']);
    fireEvent.click(screen.getByRole('tab', { name: 'Cribl Stream' }));
    const cribl = screen.getByTestId('sender-snippet-body').textContent ?? '';
    expect(cribl).toContain(`HEC auth token:      ${state.tokens[0]}`);
    expect(cribl).toContain('Allowed sourcetypes: palo_alto_traffic, okta, pan:traffic, pan_traffic_v2');
    expect(cribl).not.toMatch(/\{\{[a-z_]+\}\}/);
  });

  it('refuses an alias the server would refuse, before any request', async () => {
    renderPanel();
    const okta = screen.getByTestId('collector-source-okta');
    const input = within(okta).getByLabelText('Add alias for okta');
    for (const [value, message] of [
      ['palo_alto_traffic', /already a source/],
      ['unknown', /reserved/],
      ['pan:traffic', /already maps to palo_alto_traffic/],
      ['has space', /A-Z/],
    ] as const) {
      fireEvent.change(input, { target: { value } });
      fireEvent.keyDown(input, { key: 'Enter' });
      expect(within(okta).getByRole('alert').textContent).toMatch(message);
    }
    expect(state.requests).toHaveLength(0);
  });

  // NAN-2617: the precheck (the server's issuance guard) decides, not "any restricted source".
  it('a restricted source the issuer can see needs no acknowledgement', async () => {
    state.permissions.add('source_scopes:view');
    state.restricted = [{ source_type: 'windows_security' }];
    renderPanel([PA, WIN]);
    await vi.waitFor(() => expect(state.prechecks).toContainEqual({ kind: 'collector', source_slugs: ['palo_alto_traffic', 'windows_security'] }));
    expect(screen.queryByTestId('restricted-ack')).toBeNull();
    expect((screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('spanning a source the issuer is restricted from needs source_scopes:manage (decision (b))', async () => {
    state.permissions.add('source_scopes:view');
    state.restricted = [{ source_type: 'windows_security' }];
    state.verdict = 'source_restricted';
    renderPanel([PA, WIN]);
    const box = await screen.findByTestId('restricted-ack');
    expect(box.textContent).toContain('windows_security');
    expect(box.textContent).toMatch(/needs the source_scopes:manage permission/);
    expect((screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('a selection mixing restriction sets without source_scopes:manage names the mix', async () => {
    state.restricted = [{ source_type: 'windows_security' }];
    state.permissions.add('source_scopes:view');
    state.verdict = 'mixed_restrictions_require_manage';
    renderPanel([PA, WIN]);
    const box = await screen.findByTestId('restricted-ack');
    expect(box.textContent).toMatch(/These sources have different restrictions/);
    expect(box.textContent).toMatch(/needs the source_scopes:manage permission/);
    expect((screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('with source_scopes:manage the acknowledgement is explicit and sent', async () => {
    state.permissions.add('source_scopes:view');
    state.permissions.add('source_scopes:manage');
    state.restricted = [{ source_type: 'windows_security' }];
    state.verdict = 'restricted_sources_unacknowledged';
    renderPanel([PA, WIN]);
    const box = await screen.findByTestId('restricted-ack');
    const button = screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(within(box).getByRole('checkbox'));
    expect(button.disabled).toBe(false);
    await issue();
    await screen.findByLabelText('Ingest token');
    expect(state.requests[0]).toMatchObject({ kind: 'collector', restricted_sources_acknowledged: true, source_slugs: ['palo_alto_traffic', 'windows_security'] });
  });

  it('a mixed-restriction refusal from the server asks for the acknowledgement', async () => {
    state.permissions.add('source_scopes:manage');
    state.refuseWith = 'Forbidden: ingest_credential_refused: mixed_restrictions_require_manage';
    renderPanel([PA, WIN]);
    await issue();
    const box = await screen.findByTestId('restricted-ack');
    state.refuseWith = null;
    fireEvent.click(within(box).getByRole('checkbox'));
    await issue();
    await screen.findByLabelText('Ingest token');
    expect(state.requests[0].restricted_sources_acknowledged).toBe(true);
  });

  it('a tenant whose Worker is still on ingress v1 cannot issue a collector (NAN-2617)', async () => {
    renderPanel([PA, OKTA], V1_ENDPOINT);
    expect(screen.getByTestId('collector-unavailable').textContent).toMatch(/not enabled for this tenant yet/);
    expect((screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement).disabled).toBe(true);
    expect(state.prechecks).toHaveLength(0);
  });

  it('sources with no shared protocol cannot be issued together', () => {
    renderPanel([PA, { slug: 'k8s_logs', protocols: ['otlp_http'], enrolled: true }]);
    expect(screen.getByText(/share no protocol/)).toBeTruthy();
    expect((screen.getByRole('button', { name: /issue credential/i }) as HTMLButtonElement).disabled).toBe(true);
  });
});
