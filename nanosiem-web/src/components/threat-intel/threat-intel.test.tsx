// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** On-demand threat-intel enrichment: type mapping, origin labels, the
    EnrichSheet host, case-notebook citations and the pivt `@enrich` command. */
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { CapabilitiesContext, type CapabilitiesContextValue } from '@/hooks/use-capabilities';
import type { IndicatorLookupResponse, ThreatIntelLookupResponse } from '@/lib/api/threat-intel';

const lookup = vi.fn();
const lookupIndicators = vi.fn();
const listProviders = vi.fn();
const configureProvider = vi.fn();
vi.mock('@/lib/api', () => ({
  api: {
    threatIntel: {
      lookup: (...a: unknown[]) => lookup(...a),
      lookupIndicators: (...a: unknown[]) => lookupIndicators(...a),
      listProviders: (...a: unknown[]) => listProviders(...a),
      configureProvider: (...a: unknown[]) => configureProvider(...a),
      uninstallProvider: vi.fn(),
    },
  },
}));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasAllPermissions: () => true }) }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
vi.mock('@/contexts/PageContext', () => ({ usePageContext: () => ({ pageKey: 'search' }) }));

import { detectArtifactType, enrichTypeFor, ENRICH_ARTIFACT_EVENT, openEnrich } from './enrich-event';
import { citationToResponse, originLabel } from './format';
import { EnrichSheetHost } from './EnrichSheet';
import { ThreatIntelResults } from './ThreatIntelResults';
import { useEnrichEnabled, useThreatIntelEnabled } from './use-threat-intel';
import { IndicatorResults } from './IndicatorResults';
import { indicatorMissText } from './format';
import { ThreatIntelProvidersSection } from './ThreatIntelProviders';
import { usePivtCommands } from '@/enterprise/components/pivt/commands/router';

function caps(opts: { shared?: boolean; agent?: boolean; perms?: string[] } = {}): CapabilitiesContextValue {
  const { shared = true, agent = true, perms = ['enrichments:view', 'search:execute'] } = opts;
  return {
    edition: 'enterprise',
    version: 'test',
    capabilities: { agentEnrichment: agent } as CapabilitiesContextValue['capabilities'],
    tenantPlan: shared
      ? ({ identity: { userId: 'member-1', roles: [], permissions: perms, authorizationRevision: 1 } } as unknown as CapabilitiesContextValue['tenantPlan'])
      : undefined,
  };
}

function wrapper(value: CapabilitiesContextValue) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => (
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <CapabilitiesContext.Provider value={value}>{children}</CapabilitiesContext.Provider>
      </QueryClientProvider>
    </MemoryRouter>
  );
}

const vt = (over: Partial<ThreatIntelLookupResponse> = {}): ThreatIntelLookupResponse => ({
  artifact: '44d88612fea8a8f36de82e1278abb02f',
  artifact_type: 'hash',
  origin: 'pivt',
  availability: 'available',
  verdict: 'malicious',
  score: 86,
  results: [
    {
      provider: 'virustotal',
      provider_name: 'VirusTotal',
      status: 'cached',
      verdict: 'malicious',
      score: 86,
      link: 'https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f',
      tags: ['eicar'],
      summary: {},
      fetched_at: null,
      cached_at: new Date().toISOString(),
      expires_at: null,
      quota_reason: null,
      retry_after_secs: null,
      message: null,
    },
    {
      provider: 'malwarebazaar',
      provider_name: 'MalwareBazaar',
      status: 'quota_exhausted',
      verdict: null,
      score: null,
      link: null,
      tags: [],
      summary: {},
      fetched_at: null,
      cached_at: null,
      expires_at: null,
      quota_reason: 'local_minute_limit',
      retry_after_secs: 50,
      message: null,
    },
  ],
  ...over,
});

// jsdom lacks ResizeObserver (Radix Switch measures itself).
if (!('ResizeObserver' in globalThis)) {
  (globalThis as Record<string, unknown>).ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
}

const iocs = (over: Partial<IndicatorLookupResponse> = {}): IndicatorLookupResponse => ({
  artifact: '185.220.101.1',
  artifact_type: 'ip',
  source_count: 3,
  source_names: ['Custom IOC list', 'ThreatFox', 'Tor exit nodes'],
  sources: [],
  ...over,
});

const iocHit = (): IndicatorLookupResponse =>
  iocs({
    sources: [
      {
        source: 'Tor exit nodes',
        matches: [
          { ioc_type: 'ip', threat_type: 'anonymizer', malware: null, confidence: 90, first_seen_at: null, last_seen_at: new Date().toISOString(), tags: ['tor', 'exit'] },
        ],
      },
      {
        source: 'Custom IOC list',
        matches: [
          { ioc_type: 'ip', threat_type: null, malware: null, confidence: 70, first_seen_at: null, last_seen_at: null, tags: ['watchlist'] },
        ],
      },
    ],
  });

beforeEach(() => {
  lookup.mockReset();
  lookupIndicators.mockReset();
  listProviders.mockReset();
  configureProvider.mockReset();
});
afterEach(cleanup);

describe('artifact type mapping', () => {
  it('detects hashes, URLs, IPs and domains from the value', () => {
    expect(detectArtifactType('44d88612fea8a8f36de82e1278abb02f')).toBe('hash');
    expect(detectArtifactType('https://evil.example.com/x')).toBe('url');
    expect(detectArtifactType('185.220.101.1')).toBe('ip');
    expect(detectArtifactType('evil.example.com')).toBe('domain');
    expect(detectArtifactType('bob wilson')).toBe(null);
    expect(detectArtifactType('WORKSTATION-01')).toBe(null);
  });

  it('only offers Enrich where the kind and value agree', () => {
    expect(enrichTypeFor('ip', '185.220.101.1')).toBe('ip');
    expect(enrichTypeFor('ip', 'not-an-ip')).toBe(null);
    expect(enrichTypeFor('hash_sha256', 'a'.repeat(64))).toBe('hash');
    expect(enrichTypeFor('subdomain', 'cdn.evil.example.com')).toBe('domain');
    expect(enrichTypeFor('ip_address_private', '10.0.0.1')).toBe(null);
    expect(enrichTypeFor('user', 'a'.repeat(32))).toBe(null);
    expect(enrichTypeFor('identity', 'bob')).toBe(null);
    // Generic field: only unambiguous values.
    expect(enrichTypeFor(null, 'a'.repeat(40))).toBe('hash');
    expect(enrichTypeFor(null, 'evil.example.com')).toBe(null);
  });

  it('labels the result origin', () => {
    expect(originLabel('pivt')).toBe('On demand · pivt');
    expect(originLabel('analyst')).toBe('On demand');
    expect(originLabel('auto_investigation')).toBe('Auto-investigation');
  });
});

describe('useThreatIntelEnabled', () => {
  it('is on only for shared tenants with agent enrichment and enrichments:view', () => {
    const on = (v: CapabilitiesContextValue) => renderHook(() => useThreatIntelEnabled(), { wrapper: wrapper(v) }).result.current;
    expect(on(caps())).toBe(true);
    expect(on(caps({ shared: false }))).toBe(false);
    expect(on(caps({ agent: false }))).toBe(false);
    expect(on(caps({ perms: ['search:execute'] }))).toBe(false);
    // Outside any provider (tests, embeds) it is simply off, never a throw.
    expect(renderHook(() => useThreatIntelEnabled()).result.current).toBe(false);
  });
});

describe('useEnrichEnabled', () => {
  it('is on for shared members who can search indicator sets or use external providers', () => {
    const on = (v: CapabilitiesContextValue) => renderHook(() => useEnrichEnabled(), { wrapper: wrapper(v) }).result.current;
    expect(on(caps())).toBe(true);
    expect(on(caps({ agent: false }))).toBe(true);
    expect(on(caps({ shared: false }))).toBe(false);
    expect(on(caps({ perms: ['search:execute'] }))).toBe(false);
    // enrichments:view alone: external providers only, so only with the add-on.
    expect(on(caps({ perms: ['enrichments:view'] }))).toBe(true);
    expect(on(caps({ agent: false, perms: ['enrichments:view'] }))).toBe(false);
    expect(renderHook(() => useEnrichEnabled()).result.current).toBe(false);
  });
});

describe('IndicatorResults', () => {
  it('groups matches by source with mono feed names, type, confidence and tags', () => {
    render(<IndicatorResults response={iocHit()} />);
    const groups = screen.getByTestId('ioc-results').querySelectorAll('[data-source]');
    expect(Array.from(groups).map((g) => g.getAttribute('data-source'))).toEqual(['Tor exit nodes', 'Custom IOC list']);
    expect(screen.getByText('Tor exit nodes').className).toContain('font-mono');
    expect(screen.getByText('conf 90').parentElement?.className).toContain('font-mono');
    expect(screen.getByText('tor · exit')).toBeTruthy();
    expect(screen.getByText('anonymizer')).toBeTruthy();
  });

  it('says how many sources were searched when nothing matches', () => {
    render(<IndicatorResults response={iocs()} />);
    expect(screen.getByTestId('ioc-no-match').textContent).toBe('No matches in 3 indicator sources');
    expect(indicatorMissText(1)).toBe('No matches in 1 indicator source');
    expect(indicatorMissText(0)).toBe('No indicator sources published yet');
    expect(indicatorMissText(null)).toBe('No matches in your indicator sources');
  });
});

describe('ThreatIntelResults', () => {
  it('renders provider rows with mono score, https link, cached and quota states', () => {
    render(<ThreatIntelResults response={vt()} />);
    const link = screen.getByRole('link', { name: 'VirusTotal' });
    expect(link.getAttribute('href')).toMatch(/^https:\/\/www\.virustotal\.com\//);
    expect(link.getAttribute('rel')).toContain('noopener');
    expect(screen.getByText('86').className).toContain('font-mono');
    expect(screen.getByText(/^cached /)).toBeTruthy();
    expect(screen.getByText('quota exhausted · retry in 50s')).toBeTruthy();
  });

  it('never links a non-https provider URL', () => {
    const r = vt();
    r.results[0].link = 'javascript:alert(1)';
    render(<ThreatIntelResults response={r} />);
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('is a one-line hint, not an error, when no external provider is installed', () => {
    render(<ThreatIntelResults response={vt({ availability: 'no_provider_configured', results: [], verdict: null, score: null })} />);
    const hint = screen.getByTestId('ti-no-provider');
    expect(hint.textContent).toContain('No external provider installed');
    expect(hint.textContent).not.toContain('No threat-intel provider is configured');
    expect(hint.tagName).toBe('P');
  });
});

describe('EnrichSheetHost', () => {
  it('runs the lookup for an Enrich event and labels pivt results', async () => {
    lookup.mockResolvedValue(vt());
    lookupIndicators.mockResolvedValue(iocs({ artifact: '44d88612fea8a8f36de82e1278abb02f', artifact_type: 'hash' }));
    render(<EnrichSheetHost />, { wrapper: wrapper(caps()) });
    act(() => openEnrich({ artifact: ' 44d88612fea8a8f36de82e1278abb02f ', artifactType: 'hash', origin: 'pivt' }));
    await waitFor(() => expect(screen.getByTestId('ti-results')).toBeTruthy());
    expect(lookup).toHaveBeenCalledWith({
      artifact: '44d88612fea8a8f36de82e1278abb02f',
      artifact_type: 'hash',
      origin: 'pivt',
      force_refresh: false,
    });
    expect(screen.getByTestId('ti-origin').textContent).toContain('On demand · pivt');
    expect(lookupIndicators).toHaveBeenCalledWith({ artifact: '44d88612fea8a8f36de82e1278abb02f', artifact_type: 'hash' });
  });

  it('NAN-3881: searches the tenant indicator sets even with no external provider, and shows the hit', async () => {
    lookup.mockResolvedValue(vt({ availability: 'no_provider_configured', results: [], verdict: null, score: null, artifact_type: 'ip' }));
    lookupIndicators.mockResolvedValue(iocHit());
    render(<EnrichSheetHost />, { wrapper: wrapper(caps()) });
    act(() => openEnrich({ artifact: '185.220.101.1', artifactType: 'ip' }));
    await waitFor(() => expect(screen.getByTestId('ioc-results')).toBeTruthy());
    await waitFor(() => expect(screen.getByTestId('ti-no-provider')).toBeTruthy());
    expect(screen.getByTestId('ti-ioc-count').textContent).toBe('2 indicator matches');
    // The old error-state copy and the permanent explanatory paragraph are gone;
    // the explanation lives behind the info tooltip trigger.
    expect(screen.queryByText(/No threat-intel provider is configured/)).toBeNull();
    expect(screen.queryByText(/Each external lookup is audited/)).toBeNull();
    expect(screen.getByTestId('ti-about').getAttribute('aria-label')).toBe('About these results');
  });

  it('reports a miss against the number of indicator sources searched', async () => {
    lookup.mockResolvedValue(vt({ availability: 'no_provider_configured', results: [], verdict: null, score: null }));
    lookupIndicators.mockResolvedValue(iocs());
    render(<EnrichSheetHost />, { wrapper: wrapper(caps()) });
    act(() => openEnrich({ artifact: '185.220.101.1', artifactType: 'ip' }));
    await waitFor(() => expect(screen.getByTestId('ioc-no-match').textContent).toBe('No matches in 3 indicator sources'));
  });

  it('without the agent-enrichment add-on: indicator sets only, no external call', async () => {
    lookupIndicators.mockResolvedValue(iocHit());
    render(<EnrichSheetHost />, { wrapper: wrapper(caps({ agent: false })) });
    act(() => openEnrich({ artifact: '185.220.101.1', artifactType: 'ip' }));
    await waitFor(() => expect(screen.getByTestId('ioc-results')).toBeTruthy());
    expect(lookup).not.toHaveBeenCalled();
    expect(screen.queryByTestId('ti-external')).toBeNull();
  });

  it('without search:execute: external providers only, no indicator call', async () => {
    lookup.mockResolvedValue(vt());
    render(<EnrichSheetHost />, { wrapper: wrapper(caps({ perms: ['enrichments:view'] })) });
    act(() => openEnrich({ artifact: '44d88612fea8a8f36de82e1278abb02f', artifactType: 'hash' }));
    await waitFor(() => expect(screen.getByTestId('ti-results')).toBeTruthy());
    expect(lookupIndicators).not.toHaveBeenCalled();
    expect(screen.queryByTestId('ti-indicators')).toBeNull();
  });

  it('an external refusal (internal value) does not hide indicator matches', async () => {
    lookup.mockRejectedValue(new Error('private IPs are never sent out'));
    lookupIndicators.mockResolvedValue(iocHit());
    render(<EnrichSheetHost />, { wrapper: wrapper(caps()) });
    act(() => openEnrich({ artifact: '10.0.0.5', artifactType: 'ip' }));
    await waitFor(() => expect(screen.getByTestId('ti-external-error')).toBeTruthy());
    expect(screen.getByTestId('ioc-results')).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('ignores Enrich events where threat intel is unavailable', () => {
    render(<EnrichSheetHost />, { wrapper: wrapper(caps({ shared: false })) });
    act(() => {
      window.dispatchEvent(new CustomEvent(ENRICH_ARTIFACT_EVENT, { detail: { artifact: '1.1.1.1' } }));
    });
    expect(lookup).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});

describe('case notebook citation', () => {
  it('maps an ioc_marker threat_intel entry to provider rows', () => {
    const r = citationToResponse({
      kind: 'threat_intel',
      entity_type: 'hash',
      value: '44d88612fea8a8f36de82e1278abb02f',
      verdict: 'malicious',
      score: 86,
      origin: 'auto_investigation',
      citations: [
        { provider: 'virustotal', provider_name: 'VirusTotal', status: 'cached', verdict: 'malicious', score: 86, link: 'https://www.virustotal.com/gui/file/x', cached_at: '2026-10-13T12:00:00Z', tags: ['eicar'] },
        { provider: 'abuseipdb', provider_name: 'AbuseIPDB', status: 'quota_exhausted', reason: 'provider_quota' },
      ],
    });
    expect(r.results.map((p) => [p.provider_name, p.status])).toEqual([
      ['VirusTotal', 'cached'],
      ['AbuseIPDB', 'quota_exhausted'],
    ]);
    expect(r.results[1].quota_reason).toBe('provider_quota');
    expect(r.origin).toBe('auto_investigation');
    expect(citationToResponse({ kind: 'threat_intel', citations: [] }).availability).toBe('no_provider_configured');
  });
});

describe('pivt @enrich', () => {
  it('opens the enrich sheet with origin pivt', () => {
    const seen: unknown[] = [];
    const on = (e: Event) => seen.push((e as CustomEvent).detail);
    window.addEventListener(ENRICH_ARTIFACT_EVENT, on);
    const { result } = renderHook(() => usePivtCommands(), { wrapper: wrapper(caps()) });
    expect(result.current.dispatch('@enrich 185.220.101.1 please').action).toBe('enrich');
    window.removeEventListener(ENRICH_ARTIFACT_EVENT, on);
    expect(seen).toEqual([{ artifact: '185.220.101.1', origin: 'pivt' }]);
  });

  it('explains when threat intel is unavailable', () => {
    const { result } = renderHook(() => usePivtCommands(), { wrapper: wrapper(caps({ perms: ['search:execute'] })) });
    expect(result.current.dispatch('@enrich 185.220.101.1').action).toBe('enrich (threat intel unavailable)');
  });
});

describe('marketplace threat-intel providers', () => {
  const vtProvider = {
    provider: 'virustotal',
    name: 'VirusTotal',
    description: 'File, domain, IP and URL reputation.',
    homepage: null,
    artifact_types: ['hash', 'domain', 'ip', 'url'],
    credential_fields: [{ name: 'API_KEY', label: 'API key', required: true, set: false }],
    installed: false,
    enabled: false,
    ready: false,
    defaults: { per_minute: 4, per_day: 500, cache_ttl_secs: 86400 },
    effective: { per_minute: 4, per_day: 500, cache_ttl_secs: 86400 },
    usage: { this_minute: 0, today: 0 },
    updated_at: null,
  };

  it('installs a provider with a write-only key and leaves untouched limits at their defaults', async () => {
    listProviders.mockResolvedValue({ providers: [vtProvider] });
    configureProvider.mockResolvedValue({ ...vtProvider, installed: true, enabled: true, ready: true });
    render(<ThreatIntelProvidersSection />, { wrapper: wrapper(caps()) });
    fireEvent.click(await screen.findByText('VirusTotal'));
    const key = await screen.findByLabelText('API key');
    expect(key.getAttribute('type')).toBe('password');
    fireEvent.change(key, { target: { value: 'vt-key-123' } });
    fireEvent.click(screen.getByRole('button', { name: 'Install' }));
    await waitFor(() => expect(configureProvider).toHaveBeenCalled());
    expect(configureProvider).toHaveBeenCalledWith('virustotal', {
      enabled: true,
      credentials: { API_KEY: 'vt-key-123' },
      per_minute: undefined,
      per_day: undefined,
      cache_ttl_secs: undefined,
    });
  });

  it('is hidden where threat intel is unavailable', () => {
    render(<ThreatIntelProvidersSection />, { wrapper: wrapper(caps({ shared: false })) });
    expect(listProviders).not.toHaveBeenCalled();
    expect(screen.queryByText('Threat intel lookups')).toBeNull();
  });
});
