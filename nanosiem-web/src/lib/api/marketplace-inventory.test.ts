// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4946: the dedicated inventory projection (catalog + custom enrichments, capability-gated). */
import { describe, expect, it } from 'vitest';
import type { Capabilities } from '@/hooks/use-capabilities';
import type { EnrichmentMarketplaceRepo, MarketplaceCatalogEntry } from './marketplace';
import { applyFeedBundle, buildInventory, bundleFeedForSlug, bundleProvisions, catalogItem, inventoryAction, inventoryReason, isFirstPartyRepo, platformFeedForEntry, syncPollInterval, SYNC_POLL_MAX_MS, SYNC_POLL_MS } from './marketplace-inventory';
import { executionStageLabel, humanizeEnum } from '../marketplace-labels';

const OPEN = { customEnrichment: false, agentEnrichment: false } as Capabilities;
const ENT = { customEnrichment: true, agentEnrichment: true } as Capabilities;

function entry(over: Partial<MarketplaceCatalogEntry>): MarketplaceCatalogEntry {
  return {
    id: 'e', slug: 'abuseipdb', name: 'AbuseIPDB', category: 'agent', tags: ['ip_reputation'], source_type: 'repository',
    repository_id: 'r1', manifest_version: 1, execution_backend: 'deno', installed: false, requires_credential: 'required',
    credential_fields: [], has_credentials: false, allowed_domains: [], config: {}, enabled: false, record_count: 0,
    created_at: '', updated_at: '', ...over,
  } as MarketplaceCatalogEntry;
}
const official = { id: 'r1', name: 'nano Enrichments', url: 'https://github.com/nano-rs/nano-enrichments' } as EnrichmentMarketplaceRepo;
const thirdParty = { id: 'r2', name: 'Acme', url: 'https://github.com/acme/marketplace' } as EnrichmentMarketplaceRepo;

describe('marketplace inventory projection', () => {
  it('classifies first-party vs third-party repository content', () => {
    expect(isFirstPartyRepo(official)).toBe(true);
    expect(isFirstPartyRepo({ url: 'https://github.com/nanos-sh/nano-enrichments' })).toBe(true);
    expect(isFirstPartyRepo(thirdParty)).toBe(false);
    for (const url of [
      'https://attacker.example/github.com/nano-rs/rules',
      'https://github.com.attacker.example/nano-rs/rules',
      'https://user:tok@github.com/nano-rs/rules',
      'https://github.com/nano-rs-evil/rules',
      'https://github.com/nano-rs/rules/tree/main',
      'http://github.com/nano-rs/rules',
      'https://github.com/nano-rs/rules?x=1',
      'not a url',
    ]) expect(isFirstPartyRepo({ url }), url).toBe(false);
    expect(isFirstPartyRepo(null)).toBe(false);
    // A repository entry whose repository metadata is missing is untrusted.
    expect(catalogItem(entry({}), [], ENT).kind).toBe('custom');
    expect(catalogItem(entry({}), [official, thirdParty], ENT).kind).toBe('platform');
    expect(catalogItem(entry({ repository_id: 'r2' }), [official, thirdParty], ENT).kind).toBe('custom');
  });

  it('gates deno and collector backends on build capabilities, never a hosted flag', () => {
    const agent = catalogItem(entry({}), [official], OPEN);
    expect(agent.requirement).toEqual({ capability: 'agentEnrichment', label: 'Enterprise edition' });
    expect(inventoryAction(agent)).toBe('Enterprise edition');
    expect(inventoryReason(agent)).toBe('Requires the Enterprise edition.');
    expect(catalogItem(entry({ category: 'collector', execution_backend: 'collector' }), [official], OPEN).requirement?.capability).toBe('customEnrichment');
    expect(catalogItem(entry({ execution_backend: 'native', category: 'data' }), [official], OPEN).requirement).toBeNull();
    expect(catalogItem(entry({}), [official], ENT).requirement).toBeNull();
  });

  it('derives install/enable state, reason and stage', () => {
    const available = catalogItem(entry({}), [official], ENT);
    expect(inventoryAction(available)).toBe('Install');
    expect(available.effective_health).toBe('available');
    expect(executionStageLabel(available.execution_stage)).toBe('On demand · pivt');
    const installed = catalogItem(entry({ installed: true, enabled: true, has_credentials: true }), [official], ENT);
    expect(inventoryAction(installed)).toBe('Disable');
    expect(installed.reason).toBeNull();
    const missing = catalogItem(entry({ installed: true, enabled: true }), [official], ENT);
    expect(missing.reason).toBe('missing_credentials');
    const feed = catalogItem(entry({ slug: 'tor', category: 'data', execution_backend: 'native', installed: true, enabled: true, requires_credential: 'none', last_sync_status: 'failed' }), [official], OPEN);
    expect(feed.reason).toBe('bundle_inactive');
    expect(inventoryAction(feed)).toBe('Feed bundle');
    expect(executionStageLabel(feed.execution_stage)).toBe('Built in · at ingest');
    expect(executionStageLabel(catalogItem(entry({ category: 'identity', execution_backend: 'identity' }), [], OPEN).execution_stage)).toBe('Directory sync');
  });

  it('lists a catalog-installed custom enrichment once', () => {
    const items = buildInventory(
      [entry({ installed: true, enabled: true, custom_enrichment_id: 'c1' })],
      [
        { id: 'c1', namespace_id: 'n', name: 'AbuseIPDB', description: null, enrichment_type: 'agent', enabled: true, status: 'active', last_run_at: null, last_run_status: null, created_at: '' },
        { id: 'c2', namespace_id: 'n', name: 'Asset CMDB', description: null, enrichment_type: 'data', enabled: true, status: 'draft', last_run_at: null, last_run_status: null, created_at: '' },
      ],
      [official], ENT,
    );
    expect(items.map(i => i.id)).toEqual(['abuseipdb', 'custom:c2']);
    expect(items[1]).toMatchObject({ kind: 'custom', reason: 'not_deployed', can_edit: true });
  });

  it('never renders a raw snake_case enum', () => {
    for (const v of ['identity_directory_sync', 'scheduled_pull', 'some_new_value']) {
      expect(executionStageLabel(v)).not.toMatch(/\b[a-z0-9]+(?:_[a-z0-9]+)+\b/);
      expect(humanizeEnum(v)).not.toMatch(/_/);
    }
  });
});

describe('catalog sync polling', () => {
  it('polls while syncing, stops after two minutes, and re-arms for the next sync', () => {
    const started = { current: null as number | null };
    expect(syncPollInterval(true, started, 1_000)).toBe(SYNC_POLL_MS);
    expect(syncPollInterval(true, started, 1_000 + SYNC_POLL_MAX_MS - 1)).toBe(SYNC_POLL_MS);
    expect(syncPollInterval(true, started, 1_000 + SYNC_POLL_MAX_MS)).toBe(false);
    expect(syncPollInterval(false, started, 500_000)).toBe(false);
    expect(started.current).toBeNull();
    expect(syncPollInterval(true, started, 600_000)).toBe(SYNC_POLL_MS);
  });
});

describe('platform feed bundle (NAN-4948)', () => {
  const status = {
    available: true, installed: true, bundle_sha256: 'ab', source: 'online', installed_at: null, stale_after_days: 7, notice: null,
    feeds: [
      { feed_id: 'tor_exit_nodes', name: 'Tor', revision: 4, produced_at: '2026-11-03T00:00:00Z', hard_expiry: '2026-11-10T00:00:00Z', age_seconds: 60, state: 'fresh' as const, license_id: null, terms_revision: null, records: 1200, active: true, loaded: 1200 },
      { feed_id: 'threatfox', name: 'ThreatFox', revision: 9, produced_at: null, hard_expiry: '2026-11-01T00:00:00Z', age_seconds: null, state: 'expired' as const, license_id: null, terms_revision: null, records: 10, active: false },
    ],
  };
  it('marks covered cards, clears the edition requirement, and leaves others alone', () => {
    const items = [
      catalogItem(entry({ slug: 'tor-exit-nodes', category: 'data', requires_credential: 'none' }), [official], OPEN),
      catalogItem(entry({ slug: 'threatfox', category: 'data' }), [official], OPEN),
      catalogItem(entry({}), [official], OPEN),
    ];
    const [tor, fox, abuse] = applyFeedBundle(items, status);
    expect(tor.provided_by_bundle).toMatchObject({ feed_id: 'tor_exit_nodes', revision: 4, active: true });
    expect(tor.requirement).toBeNull();
    expect(inventoryAction(tor)).toBe('Feed bundle');
    expect(inventoryReason(tor)).toMatch(/nano feed bundle/);
    expect(tor.record_count).toBe(1200);
    expect(fox.reason).toBe('bundle_inactive');
    expect(abuse.provided_by_bundle).toBeUndefined();
    expect(abuse.requirement?.label).toBe('Enterprise edition');
  });
  it('marks bundle-only feeds not installed without an installed bundle, and leaves other cards alone (NAN-4959)', () => {
    const items = [catalogItem(entry({ slug: 'threatfox', category: 'data' }), [official], OPEN), catalogItem(entry({}), [official], OPEN)];
    const [fox, abuse] = applyFeedBundle(items, { ...status, installed: false });
    expect(fox.provided_by_bundle).toMatchObject({ feed_id: 'threatfox', revision: null, state: 'not_installed' });
    expect(fox.requirement).toBeNull();
    expect(abuse).toBe(items[1]);
    expect(applyFeedBundle(items, undefined)).toBe(items);
  });
});

describe('IPinfo Lite is bundle-only (NAN-4959)', () => {
  const base = {
    available: true, installed: true, bundle_sha256: 'ab', source: 'online', installed_at: '2026-11-04T08:00:00Z', stale_after_days: 7, notice: null,
    auto_update: true, next_check_at: '2026-11-04T10:00:00Z', channel: 'open',
    feeds: [
      { feed_id: 'ipinfo_lite', name: 'IPinfo Lite', revision: 12, produced_at: '2026-11-04T07:00:00Z', hard_expiry: '2026-11-20T00:00:00Z', age_seconds: 60, state: 'fresh' as const, license_id: null, terms_revision: null, records: 500, active: true, loaded: 480 },
    ],
  };
  const ipinfo = () => catalogItem(entry({ slug: 'ipinfo_lite', category: 'data', execution_backend: 'native', native_source_id: 'ipinfo_lite' }), [official], OPEN);

  it('carries revision, last update and next refresh from the platform feed status', () => {
    const [item] = applyFeedBundle([ipinfo()], base);
    expect(item.provided_by_bundle).toMatchObject({
      feed_id: 'ipinfo_lite', revision: 12, state: 'fresh', active: true,
      produced_at: '2026-11-04T07:00:00Z', installed_at: '2026-11-04T08:00:00Z', next_check_at: '2026-11-04T10:00:00Z', auto_update: true,
    });
    expect(item.record_count).toBe(480);
    expect(item.reason).toBeNull();
  });

  it('reads as bundle-provided before any bundle is installed, with no stale native counts', () => {
    const stale = { ...ipinfo(), last_sync: '2026-01-01T00:00:00Z', record_count: 3_000_000 };
    const [item] = applyFeedBundle([stale], { ...base, installed: false, feeds: [], installed_at: null });
    expect(item.provided_by_bundle).toMatchObject({ feed_id: 'ipinfo_lite', revision: null, state: 'not_installed', active: false });
    expect(item.reason).toBe('bundle_inactive');
    expect(item.last_sync).toBeNull();
    expect(item.record_count).toBeNull();
    expect(inventoryAction(item)).toBe('Feed bundle');
  });

  it('marks IPinfo not carried when the installed bundle omits it', () => {
    const torOnly = { ...base, feeds: [{ ...base.feeds[0], feed_id: 'tor_exit_nodes', name: 'Tor' }] };
    expect(bundleProvisions(torOnly).get('ipinfo_lite')).toMatchObject({ revision: null, state: 'not_installed' });
  });

  it('is unchanged where the status is unavailable', () => {
    const items = [ipinfo()];
    expect(applyFeedBundle(items, { ...base, available: false })).toBe(items);
    expect(applyFeedBundle(items, null)).toBe(items);
  });
});

describe('bundle feed slugs (NAN-4959)', () => {
  it('maps the server aliases and nothing else', () => {
    expect(bundleFeedForSlug('ipinfo-lite')).toBe('ipinfo_lite');
    expect(bundleFeedForSlug('ThreatFox')).toBe('threatfox');
    expect(bundleFeedForSlug('tor')).toBe('tor_exit_nodes');
    expect(bundleFeedForSlug('tor-exit-nodes')).toBe('tor_exit_nodes');
    expect(bundleFeedForSlug('urlhaus')).toBeNull();
  });

  it('honors explicit API ownership before feed status is available', () => {
    const owned = catalogItem(entry({
      slug: 'catalog-tor',
      platform_feed_id: 'tor_exit_nodes',
      category: 'data',
    }), [official], OPEN);

    expect(platformFeedForEntry(owned.entry!)).toBe('tor_exit_nodes');
    expect(owned.provided_by_bundle).toMatchObject({ feed_id: 'tor_exit_nodes' });
    expect(owned.requirement).toBeNull();
    expect(owned.can_toggle).toBe(false);
    expect(inventoryAction(owned)).toBe('Feed bundle');
  });
});
