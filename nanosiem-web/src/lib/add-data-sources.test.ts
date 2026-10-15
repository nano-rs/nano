// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2593: the hosted-shared "Add data" source list and credential error copy. */
import { describe, expect, it } from 'vitest';
import type { LogSource, TenantIngestSource } from '@/lib/api/types';
import {
  ADD_DATA_PATH, addDataLink, addDataSources, defaultCredentialLabel, issuableSlugs, preselectedAddDataSource, protocolsFor, tokenLost,
} from './add-data-sources';
import { describeRefusal, refusalCode } from './ingest-credential-errors';

function row(partial: Partial<TenantIngestSource>): TenantIngestSource {
  return {
    credential_id: 'c', route_id: 'r', protocol: 'hec', label: 'route template: x', source_slug: 'x',
    credential_state: 'active', route_state: 'active', route_revision: 1, cell_name: 'cell', cell_state: 'ready',
    created_at: '2026-09-22T00:00:00Z', ...partial,
  };
}

function logSource(partial: Partial<LogSource>): LogSource {
  return { id: 'feed_1', name: 'n', deployed: true, enabled: true, validated: true, stale_alert_enabled: false,
    stale_threshold_minutes: 60, source_parser_linked: false, created_at: '', updated_at: '', ...partial } as LogSource;
}

describe('addDataSources (NAN-2593)', () => {
  it('lists enrolled route templates joined to registry entries, then sources still rolling out', () => {
    const endpoint = {
      sources: [
        row({ source_slug: 'palo_alto_traffic', label: 'route template: palo_alto_traffic', protocol: 'nano_https' }),
        row({ source_slug: 'palo_alto_traffic', label: 'route template: palo_alto_traffic', protocol: 'hec' }),
        row({ source_slug: 'okta', label: 'route template: okta', protocol: 'hec' }),
        // A tenant credential on an enrolled slug is not a template: it adds nothing.
        row({ source_slug: 'okta', label: 'okta-prod', protocol: 'nano_https' }),
        // Suspended templates are not offered.
        row({ source_slug: 'retired', label: 'route template: retired', route_state: 'suspended' }),
      ],
    };
    const registry = [
      logSource({ id: 'feed_pa', name: 'Palo Alto', ingest: { source_slugs: ['palo_alto_traffic'], events_last_24h: 1200, events_last_hour: 1, bytes_last_24h: 1, parse_failures_24h: 0, health_status: 'healthy' } }),
      logSource({ id: 'feed_custom', name: 'My app', match_values: ['my_app'] }),
      logSource({ id: 'feed_draft', name: 'Draft', lifecycle_status: 'draft', match_values: ['draft_app'] }),
    ];
    const out = addDataSources(endpoint, registry);
    expect(out.map((s) => [s.slug, s.enrolled, s.protocols.join('+')])).toEqual([
      ['okta', true, 'hec'],
      ['palo_alto_traffic', true, 'hec+nano_https'],
      ['my_app', false, ''],
    ]);
    expect(out[1].logSource?.id).toBe('feed_pa');
    expect(out[1].events24h).toBe(1200);
    expect(protocolsFor(out[2])).toEqual(['hec', 'nano_https']);
    expect(protocolsFor(out[0])).toEqual(['hec']);
  });

  it('builds a default label the server accepts', () => {
    expect(defaultCredentialLabel('palo_alto_traffic', 'nano_https')).toBe('palo_alto_traffic-nano-https');
    expect(defaultCredentialLabel('x'.repeat(200), 'hec').length).toBeLessThanOrEqual(128);
  });

  it('flags issued credentials whose token was never revealed within 10 minutes', () => {
    const base = { state: 'active', request_id: 'req', revealed_at: null, created_at: '2026-09-22T00:00:00Z' };
    const t0 = Date.parse('2026-09-22T00:00:00Z');
    expect(tokenLost(base, t0 + 5 * 60_000)).toBe(false);
    expect(tokenLost(base, t0 + 11 * 60_000)).toBe(true);
    expect(tokenLost({ ...base, revealed_at: '2026-09-22T00:01:00Z' }, t0 + 11 * 60_000)).toBe(false);
    expect(tokenLost({ ...base, request_id: null }, t0 + 11 * 60_000)).toBe(false); // app.nano.rs-issued
  });
});

describe('ingest credential refusal copy (NAN-2593)', () => {
  it('reads the reason code from 403/410 messages and dispositions', () => {
    expect(refusalCode('Forbidden: ingest_credential_refused: source_restricted')).toBe('source_restricted');
    expect(refusalCode('ingest_credential_refused: restricted_sources_unacknowledged')).toBe('restricted_sources_unacknowledged');
    expect(refusalCode('Forbidden: Tenant ingest credential request limit reached')).toBe('limit_reached');
    expect(refusalCode('Gone: already_revealed: the sealed ingest credential is no longer available')).toBe('already_revealed');
    expect(refusalCode('reveal_key_missing: request carried no reveal key')).toBe('reveal_key_missing');
    expect(refusalCode('Bad request: collector_unavailable: collector credentials are not available yet')).toBe('collector_unavailable');
    expect(refusalCode('something else')).toBe('unknown');
  });

  it('asks for the acknowledgement only where the user can give it', () => {
    expect(describeRefusal('restricted_sources_unacknowledged').needsAcknowledgement).toBe(true);
    expect(describeRefusal('mixed_restrictions_require_manage').needsAcknowledgement).toBe(true);
    expect(describeRefusal('source_restricted').needsAcknowledgement).toBeFalsy();
    expect(describeRefusal('mixed_restrictions_require_manage').detail).toMatch(/source_scopes:manage/);
    expect(describeRefusal('sealed_token_expired').terminal).toBe(true);
  });
});

describe('Add data deep link (NAN-2946)', () => {
  it('builds the wizard link with an encoded source, or the bare wizard', () => {
    expect(ADD_DATA_PATH).toBe('/ingestion/log-sources/wizard');
    expect(addDataLink('apache_access')).toBe('/ingestion/log-sources/wizard?source=apache_access');
    expect(addDataLink('a b&c')).toBe('/ingestion/log-sources/wizard?source=a%20b%26c');
    expect(addDataLink('  ')).toBe(ADD_DATA_PATH);
    expect(addDataLink(null)).toBe(ADD_DATA_PATH);
  });

  it('never offers issuance for the Unattributed labels', () => {
    expect(issuableSlugs(['unknown', 'okta', 'default', ''])).toEqual(['okta']);
    expect(issuableSlugs(undefined)).toEqual([]);
  });

  it('preselects only a listed, issuable source', () => {
    const sources = addDataSources({ sources: [row({ source_slug: 'okta', label: 'route template: okta' })] }, []);
    expect(preselectedAddDataSource(sources, 'okta')?.slug).toBe('okta');
    expect(preselectedAddDataSource(sources, ' okta ')?.slug).toBe('okta');
    expect(preselectedAddDataSource(sources, 'nope')).toBeNull();
    expect(preselectedAddDataSource(sources, 'unknown')).toBeNull();
    expect(preselectedAddDataSource(sources, null)).toBeNull();
  });
});
