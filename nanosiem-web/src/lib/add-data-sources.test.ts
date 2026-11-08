// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4922: the Add source list and links, re-backed on the ClickHouse product (main's NAN-2593 tests). */
import { describe, expect, it } from 'vitest';
import type { LogSource } from '@/lib/api/types';
import type { LogSourceConnectStatus } from '@/lib/api/log-source-connect';
import {
  ADD_DATA_PATH, addDataLink, addDataSources, defaultCredentialLabel, issuableSlugs, preselectedAddDataSource,
  protocolsFor, sourceOnboardingPermission,
} from './add-data-sources';

function logSource(partial: Partial<LogSource>): LogSource {
  return { id: 'lsrc_1', name: 'n', deployed: true, enabled: true, validated: true, source_type: 'routed',
    created_at: '', updated_at: '', ...partial } as LogSource;
}
function status(partial: Partial<LogSourceConnectStatus>): LogSourceConnectStatus {
  return { source_id: 'lsrc_1', route_key: 'x', state: 'receiving', deployed: true, lifecycle_status: 'active',
    push_capable: true, events_24h: 0, active_tokens: 0, ...partial };
}

it('requires edit for an existing source parser and create for other onboarding routes', () => {
  expect(sourceOnboardingPermission('?stage=parse&source_id=lsrc_existing')).toBe('log_sources:edit');
  for (const search of ['', '?stage=parse', '?stage=parse&source_id=', '?source_id=lsrc_existing', '?stage=connect&source_id=lsrc_existing']) {
    expect(sourceOnboardingPermission(search)).toBe('log_sources:create');
  }
});

describe('addDataSources', () => {
  it('keys sources by their connect route key, skips pull-only and unattributed keys, sorts by name', () => {
    const out = addDataSources(
      [
        logSource({ id: 'lsrc_b', name: 'Zeta app', match_values: ['zeta'] }),
        logSource({ id: 'lsrc_a', name: 'Apache', match_values: ['apache_old'] }),
        logSource({ id: 'lsrc_k', name: 'Kafka feed', match_values: ['kafka_feed'] }),
        logSource({ id: 'lsrc_u', name: 'Fallback', match_values: ['unknown'] }),
      ],
      [
        status({ source_id: 'lsrc_b', route_key: 'zeta', events_24h: 5, last_seen: '2026-11-03T00:00:00Z' }),
        status({ source_id: 'lsrc_a', route_key: 'apache_access' }),
        status({ source_id: 'lsrc_k', route_key: 'kafka_feed', push_capable: false }),
      ],
    );
    expect(out.map((s) => [s.slug, s.logSource?.id])).toEqual([['apache_access', 'lsrc_a'], ['zeta', 'lsrc_b']]);
    expect(out[1].events24h).toBe(5);
    expect(out[1].lastEventAt).toBe('2026-11-03T00:00:00Z');
    expect(protocolsFor(out[0])).toEqual(['hec', 'nano_https', 'otlp_http']);
  });

  it('falls back to the first match value when the status read failed', () => {
    const out = addDataSources([logSource({ match_values: ['okta'] })], undefined);
    expect(out.map((s) => s.slug)).toEqual(['okta']);
  });
});

describe('links', () => {
  it('preselects issuable slugs only', () => {
    expect(addDataLink('okta')).toBe(`${ADD_DATA_PATH}?source=okta`);
    expect(addDataLink('audit')).toBe(ADD_DATA_PATH);
    expect(addDataLink('unknown')).toBe(ADD_DATA_PATH);
    expect(addDataLink(null)).toBe(ADD_DATA_PATH);
    expect(issuableSlugs(['audit', 'default', 'okta', ''])).toEqual(['okta']);
  });

  it('resolves a ?source= deep link against the loaded list', () => {
    const sources = addDataSources([logSource({ match_values: ['okta'] })], [status({ route_key: 'okta' })]);
    expect(preselectedAddDataSource(sources, 'okta')?.logSource?.id).toBe('lsrc_1');
    expect(preselectedAddDataSource(sources, 'nope')).toBeNull();
    expect(preselectedAddDataSource(sources, 'default')).toBeNull();
  });

  it('names tokens <slug>-<protocol>', () => {
    expect(defaultCredentialLabel('okta', 'nano_https')).toBe('okta-nano-https');
    expect(defaultCredentialLabel('x'.repeat(200), 'hec')).toHaveLength(120);
  });
});
