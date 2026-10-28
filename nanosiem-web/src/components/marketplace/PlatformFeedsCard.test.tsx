// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4759: self-hosted platform feed freshness on the marketplace.
import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import '../../test/marketplace-dom';
import type { PlatformFeedsStatus } from '../../lib/api/enrichment';
const { cleanup, render } = await import('@testing-library/react');
const { PlatformFeedsCard } = await import('./PlatformFeedsCard');

afterEach(cleanup);

const base: PlatformFeedsStatus = {
  available: true, installed: true, bundle_sha256: 'ab'.repeat(32), source: 'portable',
  installed_at: '2026-10-28T10:00:00Z', stale_after_days: 7, notice: 'IPinfo Lite data, CC BY-SA 4.0, ipinfo.io', feeds: [
    { feed_id: 'ipinfo_lite', name: 'IPinfo Lite', revision: 41, produced_at: '2026-10-28T09:00:00Z', hard_expiry: '2026-11-27T09:00:00Z',
      age_seconds: 3600, state: 'fresh', license_id: 'CC-BY-SA-4.0', terms_revision: '2025-01', records: 1 },
    { feed_id: 'threatfox', name: 'ThreatFox', revision: 9, produced_at: '2026-10-18T09:00:00Z', hard_expiry: '2026-11-01T09:00:00Z',
      age_seconds: 864000, state: 'stale', license_id: 'CC0-1.0', terms_revision: '1', records: 120 },
    { feed_id: 'tor_exit_nodes', name: 'Tor exit nodes', revision: 3, produced_at: '2026-09-01T09:00:00Z', hard_expiry: '2026-10-01T09:00:00Z',
      age_seconds: 4924800, state: 'expired', license_id: 'public', terms_revision: '1', records: 1200 },
  ],
};

test('renders every feed with its state, revision and the attribution notice', () => {
  const { getByTestId } = render(<PlatformFeedsCard status={base} />);
  for (const [id, state] of [['ipinfo_lite', 'fresh'], ['threatfox', 'stale'], ['tor_exit_nodes', 'expired']]) {
    const row = getByTestId(`platform-feed-${id}`);
    assert.match(row.textContent ?? '', new RegExp(state));
  }
  assert.match(getByTestId('platform-feed-ipinfo_lite').textContent ?? '', /41/);
  assert.match(getByTestId('platform-feeds-notice').textContent ?? '', /CC BY-SA 4\.0/);
  assert.match(getByTestId('platform-feeds-card').textContent ?? '', /scripts\/nano feeds update/);
});

test('no installed bundle says new events are not stamped', () => {
  const { getByTestId } = render(<PlatformFeedsCard status={{ ...base, installed: false, feeds: [], notice: null, bundle_sha256: null }} />);
  assert.match(getByTestId('platform-feeds-card').textContent ?? '', /No feed bundle installed/);
});

test('unavailable (hosted, ClickHouse) renders nothing', () => {
  const { container } = render(<PlatformFeedsCard status={{ ...base, available: false }} />);
  assert.equal(container.innerHTML, '');
  const empty = render(<PlatformFeedsCard status={null} />);
  assert.equal(empty.container.innerHTML, '');
});
