// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4759 / NAN-4948: platform feed bundle status card.
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@testing-library/react';
import type { PlatformFeedsStatus } from '@/lib/api/enrichment';
import { PlatformFeedsCard } from './PlatformFeedsCard';

afterEach(cleanup);

const base: PlatformFeedsStatus = {
  available: true, installed: true, bundle_sha256: 'ab'.repeat(32), source: 'online',
  installed_at: '2026-11-03T18:10:00Z', stale_after_days: 7, notice: 'IPinfo Lite data, CC BY-SA 4.0, ipinfo.io',
  sequence: 1793728874855, channel: 'open', auto_update: true, last_check_at: '2026-11-03T19:00:00Z',
  last_check_status: 'current', last_error: null, last_error_at: null,
  feeds: [
    { feed_id: 'ipinfo_lite', name: 'IPinfo Lite', revision: 7, produced_at: '2026-10-29T00:00:11Z', hard_expiry: '2026-11-11T08:01:57Z',
      age_seconds: 3600, state: 'fresh', license_id: 'CC-BY-SA-4.0', terms_revision: 'r', records: 4376565, active: true, loaded: 4376565, detail: null },
    { feed_id: 'threatfox', name: 'ThreatFox', revision: 169, produced_at: '2026-10-18T09:00:00Z', hard_expiry: '2026-11-04T17:51:24Z',
      age_seconds: 864000, state: 'stale', license_id: 'CC0-1.0', terms_revision: '1', records: 129135, active: true, loaded: 128000, detail: null },
    { feed_id: 'tor_exit_nodes', name: 'Tor exit nodes', revision: 3, produced_at: '2026-09-01T09:00:00Z', hard_expiry: '2026-10-01T09:00:00Z',
      age_seconds: 4924800, state: 'expired', license_id: 'public', terms_revision: '1', records: 1200, active: false, loaded: 1200,
      detail: 'Past its hard expiry: no longer stamps new events. Update the feed bundle.' },
  ],
};

it('renders every feed with its state, revision, loaded rows and the attribution notice', () => {
  const { getByTestId } = render(<PlatformFeedsCard status={base} />);
  for (const [id, state] of [['ipinfo_lite', 'fresh'], ['threatfox', 'stale'], ['tor_exit_nodes', 'expired']]) {
    expect(getByTestId(`platform-feed-${id}`).textContent).toMatch(new RegExp(state));
  }
  expect(getByTestId('platform-feed-ipinfo_lite').textContent).toMatch(/4376565/);
  expect(getByTestId('platform-feed-tor_exit_nodes').textContent).toMatch(/hard expiry/);
  expect(getByTestId('platform-feeds-notice').textContent).toMatch(/CC BY-SA 4\.0/);
  expect(getByTestId('platform-feeds-card').textContent).toMatch(/nano open feed/);
});

it('an inactive, unexpired feed says why it is not stamping', () => {
  const status = { ...base, feeds: [{ ...base.feeds[0], active: false, detail: 'Your own IPinfo token is configured.' }] };
  const { getByTestId } = render(<PlatformFeedsCard status={status} />);
  expect(getByTestId('platform-feed-ipinfo_lite').textContent).toMatch(/not stamping/);
  expect(getByTestId('platform-feed-ipinfo_lite').textContent).toMatch(/IPinfo token/);
});

it('a refused check shows the error and that the installed bundle is kept', () => {
  const status = { ...base, last_check_status: 'refused', last_error: 'feed bundle refused: feed bundle signature is invalid' };
  const { getByTestId } = render(<PlatformFeedsCard status={status} />);
  expect(getByTestId('platform-feeds-error').textContent).toMatch(/signature is invalid/);
  expect(getByTestId('platform-feeds-error').textContent).toMatch(/still in use/);
});

it('check and import call back; checking disables them; air-gap hides check', () => {
  const onCheck = vi.fn();
  const onImport = vi.fn();
  const { getByTestId, rerender, queryByTestId } = render(<PlatformFeedsCard status={base} onCheck={onCheck} onImport={onImport} />);
  fireEvent.click(getByTestId('platform-feeds-check'));
  expect(onCheck).toHaveBeenCalledTimes(1);
  const file = new File(['NANFEED1'], 'bundle.nanfeed');
  fireEvent.change(getByTestId('platform-feeds-file'), { target: { files: [file] } });
  expect(onImport).toHaveBeenCalledWith(file);
  rerender(<PlatformFeedsCard status={{ ...base, last_check_status: 'checking' }} onCheck={onCheck} onImport={onImport} />);
  expect((getByTestId('platform-feeds-check') as HTMLButtonElement).disabled).toBe(true);
  rerender(<PlatformFeedsCard status={{ ...base, auto_update: false }} onCheck={onCheck} onImport={onImport} />);
  expect(queryByTestId('platform-feeds-check')).toBeNull();
  expect(getByTestId('platform-feeds-card').textContent).toMatch(/import a bundle file/);
});

it('no installed bundle says new events are not stamped; unavailable renders nothing', () => {
  const { getByTestId } = render(<PlatformFeedsCard status={{ ...base, installed: false, feeds: [], notice: null, bundle_sha256: null }} />);
  expect(getByTestId('platform-feeds-card').textContent).toMatch(/No feed bundle installed/);
  cleanup();
  const { container } = render(<PlatformFeedsCard status={{ ...base, available: false }} />);
  expect(container.innerHTML).toBe('');
});
