// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4759 / NAN-4948: platform feed bundle status card.
// NAN-5087: dense layout; explanations and per-feed attribution behind tooltips/popovers.
import { afterEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { PlatformFeedsStatus } from '@/lib/api/enrichment';
import { parseFeedNotice } from '@/lib/platform-feed-notice';
import { PlatformFeedsCard } from './PlatformFeedsCard';

afterEach(cleanup);

// Verbatim shape of `notice_for` (nanosiem-core/src/platform_enrichment/portable.rs).
const NOTICE = `NOTICE: nano enrichment feed bundle. Third-party data, redistributed under the terms below.

[ipinfo_lite] CC-BY-SA-4.0
IP geolocation and ASN data: IPinfo Lite by IPinfo (https://ipinfo.io), licensed under the Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0, https://creativecommons.org/licenses/by-sa/4.0/). The IPinfo Lite MMDB is redistributed unmodified inside this bundle.

[threatfox] CC0-1.0
Threat indicators: ThreatFox by abuse.ch (https://threatfox.abuse.ch), released under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/).

[tor_exit_nodes] LicenseRef-tor-bulk-exit-list-public
Tor exit addresses: The Tor Project bulk exit list (https://check.torproject.org/torbulkexitlist), public data.
`;

const base: PlatformFeedsStatus = {
  available: true, installed: true, bundle_sha256: 'ab'.repeat(32), source: 'online',
  installed_at: '2026-11-03T18:10:00Z', stale_after_days: 7, notice: NOTICE,
  sequence: 1793728874855, channel: 'open', auto_update: true, last_check_at: '2026-11-03T19:00:00Z',
  last_check_status: 'current', last_error: null, last_error_at: null,
  feeds: [
    { feed_id: 'ipinfo_lite', name: 'IPinfo Lite', revision: 7, produced_at: '2026-10-29T00:00:11Z', hard_expiry: '2026-11-11T08:01:57Z',
      age_seconds: 3600, state: 'fresh', license_id: 'CC-BY-SA-4.0', terms_revision: 'r', records: 4376565, active: true, loaded: 4376565, detail: null },
    { feed_id: 'threatfox', name: 'ThreatFox', revision: 169, produced_at: '2026-10-18T09:00:00Z', hard_expiry: '2026-11-04T17:51:24Z',
      age_seconds: 864000, state: 'stale', license_id: 'CC0-1.0', terms_revision: '1', records: 129135, active: true, loaded: 128000, detail: null },
    { feed_id: 'tor_exit_nodes', name: 'Tor exit nodes', revision: 3, produced_at: '2026-09-01T09:00:00Z', hard_expiry: '2026-10-01T09:00:00Z',
      age_seconds: 4924800, state: 'expired', license_id: 'LicenseRef-tor-bulk-exit-list-public', terms_revision: '1', records: 1200, active: false, loaded: 1200,
      detail: 'Past its hard expiry: no longer stamps new events. Update the feed bundle.' },
  ],
};

/** Radix tooltips open on focus; the text renders in the content and an a11y copy. */
function tooltipText(trigger: HTMLElement): string {
  act(() => { fireEvent.focus(trigger); });
  return screen.getAllByRole('tooltip').map(t => t.textContent ?? '').join(' ');
}

it('parses the bundle NOTICE into verbatim per-feed sections', () => {
  const { header, feeds } = parseFeedNotice(NOTICE);
  expect(header).toMatch(/^NOTICE: nano enrichment feed bundle/);
  expect([...feeds.keys()]).toEqual(['ipinfo_lite', 'threatfox', 'tor_exit_nodes']);
  expect(feeds.get('ipinfo_lite')!.licenseId).toBe('CC-BY-SA-4.0');
  expect(feeds.get('ipinfo_lite')!.text).toBe(NOTICE.split('\n')[3]);
  expect(feeds.get('tor_exit_nodes')!.text).toMatch(/public data\.$/);
  expect(parseFeedNotice(null).feeds.size).toBe(0);
});

it('renders every feed row with state, revision, formatted records and a compact meta row', () => {
  const { getByTestId } = render(<PlatformFeedsCard status={base} />);
  for (const [id, state] of [['ipinfo_lite', 'fresh'], ['threatfox', 'stale'], ['tor_exit_nodes', 'expired']]) {
    expect(getByTestId(`platform-feed-state-${id}`).textContent).toMatch(new RegExp(state));
  }
  expect(getByTestId('platform-feed-ipinfo_lite').textContent).toContain((4376565).toLocaleString());
  expect(getByTestId('platform-feed-threatfox').textContent).toContain('169');
  const meta = getByTestId('platform-feeds-meta').textContent!;
  expect(meta).toMatch(/nano open feed/);
  expect(meta).toMatch(/seq 1793728874855/);
  expect(meta).toMatch(/checked .* · current/);
  // Hash is truncated inline; the full value is in its tooltip.
  const hash = getByTestId('platform-feeds-hash');
  expect(hash.textContent).toBe('ab'.repeat(6));
  expect(tooltipText(hash)).toContain('ab'.repeat(32));
  // No attribution or explanatory paragraph is dumped inline.
  expect(getByTestId('platform-feeds-card').textContent).not.toMatch(/Creative Commons|stops stamping/);
});

it('each license chip opens the exact attribution text with its links', () => {
  const { getByTestId } = render(<PlatformFeedsCard status={base} />);
  const chip = getByTestId('platform-feed-licence-ipinfo_lite');
  expect(chip.textContent).toBe('CC-BY-SA-4.0');
  expect(getByTestId('platform-feed-licence-tor_exit_nodes').textContent).toBe('tor-bulk-exit-list-public');
  fireEvent.click(chip);
  const pop = getByTestId('platform-feed-notice-ipinfo_lite');
  expect(pop.textContent).toContain(parseFeedNotice(NOTICE).feeds.get('ipinfo_lite')!.text);
  const hrefs = within(pop).getAllByRole('link').map(a => a.getAttribute('href'));
  expect(hrefs).toEqual(['https://ipinfo.io', 'https://creativecommons.org/licenses/by-sa/4.0/']);
});

it('the full bundle NOTICE stays reachable verbatim from the header', () => {
  const { getByTestId } = render(<PlatformFeedsCard status={base} />);
  fireEvent.click(getByTestId('platform-feeds-notice-open'));
  expect(getByTestId('platform-feeds-notice').textContent).toBe(NOTICE);
});

it('explanations live in header tooltips', () => {
  render(<PlatformFeedsCard status={base} />);
  expect(tooltipText(screen.getByLabelText('About hard expiry'))).toMatch(/stops stamping new events; values already stamped stay searchable/);
  cleanup();
  render(<PlatformFeedsCard status={base} />);
  expect(tooltipText(screen.getByLabelText('About feed state'))).toMatch(/stale after 7 days/);
});

it('an inactive, unexpired feed says why it is not stamping', () => {
  const status = { ...base, feeds: [{ ...base.feeds[0], active: false, detail: 'Your own IPinfo token is configured.' }] };
  const { getByTestId } = render(<PlatformFeedsCard status={status} />);
  expect(getByTestId('platform-feed-ipinfo_lite').textContent).toMatch(/not stamping/);
  expect(tooltipText(getByTestId('platform-feed-detail-ipinfo_lite'))).toMatch(/IPinfo token/);
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
  expect((getByTestId('platform-feeds-import') as HTMLButtonElement).disabled).toBe(true);
  rerender(<PlatformFeedsCard status={{ ...base, auto_update: false }} onCheck={onCheck} onImport={onImport} />);
  expect(queryByTestId('platform-feeds-check')).toBeNull();
  expect(getByTestId('platform-feeds-manual').textContent).toMatch(/online updates off/);
  expect(tooltipText(screen.getByLabelText('Online updates are off'))).toMatch(/import a bundle file/);
});

it('no installed bundle says so; unavailable renders nothing', () => {
  const { getByTestId } = render(<PlatformFeedsCard status={{ ...base, installed: false, feeds: [], notice: null, bundle_sha256: null }} />);
  expect(getByTestId('platform-feeds-card').textContent).toMatch(/No feed bundle installed/);
  expect(getByTestId('platform-feeds-state').textContent).toBe('not installed');
  cleanup();
  const { container } = render(<PlatformFeedsCard status={{ ...base, available: false }} />);
  expect(container.innerHTML).toBe('');
});
