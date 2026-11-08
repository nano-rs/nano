// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4959: bundle status of a feed in the marketplace drawers (IPinfo Lite is bundle-only).
import { afterEach, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { formatUntil } from '@/lib/date-utils';
import { BundleFeedStatus } from './BundleFeedStatus';

afterEach(cleanup);

const installed = {
  feed_id: 'ipinfo_lite', revision: 12, state: 'fresh', active: true, detail: null,
  produced_at: '2026-11-04T07:00:00Z', installed_at: '2026-11-04T08:00:00Z',
  next_check_at: '2026-11-04T10:00:00Z', auto_update: true, channel: 'open',
};

it('shows revision, last update and next refresh, and no credential inputs', () => {
  const { getByTestId, container } = render(<BundleFeedStatus provision={installed} />);
  expect(getByTestId('inventory-bundle').textContent).toMatch(/signed bundle · ipinfo_lite/);
  expect(getByTestId('bundle-feed-revision').textContent).toBe('12');
  expect(getByTestId('bundle-feed-state').textContent).toBe('fresh');
  expect(getByTestId('bundle-feed-last-update').textContent).toMatch(/2026|Nov/);
  expect(getByTestId('bundle-feed-next-refresh').textContent).toMatch(/2026|Nov/);
  expect(getByTestId('inventory-bundle-note').textContent).toMatch(/no download URL or\s+token/);
  expect(container.querySelectorAll('input, textarea, select')).toHaveLength(0);
});

it('says when no bundle carries the feed yet and when online updates are off', () => {
  const { getByTestId } = render(
    <BundleFeedStatus provision={{ ...installed, revision: null, state: 'not_installed', active: false, produced_at: null, auto_update: false, next_check_at: null, detail: 'No feed bundle installed yet.' }} />,
  );
  expect(getByTestId('bundle-feed-revision').textContent).toBe('—');
  expect(getByTestId('bundle-feed-state').textContent).toBe('not installed');
  expect(getByTestId('bundle-feed-next-refresh').textContent).toMatch(/import a bundle file/);
  expect(getByTestId('bundle-feed-detail').textContent).toMatch(/No feed bundle installed/);
});

it('formats the time until the next check', () => {
  const now = new Date('2026-11-04T09:00:00Z');
  expect(formatUntil('2026-11-04T09:30:00Z', now)).toBe('in 30m');
  expect(formatUntil('2026-11-04T12:00:00Z', now)).toBe('in 3h');
  expect(formatUntil('2026-11-04T08:59:00Z', now)).toBe('due');
});
