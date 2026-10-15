// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-3680: the Log Sources list's refused-rows badge. */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { RefusedEventsBadge } from './RefusedEventsBadge';

afterEach(cleanup);

describe('RefusedEventsBadge', () => {
  it('compact: a mono count with the full sentence as its tooltip', () => {
    render(<RefusedEventsBadge count={100} sample={{ reason: 'ocsf_constraint_failed', field: 'device' }} compact />);
    const badge = screen.getByTestId('refused-events-badge');
    expect(badge.textContent).toBe('100 refused');
    expect(badge.className).toMatch(/font-mono/);
    expect(badge.getAttribute('title')).toBe('100 events refused by OCSF validation (constraint_failed at device)');
  });

  it('full: the sentence inline', () => {
    render(<RefusedEventsBadge count={2} sample={{ reason: 'time_invalid', field: 'time' }} />);
    expect(screen.getByTestId('refused-events-badge').textContent).toBe('2 events refused by OCSF validation (time_invalid at time)');
  });

  it('renders nothing for zero or a lake that does not record refusals', () => {
    const { container } = render(
      <>
        <RefusedEventsBadge count={0} />
        <RefusedEventsBadge count={null} />
        <RefusedEventsBadge count={undefined} compact />
      </>,
    );
    expect(container.textContent).toBe('');
  });
});
