// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { AssetDossierAuth, AssetDossierFiles } from '@/lib/api/types';
import { AuthCard } from './AuthCard';
import { FilesCard } from './FilesCard';
import { formatEventTimeFull, formatEventTimeShort } from '../helpers';

afterEach(cleanup);

describe('formatEventTimeShort / formatEventTimeFull (NAN-3408)', () => {
  it('renders the lake raw timestamp as MM-DD HH:MM:SS UTC, no microseconds', () => {
    expect(formatEventTimeShort('2026-10-09 11:39:46.419000')).toBe('10-09 11:39:46');
    expect(formatEventTimeFull('2026-10-09 11:39:46.419000')).toBe('2026-10-09 11:39:46 UTC');
  });

  it('converts offset timestamps to UTC', () => {
    expect(formatEventTimeShort('2026-10-09T07:39:46-04:00')).toBe('10-09 11:39:46');
    expect(formatEventTimeShort('2026-10-09T11:39:46.5Z')).toBe('10-09 11:39:46');
  });

  it('keeps the ClickHouse bare HH:MM:SS form at second precision', () => {
    expect(formatEventTimeShort('11:39:46')).toBe('11:39:46');
    expect(formatEventTimeShort('11:39:46.419')).toBe('11:39:46');
    expect(formatEventTimeFull('11:39:46')).toBe('11:39:46 UTC');
  });

  it('passes unparseable input through without fractional seconds', () => {
    expect(formatEventTimeShort('')).toBe('');
    expect(formatEventTimeShort(null)).toBe('');
    expect(formatEventTimeShort('garbage.123')).toBe('garbage');
    expect(formatEventTimeFull('garbage.123')).toBe('garbage.123');
  });
});

const auth: AssetDossierAuth = {
  success: 1200,
  failure: 179,
  interactive: 0,
  network: 0,
  lateral: 0,
  recent: [
    { ts: '2026-10-09 11:39:46.419000', auth_type: 'NTLM', user: 'randerson', src: 'ws-fin-072', result: 'success', reason: null },
    { ts: '2026-10-09 11:39:40.000000', auth_type: 'other', user: 'randerson', src: null, result: 'failure', reason: 'Logon' },
  ],
};

describe('AuthCard recent logons (NAN-3408)', () => {
  it('renders one fixed-width, non-wrapping mono time per row', () => {
    render(<AuthCard auth={auth} />);
    const rows = screen.getAllByTestId('auth-recent-row');
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.className).toContain('h-6');
      expect(row.className).toContain('whitespace-nowrap');
      expect(row.className).toContain('font-mono');
    }
    const time = screen.getByText('10-09 11:39:46');
    expect(time.className).toContain('w-[14ch]');
    expect(time.getAttribute('title')).toBe('2026-10-09 11:39:46 UTC');
    expect(screen.queryByText(/419000/)).toBeNull();
    expect(screen.getByText(/Recent logons · UTC/)).toBeTruthy();
  });

  it('shows "via <host>" only when a source host is present', () => {
    render(<AuthCard auth={auth} />);
    expect(screen.getAllByText(/^via/)).toHaveLength(1);
    expect(screen.getByText('ws-fin-072')).toBeTruthy();
  });

  it('uses the same warn token for the header fail count and the FAILURE tile', () => {
    const { container } = render(<AuthCard auth={auth} />);
    const header = container.querySelector('.font-mono .tabular-nums:nth-of-type(2)');
    expect(header?.textContent).toBe('179');
    expect(header?.className).toContain('text-[oklch(72%_0.14_80)]');
    const tile = screen.getByText('FAILURE').previousElementSibling;
    expect(tile?.textContent).toBe('179');
    expect(tile?.className).toContain('text-[oklch(72%_0.14_80)]');
    expect(container.innerHTML).not.toContain('oklch(62%_0.18_28)');
  });
});

describe('FilesCard recent (NAN-3408)', () => {
  it('formats the raw lake timestamp the same way', () => {
    const files: AssetDossierFiles = {
      writes: 1,
      sensitive: 0,
      exec: 0,
      recent: [{ ts: '2026-10-09 11:39:46.419000', path: 'C:\\x.txt', size_bytes: 0, action: 'write', proc: null }],
    };
    render(<FilesCard files={files} />);
    const time = screen.getByText('10-09 11:39:46');
    expect(time.className).toContain('whitespace-nowrap');
    expect(time.getAttribute('title')).toBe('2026-10-09 11:39:46 UTC');
  });
});
