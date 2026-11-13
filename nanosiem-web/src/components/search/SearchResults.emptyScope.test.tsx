// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// NAN-5328: an empty search for a scope-restricted role says rows may be
// hidden by the role's data scope, not only "expand the time range".
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { EmptyState } from './SearchResults';

vi.mock('@/lib/api', () => ({ api: {} }));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));

afterEach(cleanup);

describe('EmptyState data-scope note (NAN-5328)', () => {
  it('names the data scope when the role is restricted', () => {
    render(<EmptyState hasSearched query="class_uid=6003" scopeRestricted />);
    expect(screen.getByTestId('empty-scope-note').textContent).toMatch(/data scope hides some sources/);
  });

  it('stays silent for an unrestricted role', () => {
    render(<EmptyState hasSearched query="class_uid=6003" />);
    expect(screen.queryByTestId('empty-scope-note')).toBeNull();
  });
});
