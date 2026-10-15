// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { BreadcrumbProvider } from '@/contexts/BreadcrumbContext';
import { AppBreadcrumbs, useCurrentPageTitle } from './AppBreadcrumbs';

vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ capabilities: {} }) }));

function Header() {
  return <><h1>{useCurrentPageTitle()}</h1><AppBreadcrumbs /></>;
}
afterEach(cleanup);
it('names onboarding in the app header and links back to Log Sources', () => {
  render(<MemoryRouter initialEntries={['/ingestion/log-sources/onboarding']}><BreadcrumbProvider><Header /></BreadcrumbProvider></MemoryRouter>);
  expect(screen.getByRole('heading').textContent).toBe('Source onboarding');
  expect(screen.getByRole('link', { name: 'Log Sources' }).getAttribute('href')).toBe('/ingestion/log-sources');
  expect(screen.getByText('Ingestion')).toBeTruthy();
});
