// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-3467 — `/api/ioc-lists` exists only on hosted-shared tenants. Open-core
// and dedicated builds must render an explicit notice instead of the IOC Lists
// page, whose every request 404s.
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const mock = vi.hoisted(() => ({ iocLists: false }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ edition: 'open', version: 'test', capabilities: { iocLists: mock.iocLists } }),
}));

import { IocListsRouteGate } from './IocListsRouteGate';

function renderGate() {
  return render(
    <MemoryRouter>
      <IocListsRouteGate>
        <div>ioc lists page</div>
      </IocListsRouteGate>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mock.iocLists = false;
});
afterEach(cleanup);

test('renders the unavailable notice, not the page, when iocLists is off', () => {
  renderGate();
  expect(screen.queryByText('ioc lists page')).toBeNull();
  expect(screen.getByText('IOC lists are not available')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Go to Lookup Tables' }).getAttribute('href')).toBe('/rules/lookup-tables');
});

test('renders the page when iocLists is on', () => {
  mock.iocLists = true;
  renderGate();
  expect(screen.getByText('ioc lists page')).toBeTruthy();
  expect(screen.queryByText('IOC lists are not available')).toBeNull();
});
