// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3620: /ingestion/credentials* lands on Log Sources → Cloud pull on hosted-shared only. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { RetiredOnSharedRoute } from './RetiredOnSharedRoute';
import { CLOUD_PULL_PATH } from '@/lib/shared-credentials-retired';

const shared = vi.hoisted(() => ({ value: false }));
vi.mock('@/hooks/use-shared-tenant', () => ({ useSharedTenant: () => shared.value }));

function Where() {
  const location = useLocation();
  return <div data-testid="where">{location.pathname + location.search}</div>;
}

// Mirrors the App.tsx credentials routes.
function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/ingestion/credentials" element={
          <RetiredOnSharedRoute to={CLOUD_PULL_PATH}><div data-testid="credentials-page"><Where /></div></RetiredOnSharedRoute>
        } />
        <Route path="/ingestion/credentials/new" element={
          <RetiredOnSharedRoute to={CLOUD_PULL_PATH}><Navigate to="/ingestion/credentials?add=aws_s3" replace /></RetiredOnSharedRoute>
        } />
        <Route path="/ingestion/credentials/:id" element={
          <RetiredOnSharedRoute to={CLOUD_PULL_PATH}><div data-testid="credentials-page"><Where /></div></RetiredOnSharedRoute>
        } />
        <Route path={CLOUD_PULL_PATH} element={<div data-testid="cloud-pull"><Where /></div>} />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => cleanup());

describe('RetiredOnSharedRoute', () => {
  it.each(['/ingestion/credentials', '/ingestion/credentials?add=aws_s3', '/ingestion/credentials/new', '/ingestion/credentials/cred_01abc'])(
    'redirects %s to Cloud pull on hosted-shared',
    (path) => {
      shared.value = true;
      renderAt(path);
      expect(screen.queryByTestId('credentials-page')).toBeNull();
      expect(screen.getByTestId('cloud-pull')).toBeTruthy();
      expect(screen.getByTestId('where').textContent).toBe(CLOUD_PULL_PATH);
    },
  );

  it.each([
    ['/ingestion/credentials', '/ingestion/credentials'],
    ['/ingestion/credentials/new', '/ingestion/credentials?add=aws_s3'],
    ['/ingestion/credentials/cred_01abc', '/ingestion/credentials/cred_01abc'],
  ])('keeps %s on open core and dedicated', (path, landed) => {
    shared.value = false;
    renderAt(path);
    expect(screen.queryByTestId('cloud-pull')).toBeNull();
    expect(screen.getByTestId('credentials-page')).toBeTruthy();
    expect(screen.getByTestId('where').textContent).toBe(landed);
  });
});
