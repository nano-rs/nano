// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4941: the Ingestion rail matches main's ingestion-navigation.ts (Log
 * Sources · Pipelines · Repositories), the retired
 * pages are gone from it, and Repositories is listed once (rail, not a tab).
 */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
import { ingestionNavigation } from './ingestion-navigation';
import { LogSourcesTabs } from '@/components/add-data/LogSourcesTabs';

afterEach(cleanup);

it('lists Log Sources, Pipelines and Repositories only, none of the retired pages', () => {
  expect(ingestionNavigation.map((i) => [i.name, i.href])).toEqual([
    ['Log Sources', '/ingestion/log-sources'],
    ['Pipelines', '/ingestion/pipelines'],
    ['Repositories', '/ingestion/log-sources/repositories'],
  ]);
  const hrefs = ingestionNavigation.map((i) => i.href);
  for (const retired of ['/ingestion/source-configurations', '/ingestion/credentials', '/ingestion/pull-feeds', '/ingestion/connector-feeds']) {
    expect(hrefs).not.toContain(retired);
  }
});

it('keeps Repositories out of the Log Sources tabs, and one page called Credentials', () => {
  render(<MemoryRouter><LogSourcesTabs active="sources" /></MemoryRouter>);
  const tabs = screen.getAllByRole('link').map((a) => [a.textContent, a.getAttribute('href')]);
  expect(tabs).toEqual([
    ['Log sources', '/ingestion/log-sources'],
    ['Credentials', '/ingestion/log-sources/credentials'],
    ['Cloud pull', '/ingestion/log-sources/cloud-pull'],
    ['Pull feeds', '/ingestion/log-sources/pull-feeds'],
  ]);
});
