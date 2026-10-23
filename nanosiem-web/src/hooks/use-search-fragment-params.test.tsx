// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import { readSearchFragment, useSearchFragmentParams } from './use-search-fragment-params';
import { matchSearchUrl } from '@/components/matches/search-window';

afterEach(cleanup);
const payloads = ["' OR 1=1 --", '<script>alert(1)</script>', 'UNION SELECT', '../../etc/passwd', 'cmd.exe /c whoami'];

it.each(payloads)('keeps %s out of the HTTP request target', q => {
  const url = new URL(`/t/ops${matchSearchUrl(q)}`, 'https://nano.example');
  expect(url.pathname + url.search).toBe('/t/ops/search');
  expect(readSearchFragment(url.search, url.hash).get('q')).toBe(q);
});

it('prefers fragment values and accepts legacy links and anchors', () => {
  expect(readSearchFragment('?q=legacy&start=1', '#q=new&end=2').toString()).toBe('start=1&q=new&end=2');
  expect(readSearchFragment('?q=legacy', '#events').toString()).toBe('q=legacy');
});

function Probe() {
  const [params, setParams] = useSearchFragmentParams();
  const location = useLocation();
  const navigate = useNavigate();
  return <>
    <output data-testid="url">{location.pathname + location.search + location.hash}</output>
    <output data-testid="query">{params.get('q')}</output>
    <button onClick={() => setParams({ q: payloads[1], start: '1', end: '2' })}>Search</button>
    <button onClick={() => navigate(-1)}>Back</button>
  </>;
}

it('replaces a legacy entry then round-trips fragment updates and Back', async () => {
  render(<MemoryRouter initialEntries={['/search?q=legacy&start=1&end=2']}><Probe /></MemoryRouter>);
  await waitFor(() => expect(screen.getByTestId('url').textContent).toBe('/search#q=legacy&start=1&end=2'));
  fireEvent.click(screen.getByText('Search'));
  await waitFor(() => expect(screen.getByTestId('query').textContent).toBe(payloads[1]));
  expect(screen.getByTestId('url').textContent).not.toContain('?');
  fireEvent.click(screen.getByText('Back'));
  await waitFor(() => expect(screen.getByTestId('url').textContent).toBe('/search#q=legacy&start=1&end=2'));
});
