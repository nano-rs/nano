// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { StatsView } from './StatsView';

vi.mock('./SearchResults', () => ({
  FieldValueMenu: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

afterEach(cleanup);

const joinQuery =
  'source_type="proc" | stats count AS launches by device.hostname | join device.hostname [search source_type="auth" | stats count AS logons by device.hostname]';

describe('StatsView', () => {
  it('shows a column added after stats by a join (NAN-5702)', () => {
    const results = [
      { fields: { 'device.hostname': 'ws-1', launches: 4, logons: 9 } },
      { fields: { 'device.hostname': 'ws-2', launches: 2, logons: 1 } },
    ];
    render(<StatsView results={results} query={joinQuery} columnOrder={['device.hostname', 'launches']} />);
    const headers = screen.getAllByRole('columnheader').map((th) => th.textContent?.trim());
    expect(headers).toEqual(expect.arrayContaining(['device.hostname', 'launches', 'logons']));
    expect(screen.getByText('9')).toBeTruthy();
  });

  it('says when only the first page of rows is loaded and loads the rest (NAN-5701)', () => {
    const results = Array.from({ length: 50 }, (_, i) => ({ fields: { user: `u${i}`, count: 100 - i } }));
    const onLoadAll = vi.fn();
    render(
      <StatsView
        results={results}
        query="* | stats count by user"
        columnOrder={['user', 'count']}
        totalCount={120}
        onLoadAll={onLoadAll}
      />,
    );
    const notice = screen.getByTestId('stats-partial-notice');
    expect(notice.textContent).toContain('50');
    expect(notice.textContent).toContain('120');
    fireEvent.click(screen.getByText('Load all 120'));
    expect(onLoadAll).toHaveBeenCalledWith(120);
  });

  it('shows no notice when every row is loaded', () => {
    render(
      <StatsView
        results={[{ fields: { user: 'a', count: 1 } }]}
        query="* | stats count by user"
        totalCount={1}
      />,
    );
    expect(screen.queryByTestId('stats-partial-notice')).toBeNull();
  });

  it('keeps a renamed by field as the group key (review P2)', () => {
    const results = [
      { fields: { actor: 'alice', count: 100 } },
      { fields: { actor: 'bob', count: 20 } },
    ];
    render(
      <StatsView
        results={results}
        query="* | stats count by user | rename user as actor"
        columnOrder={['user', 'count']}
      />,
    );
    const headers = screen.getAllByRole('columnheader').map((th) => th.textContent?.trim());
    expect(headers.indexOf('actor')).toBeLessThan(headers.indexOf('count'));
    // Default sort is the numeric aggregate, descending: 100 before 20.
    const cells = screen.getAllByRole('row').slice(1).map((tr) => tr.textContent ?? '');
    expect(cells[0]).toContain('alice');
    expect(cells[1]).toContain('bob');
  });

  it('sorts a text column added after stats as text (review P2)', () => {
    const results = [
      { fields: { user: 'a', count: 3, dept: 'Sales' } },
      { fields: { user: 'b', count: 2, dept: 'Engineering' } },
      { fields: { user: 'c', count: 1, dept: 'Ops' } },
    ];
    render(<StatsView results={results} query="* | stats count by user | join user [search x]" columnOrder={['user', 'count']} />);
    fireEvent.click(screen.getByRole('columnheader', { name: /dept/i }));
    const order = screen.getAllByRole('row').slice(1).map((tr) => (tr.textContent ?? '').match(/Engineering|Ops|Sales/)?.[0]);
    expect(order).toEqual(['Engineering', 'Ops', 'Sales']);
  });
});

