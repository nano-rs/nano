// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { SearchSettings } from './SearchSettings';

const mock = vi.hoisted(() => ({ admission: null as unknown, limits: null as unknown }));
vi.mock('@/hooks/use-api', () => ({
  useSearchAdmissionConfig: () => ({ data: mock.admission, loading: false, error: null, refetch: vi.fn() }),
  useUpdateSearchAdmissionConfig: () => ({ mutate: vi.fn(), loading: false }),
  useSearchQueryLimits: () => ({ data: mock.limits, loading: false, refetch: vi.fn() }),
  useUpdateSearchQueryLimits: () => ({ mutate: vi.fn(), loading: false }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }));

const admission = {
  global_adhoc_limit: 30, per_user_limit: 5, max_queue_depth: 100, queue_timeout_seconds: 300,
  interactive_max_execution_time: 300, interactive_max_memory_gb: 20,
  analytics_max_execution_time: 3600, analytics_max_memory_gb: 50,
  realtime_max_execution_time: 30, realtime_max_memory_gb: 5,
};
const limits = {
  max_group_array_size: 100, max_mvexpand_rows: 100000, max_post_processing_groups: 1000000,
  max_streaming_cache_rows: 50000, block_on_cost_errors: false,
};
const verdict = {
  managed_by: 'platform', reason: 'managed_by_platform', setting: 'search_admission',
  detail: 'The values shown are the release defaults; live values may differ.',
};
const enforced = (detail: string) => ({ applies_on_shared_lake: true, detail });
const unused = (detail: string) => ({ applies_on_shared_lake: false, detail: `Not used on the shared lake: ${detail}` });
const tier = unused('this is a ClickHouse query setting.');

beforeEach(() => {
  mock.admission = admission;
  mock.limits = limits;
});
afterEach(cleanup);

test('dedicated tenants keep editable inputs and no lake labels', () => {
  render(<SearchSettings />);
  const inputs = screen.getAllByRole('textbox');
  expect(inputs.length).toBe(14);
  expect(inputs.every((input) => !(input as HTMLInputElement).disabled)).toBe(true);
  expect(screen.getByRole('switch')).toHaveProperty('disabled', false);
  expect(screen.queryByText('Enforced')).toBeNull();
  expect(screen.queryByText('Not used on the shared lake')).toBeNull();
  expect(screen.queryByText(/The shared lake doesn’t use them/)).toBeNull();
});

test('shared tenants render read-only with per-setting shared-lake labels', () => {
  mock.admission = {
    ...admission,
    managed_by_platform: verdict,
    shared_lake_applicability: {
      global_adhoc_limit: enforced('Enforced by the admission controller.'),
      per_user_limit: enforced('Enforced per user.'),
      max_queue_depth: enforced('Enforced by the queue.'),
      queue_timeout_seconds: enforced('Enforced by the queue.'),
      interactive_max_execution_time: tier, interactive_max_memory_gb: tier,
      analytics_max_execution_time: tier, analytics_max_memory_gb: tier,
      realtime_max_execution_time: tier, realtime_max_memory_gb: tier,
    },
  };
  mock.limits = {
    ...limits,
    managed_by_platform: verdict,
    shared_lake_applicability: {
      max_group_array_size: unused('built-in cap.'),
      max_mvexpand_rows: unused('built-in cap.'),
      max_post_processing_groups: enforced('Enforced on post-processing.'),
      max_streaming_cache_rows: unused('the streaming result cache is disabled for lake searches.'),
      block_on_cost_errors: enforced('Checked before lake searches.'),
    },
  };
  render(<SearchSettings />);

  expect(screen.getByRole('note').textContent).toContain('live values may differ');
  const inputs = screen.getAllByRole('textbox');
  expect(inputs.length).toBe(14);
  expect(inputs.every((input) => (input as HTMLInputElement).disabled)).toBe(true);
  expect(screen.getByRole('switch')).toHaveProperty('disabled', true);
  expect(screen.getByText('Save admission settings').closest('button')).toHaveProperty('disabled', true);
  expect(screen.getByText('Save query limits').closest('button')).toHaveProperty('disabled', true);

  const perUser = within(screen.getByTestId('setting-per_user_limit'));
  expect(perUser.getByText('Enforced')).toBeTruthy();
  expect(perUser.getByText('Enforced per user.')).toBeTruthy();

  expect(screen.getByText(/The shared lake doesn’t use them\./)).toBeTruthy();
  for (const tierKey of ['realtime', 'interactive', 'analytics']) {
    const row = within(screen.getByTestId(`setting-${tierKey}-budget`));
    expect(row.getByText('Not used on the shared lake')).toBeTruthy();
    // The prefix is the label, not repeated in the reason.
    expect(row.getByText('this is a ClickHouse query setting.')).toBeTruthy();
  }

  const cache = screen.getByTestId('setting-max_streaming_cache_rows');
  expect(within(cache).getByText('Not used on the shared lake')).toBeTruthy();
  expect(cache.querySelector('.opacity-50')).not.toBeNull();
  const post = screen.getByTestId('setting-max_post_processing_groups');
  expect(within(post).getByText('Enforced')).toBeTruthy();
  expect(post.querySelector('.opacity-50')).toBeNull();
  expect(within(screen.getByTestId('setting-block_on_cost_errors')).getByText('Enforced')).toBeTruthy();
});
