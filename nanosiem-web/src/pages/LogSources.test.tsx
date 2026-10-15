// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3248: Log Sources page layout, lean slugs and platform-managed lanes. */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { LogSource } from '@/lib/api';
import type { IngestionHistoryPoint } from '@/lib/api/types';
import { LogSources } from './LogSources';

const mocks = vi.hoisted(() => ({
  sources: [] as unknown[],
  history: [] as unknown[],
  listParserBaseOffers: vi.fn(),
  getParserRollout: vi.fn(),
  inputSummary: vi.fn(),
}));

vi.mock('@/hooks/use-api', () => ({
  useLogSources: () => ({ data: mocks.sources, loading: false, refetch: vi.fn() }),
  useIngestionHistory: () => ({ data: mocks.history }),
  useDeleteLogSource: () => ({ mutate: vi.fn() }),
  useToggleLogSource: () => ({ mutate: vi.fn() }),
  useDeployLogSource: () => ({ mutate: vi.fn() }),
  useUndeployLogSource: () => ({ mutate: vi.fn() }),
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u', deployment_mode: 'enterprise_shared' }, tenantRuntime: { key: 't' }, hasPermission: () => true }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  api: {
    sourceScopes: { listRestricted: () => Promise.resolve({ restricted: [] }) },
    listParserBaseOffers: mocks.listParserBaseOffers,
    getParserRollout: mocks.getParserRollout,
    pipelines: { inputSummary: mocks.inputSummary },
  },
}));

const now = new Date();
const hourAgo = new Date(now.getTime() - 30 * 60_000).toISOString();

function leanSource(name: string, slug: string): LogSource {
  return {
    id: `lsrc_${slug}`, name, namespace: 'default', timezone: 'UTC', source_type: 'routed', parser_vrl: '.',
    validated: true, deployed: true, enabled: true, stale_alert_enabled: false, stale_threshold_minutes: 60,
    source_parser_linked: false, created_at: hourAgo, updated_at: hourAgo, deployed_at: hourAgo,
    ingest: {
      source_slugs: [slug], events_last_24h: 1000, events_last_hour: 50, bytes_last_24h: 0, parse_failures_24h: 0,
      last_event_at: hourAgo, health_status: 'healthy',
    },
  } as LogSource;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <LogSources />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mocks.sources = [leanSource('Apache HTTP Server (OCSF)', 'apache_access'), leanSource('AWS CloudTrail (OCSF)', 'aws_cloudtrail')];
  mocks.history = [
    { source_type: 'apache_access', timestamp: hourAgo, count: 1000 },
    { source_type: 'otlp_log', timestamp: hourAgo, count: 11200 },
    { source_type: 'findings', timestamp: hourAgo, count: 56 },
  ] satisfies IngestionHistoryPoint[];
  mocks.listParserBaseOffers.mockResolvedValue([]);
  mocks.inputSummary.mockResolvedValue({ sources: [] });
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('flows in the app scroller: no fill-height column or min-h-0 scroll box around the table', () => {
  renderPage();
  const page = screen.getByTestId('log-sources-page');
  expect(page.getAttribute('data-page-shell')).toBe('log-sources');
  expect(page.className).not.toMatch(/(^|\s)h-full(\s|$)/);
  expect(page.className).not.toMatch(/(^|\s)min-h-0(\s|$)/);
  const region = screen.getByTestId('log-sources-table-region');
  expect(region.className).not.toMatch(/(^|\s)(min-h-0|flex-1|overflow-auto|overflow-y-auto)(\s|$)/);
  expect(within(region).getByText('Apache HTTP Server (OCSF)')).toBeTruthy();
});

it('shows lean sources by their lake slugs, not the "routed" transport sentinel', () => {
  renderPage();
  const slugs = screen.getAllByTestId('log-source-slugs').map((el) => el.textContent);
  expect(slugs).toEqual(['apache_access', 'aws_cloudtrail']);
  expect(screen.queryByText('routed')).toBeNull();
});

it('adds a read-only platform-managed row for OTLP logs from ingestion history', () => {
  renderPage();
  const row = screen.getByTestId('platform-lane-row-otlp_log');
  expect(row.textContent).toContain('OTLP logs');
  expect(row.textContent).toContain('Platform managed');
  expect(row.textContent).toContain('otlp_log');
  expect(row.textContent).toContain('11.2K');
  expect(within(row).queryByRole('button')).toBeNull();
  // No audit data in the window -> no audit row; findings is never a source row.
  expect(screen.queryByTestId('platform-lane-row-audit')).toBeNull();
  expect(screen.queryByTestId('platform-lane-row-findings')).toBeNull();
  expect(screen.getByTestId('ingest-chart-legend-findings').textContent).toContain('detection output');
});

it('collapses a failed platform merge to one compact row above the table', async () => {
  mocks.listParserBaseOffers.mockResolvedValue([
    {
      id: 'offer', state: 'available', base_content_sha256: '78'.repeat(32), base_source_revision: '500a539bc75598c036cc598525e2ae196c9c9975',
      runtime_image_digest: 'sha256:x', validation_state: 'failed', failure_reason: 'parser_roll_conflict',
      failure_component: 'parser_roll_conflict', failure_stage: 'roll', changed_platform_sources: [], diff: {},
      offered_at: hourAgo, updated_at: hourAgo, resolved_at: null, merge_request_id: 'rm', merged_roll_id: null,
    },
  ]);
  mocks.getParserRollout.mockResolvedValue({
    id: 'rm', kind: 'merge_base', state: 'failed', failure_stage: 'roll', failure_component: 'parser_roll_conflict',
    failure_reason: 'parser_roll_conflict', log_source_id: null, requested_at: hourAgo,
  });
  renderPage();
  await waitFor(() => expect(screen.getByTestId('platform-update-banner').getAttribute('data-compact')).toBe('true'));
  await waitFor(() => expect(mocks.getParserRollout).toHaveBeenCalled());
  expect(screen.queryByTestId('rollout-strip')).toBeNull();
  expect(screen.getByText('Apache HTTP Server (OCSF)')).toBeTruthy();
});

// NAN-3661: a failed / blocked / paused delivery into a lane is flagged on the row, reason on hover.
it('flags a source whose cloud pull is failed, with the reason in the label', async () => {
  mocks.inputSummary.mockResolvedValue({
    sources: [
      { log_source_id: 'lsrc_aws_cloudtrail', source_slugs: ['aws_cloudtrail'], push: 0, pull: 1, connectors: 0, mixed_processes: false,
        attention: [{ kind: 'pull', id: 'p1', name: 'org trail', source_slug: 'aws_cloudtrail', level: 'failed', reason: 'assume_role_denied' }] },
      { log_source_id: 'lsrc_apache_access', source_slugs: ['apache_access'], push: 1, pull: 0, connectors: 0, mixed_processes: false, attention: [] },
    ],
  });
  renderPage();
  const badge = await screen.findByTestId('delivery-attention-badge');
  expect(badge.textContent).toMatch(/pull failed/i);
  expect(badge.getAttribute('aria-label')).toContain('pull · org trail: failed (assume_role_denied)');
  const row = badge.closest('tr')!;
  expect(within(row).getByText('AWS CloudTrail (OCSF)')).toBeTruthy();
  expect(screen.getAllByTestId('delivery-attention-badge')).toHaveLength(1);
});

it('shows no delivery flag on an older backend without attention', async () => {
  mocks.inputSummary.mockResolvedValue({
    sources: [{ log_source_id: 'lsrc_aws_cloudtrail', source_slugs: ['aws_cloudtrail'], push: 0, pull: 1, connectors: 0, mixed_processes: false }],
  });
  renderPage();
  await waitFor(() => expect(mocks.inputSummary).toHaveBeenCalled());
  expect(screen.queryByTestId('delivery-attention-badge')).toBeNull();
});
