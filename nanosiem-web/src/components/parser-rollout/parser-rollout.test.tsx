// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2607: rollout strip, log source rollout panel and the "platform update available" banner. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import type { LogSourceVersion, TenantParserBaseOffer, TenantParserRollout } from '@/lib/api/types';
import { RolloutStatus, RolloutStrip } from './RolloutStrip';
import { LogSourceRolloutPanel } from './LogSourceRolloutPanel';
import { previousVersion } from '@/lib/parser-rollout';
import { PlatformUpdateBanner } from './PlatformUpdateBanner';

const mocks = vi.hoisted(() => ({
  permissions: new Set<string>(['log_sources:deploy', 'log_sources:view']),
  toast: vi.fn(),
  getParserRollout: vi.fn(),
  listLogSourceRollouts: vi.fn(),
  requestParserRollout: vi.fn(),
  revertLogSourceVersion: vi.fn(),
  listParserBaseOffers: vi.fn(),
  mergeParserBaseOffer: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user_me' }, hasPermission: (p: string) => mocks.permissions.has(p) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mocks.toast }) }));
vi.mock('@/lib/api', () => ({
  api: {
    getParserRollout: mocks.getParserRollout,
    listLogSourceRollouts: mocks.listLogSourceRollouts,
    requestParserRollout: mocks.requestParserRollout,
    revertLogSourceVersion: mocks.revertLogSourceVersion,
    listParserBaseOffers: mocks.listParserBaseOffers,
    mergeParserBaseOffer: mocks.mergeParserBaseOffer,
  },
}));

const now = '2026-09-22T12:00:00Z';
function rollout(over: Partial<TenantParserRollout> = {}): TenantParserRollout {
  return {
    id: '11111111-1111-4111-8111-111111111111', kind: 'publish', state: 'building', log_source_id: 'lsrc_1',
    log_source_version_ids: ['22222222-2222-4222-8222-222222222222'], base_offer_id: null, requested_by: 'user_me',
    requested_at: now, request_reason: null, state_revision: 2, roll_id: null, bundle_revision: null, content_sha256: null,
    report_sha256: null, failure_reason: null, failure_component: null, failure_stage: null, stage_timings: null,
    updated_at: now, completed_at: null, terminal: false, ...over,
  };
}
function version(n: number, active: boolean): LogSourceVersion {
  return { id: 100 + n, log_source_id: 'lsrc_1', version_number: n, parser_vrl: '.', is_active: active, created_at: now, change_reason: 'publish' } as LogSourceVersion;
}
const offer: TenantParserBaseOffer = {
  id: '33333333-3333-4333-8333-333333333333', state: 'available', base_content_sha256: 'ab'.repeat(32),
  base_source_revision: 'platform-2026.09.23', runtime_image_digest: 'sha256:' + 'cd'.repeat(32), validation_state: 'failed',
  failure_reason: 'error[E103]: unhandled fallible assignment', failure_component: 'transforms.tenant__acme_app',
  failure_stage: 'vector_validate', changed_platform_sources: ['apache_access'],
  diff: { unified: '--- a/x\n+++ b/x\n-old\n+new', truncated: true }, offered_at: now, updated_at: now, resolved_at: null,
  merge_request_id: null, merged_roll_id: null,
};

function wrap(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

beforeEach(() => {
  mocks.permissions = new Set(['log_sources:deploy', 'log_sources:view']);
  for (const m of Object.values(mocks)) if (typeof m === 'function' && 'mockReset' in m) (m as ReturnType<typeof vi.fn>).mockReset();
});
afterEach(cleanup);

describe('RolloutStrip', () => {
  it('shows the step sequence and says it rolls out to the parser cell', () => {
    wrap(<RolloutStrip rollout={rollout({ state: 'rolling', bundle_revision: 3, content_sha256: 'ef'.repeat(32), stage_timings: { build_ms: 1200 } })} />);
    const strip = screen.getByTestId('rollout-strip');
    for (const label of ['Queued', 'Building', 'Validated', 'Live']) expect(within(strip).getByText(label)).toBeTruthy();
    expect(screen.getByTestId('rollout-state').textContent).toBe('Rolling out');
    expect(strip.textContent).toContain('bundle r3 · efefefefefef');
    expect(strip.textContent).toMatch(/parser cell/);
    expect(strip.textContent).not.toMatch(/Vector deploy/);
    expect(screen.getByTestId('rollout-timings').textContent).toContain('build 1.2s');
  });

  it('shows the failing stage, component and Vector message, with retry', () => {
    const onRetry = vi.fn();
    wrap(
      <RolloutStrip
        onRetry={onRetry}
        rollout={rollout({ state: 'failed', failure_stage: 'vector_validate', failure_component: 'transforms.tenant__acme_app', failure_reason: 'error[E110]: fallible predicate', terminal: true })}
      />,
    );
    expect(screen.getByTestId('rollout-state').textContent).toBe('Failed');
    expect(screen.getByTestId('rollout-failure-stage').textContent).toBe('stage vector validate');
    expect(screen.getByTestId('rollout-failure-component').textContent).toBe('transforms.tenant__acme_app');
    expect(screen.getByTestId('rollout-failure-message').textContent).toBe('error[E110]: fallible predicate');
    fireEvent.click(screen.getByText('Retry rollout'));
    expect(onRetry).toHaveBeenCalled();
  });

  it('explains a rollback keeps the previous bundle', () => {
    wrap(<RolloutStrip rollout={rollout({ state: 'rolled_back', failure_reason: 'probe row missing', failure_stage: 'verify', terminal: true })} />);
    expect(screen.getByTestId('rollout-failure').textContent).toContain('stayed on the previous bundle');
  });

  it('a queued publish shows the batch it rolls with (NAN-2617 coalescing)', () => {
    const others = ['44444444-4444-4444-8444-444444444444', '55555555-5555-4555-8555-555555555555'];
    const rollsAfter = new Date(Date.now() + 40_000).toISOString();
    const { unmount } = render(
      <RolloutStrip
        rollout={rollout({
          state: 'pending',
          batch: { window_seconds: 60, rolls_after: rollsAfter, request_ids: ['11111111-1111-4111-8111-111111111111', ...others] },
        })}
      />,
    );
    const note = screen.getByTestId('rollout-batch');
    expect(note.textContent).toMatch(/Queued · rolls with 2 other changes after \d{2}:\d{2}:\d{2}/);
    expect(note.textContent).toMatch(/\((39|40)s\)/);
    unmount();

    render(
      <RolloutStrip
        rollout={rollout({ state: 'pending', batch: { window_seconds: 60, rolls_after: rollsAfter, request_ids: ['11111111-1111-4111-8111-111111111111'] } })}
      />,
    );
    expect(screen.getByTestId('rollout-batch').textContent).toMatch(/Queued · batching changes for up to 60 s/);
  });

  it('shows no batch note once the rollout has left the queue', () => {
    render(
      <RolloutStrip
        rollout={rollout({ state: 'building', batch: { window_seconds: 60, rolls_after: now, request_ids: ['x'] } })}
      />,
    );
    expect(screen.queryByTestId('rollout-batch')).toBeNull();
  });

  it('polls a rollout by id until it is terminal', async () => {
    mocks.getParserRollout.mockResolvedValue(rollout({ state: 'live', bundle_revision: 4, terminal: true }));
    wrap(<RolloutStatus rolloutId="11111111-1111-4111-8111-111111111111" />);
    await waitFor(() => expect(screen.getByTestId('rollout-state').textContent).toBe('Live'));
    expect(mocks.getParserRollout).toHaveBeenCalledWith('11111111-1111-4111-8111-111111111111');
  });
});

describe('LogSourceRolloutPanel', () => {
  it('finds the previous published version', () => {
    expect(previousVersion([version(1, false), version(3, true), version(2, false)])?.version_number).toBe(2);
    expect(previousVersion([version(1, true)])).toBeUndefined();
    expect(previousVersion(undefined)).toBeUndefined();
  });

  it('shows the latest rollout, history, retry and a confirmed revert', async () => {
    mocks.listLogSourceRollouts.mockResolvedValue([
      rollout({ id: 'r2', state: 'failed', failure_reason: 'boom', failure_stage: 'vector_test', terminal: true }),
      rollout({ id: 'r1', state: 'live', bundle_revision: 2, terminal: true }),
    ]);
    mocks.requestParserRollout.mockResolvedValue(rollout({ id: 'r3', state: 'pending' }));
    mocks.revertLogSourceVersion.mockResolvedValue({ ...version(4, true), rollout: rollout({ id: 'r4', kind: 'revert', state: 'pending' }) });
    const onReverted = vi.fn();
    wrap(<LogSourceRolloutPanel logSourceId="lsrc_1" versions={[version(2, false), version(3, true)]} onReverted={onReverted} />);
    await waitFor(() => expect(screen.getByTestId('rollout-state').textContent).toBe('Failed'));
    // History is collapsed behind "Previous rollouts" (NAN-2983).
    expect(screen.queryByTestId('rollout-history')).toBeNull();
    expect(screen.getByText('Last rollout live')).toBeTruthy();
    fireEvent.click(screen.getByText('Previous rollouts'));
    expect(screen.getByTestId('rollout-history').textContent).toContain('r2');
    fireEvent.click(screen.getByText('Retry rollout'));
    await waitFor(() => expect(mocks.requestParserRollout).toHaveBeenCalledWith('lsrc_1', expect.any(Object)));
    fireEvent.click(screen.getByText(/Revert to v2/));
    fireEvent.click(await screen.findByRole('button', { name: 'Revert' }));
    await waitFor(() => expect(mocks.revertLogSourceVersion).toHaveBeenCalledWith('lsrc_1', 102));
    await waitFor(() => expect(onReverted).toHaveBeenCalled());
  });

  it('hides mutations without log_sources:deploy', async () => {
    mocks.permissions = new Set(['log_sources:view']);
    mocks.listLogSourceRollouts.mockResolvedValue([rollout({ state: 'failed', failure_reason: 'x', terminal: true })]);
    wrap(<LogSourceRolloutPanel logSourceId="lsrc_1" versions={[version(1, false), version(2, true)]} />);
    await waitFor(() => expect(screen.getByTestId('rollout-state').textContent).toBe('Failed'));
    expect(screen.queryByText('Retry rollout')).toBeNull();
    expect(screen.queryByText(/Revert to v1/)).toBeNull();
  });
});

describe('PlatformUpdateBanner', () => {
  it('renders nothing without an open offer', async () => {
    mocks.listParserBaseOffers.mockResolvedValue([{ ...offer, state: 'merged' }]);
    wrap(<PlatformUpdateBanner />);
    await waitFor(() => expect(mocks.listParserBaseOffers).toHaveBeenCalled());
    expect(screen.queryByTestId('platform-update-banner')).toBeNull();
  });

  it('a validation failure collapses to one row; details show the failure and diff; merges on request', async () => {
    mocks.listParserBaseOffers.mockResolvedValue([offer]);
    mocks.mergeParserBaseOffer.mockResolvedValue(rollout({ id: 'rm', kind: 'merge_base', state: 'pending', base_offer_id: offer.id, log_source_id: null }));
    mocks.getParserRollout.mockResolvedValue(rollout({ id: 'rm', kind: 'merge_base', state: 'building', log_source_id: null }));
    wrap(<PlatformUpdateBanner />);
    const banner = await screen.findByTestId('platform-update-banner');
    expect(banner.getAttribute('data-compact')).toBe('true');
    expect(banner.textContent).toContain('platform-2026.09.23');
    expect(screen.getByTestId('offer-error-message').textContent).toContain('Your parsers fail on this base');
    expect(screen.queryByTestId('offer-details')).toBeNull();
    fireEvent.click(screen.getByText('Details'));
    expect(banner.textContent).toContain('stays on your current parsers until you merge');
    expect(screen.getByTestId('offer-failure').textContent).toContain('transforms.tenant__acme_app');
    expect(screen.getByTestId('offer-failure').textContent).toContain('unhandled fallible assignment');
    expect(banner.textContent).toContain('apache_access');
    fireEvent.click(screen.getByText('View diff'));
    expect(screen.getByTestId('offer-diff').textContent).toContain('+new');
    expect(screen.getByTestId('offer-diff').textContent).toContain('Diff truncated.');
    fireEvent.click(screen.getByText('Merge'));
    await waitFor(() => expect(mocks.mergeParserBaseOffer).toHaveBeenCalledWith(offer.id));
    // A new merge in flight expands back to the full banner with its rollout strip.
    await waitFor(() => expect(screen.getByTestId('rollout-strip').getAttribute('data-state')).toBeTruthy());
    expect(screen.getByTestId('platform-update-banner').getAttribute('data-compact')).toBeNull();
  });

  it('a platform-side roll conflict is one compact row: code once, human message, never "your parsers fail"', async () => {
    const conflict = {
      ...offer, failure_reason: 'parser_roll_conflict', failure_component: 'parser_roll_conflict', failure_stage: 'roll',
      changed_platform_sources: [], merge_request_id: 'rm',
    };
    mocks.listParserBaseOffers.mockResolvedValue([conflict]);
    mocks.getParserRollout.mockResolvedValue(rollout({
      id: 'rm', kind: 'merge_base', state: 'failed', log_source_id: null, failure_stage: 'roll',
      failure_component: 'parser_roll_conflict', failure_reason: 'parser_roll_conflict', terminal: true,
    }));
    wrap(<PlatformUpdateBanner />);
    const banner = await screen.findByTestId('platform-update-banner');
    await waitFor(() => expect(mocks.getParserRollout).toHaveBeenCalledWith('rm'));
    expect(banner.getAttribute('data-compact')).toBe('true');
    expect(screen.queryByTestId('rollout-strip')).toBeNull();
    expect(screen.getByTestId('offer-error-code').textContent).toBe('parser_roll_conflict');
    expect(screen.getByTestId('offer-error-message').textContent).toContain('Your parsers were not the problem');
    expect(screen.getByText('Retry merge')).toBeTruthy();
    fireEvent.click(screen.getByText('Details'));
    const text = banner.textContent ?? '';
    expect(text.split('parser_roll_conflict').length - 1).toBe(1);
    expect(text.toLowerCase()).not.toContain('your parsers fail');
    expect(screen.getByTestId('offer-failure').textContent).toContain('Platform-side failure');
    expect(screen.getByTestId('offer-failure').textContent).toContain('stage roll');
  });

  it('shows merge in progress and no merge button while merge_pending', async () => {
    mocks.listParserBaseOffers.mockResolvedValue([{ ...offer, state: 'merge_pending', merge_request_id: 'rm' }]);
    mocks.getParserRollout.mockResolvedValue(rollout({ id: 'rm', kind: 'merge_base', state: 'building', log_source_id: null }));
    wrap(<PlatformUpdateBanner />);
    await screen.findByTestId('merge-in-progress');
    expect(screen.queryByText('Merge')).toBeNull();
  });

  it('hides Merge without log_sources:deploy', async () => {
    mocks.permissions = new Set(['log_sources:view']);
    mocks.listParserBaseOffers.mockResolvedValue([offer]);
    wrap(<PlatformUpdateBanner />);
    await screen.findByTestId('platform-update-banner');
    expect(screen.queryByText('Merge')).toBeNull();
  });
});
