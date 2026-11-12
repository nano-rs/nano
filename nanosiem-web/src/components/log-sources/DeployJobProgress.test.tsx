// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-5132: the deploy-job strip shows the running phase, then the final state. */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { DeployJob } from '@/lib/api/types';
import { DeployJobProgress } from './DeployJobProgress';

afterEach(cleanup);

function job(overrides: Partial<DeployJob>): DeployJob {
  return {
    id: 'djob_1',
    kind: 'deploy',
    log_source_id: 'lsrc_a',
    state: 'running',
    phase: 'reloading',
    message: null,
    result: null,
    error_status: null,
    created_at: new Date(Date.now() - 12_000).toISOString(),
    started_at: null,
    finished_at: null,
    heartbeat_at: new Date().toISOString(),
    coalesced: false,
    status_path: '/api/log-sources/deploy-jobs/djob_1',
    ...overrides,
  };
}

describe('DeployJobProgress', () => {
  it('renders nothing without a job', () => {
    const { container } = render(<DeployJobProgress job={undefined} />);
    expect(container.firstChild).toBeNull();
  });

  it('shows the verb, the phase and the elapsed time while running', () => {
    render(<DeployJobProgress job={job({})} />);
    const strip = screen.getByTestId('deploy-job-progress');
    expect(strip.dataset.state).toBe('running');
    expect(strip.textContent).toContain('Deploying');
    expect(screen.getByTestId('deploy-job-phase').textContent).toBe('Reloading Vector');
    expect(strip.textContent).toMatch(/1[12]s/);
  });

  it('shows the final state and message', () => {
    render(
      <DeployJobProgress
        job={job({
          state: 'rolled_back',
          phase: 'done',
          message: 'Reload failed, rolled back: refused',
          finished_at: new Date().toISOString(),
        })}
      />,
    );
    expect(screen.getByTestId('deploy-job-state').textContent).toBe('Rolled back');
    expect(screen.getByTestId('deploy-job-progress').textContent).toContain('refused');
    expect(screen.queryByTestId('deploy-job-phase')).toBeNull();
  });

  it('names a waiting job honestly', () => {
    render(<DeployJobProgress job={job({ state: 'queued', phase: 'waiting_for_lock', kind: 'publish' })} />);
    expect(screen.getByTestId('deploy-job-progress').textContent).toContain('Publishing');
    expect(screen.getByTestId('deploy-job-phase').textContent).toBe('Waiting for another deploy');
  });
});
