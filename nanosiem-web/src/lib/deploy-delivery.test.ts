// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5279: a role-split deploy still being installed is in progress, not an error.
import { describe, expect, it, vi } from 'vitest';
import type { GenerationDelivery, GenerationDeliveryStatus } from '@/lib/api/types';
import { DELIVERY_PENDING_TITLE, pendingDelivery, recheckDelivery, toastDeployResult } from './deploy-delivery';

const pending: GenerationDelivery = {
  state: 'pending',
  generation: 36,
  host_count: 2,
  pending_hosts: ['http://ingest-1:8687', 'http://ingest-2:8687'],
  sync_interval_secs: 5,
  status_path: '/api/log-sources/delivery-status?generation=36',
};

function status(state: GenerationDeliveryStatus['state'], message: string = state): GenerationDeliveryStatus {
  return { generation_delivery: true, generation: 36, state, host_count: 2, hosts: [], message };
}

describe('deploy delivery (NAN-5279)', () => {
  it('treats only a pending delivery as pending', () => {
    expect(pendingDelivery({ delivery: pending })).toBe(pending);
    expect(pendingDelivery({ delivery: { ...pending, state: 'acknowledged' } })).toBeNull();
    expect(pendingDelivery({})).toBeNull();
    expect(pendingDelivery(null)).toBeNull();
  });

  it('toasts a plain success when there is no pending delivery', () => {
    const toast = vi.fn();
    toastDeployResult(toast, vi.fn(), { message: 'ok' }, { title: 'Deployed', description: 'fallback' });
    expect(toast).toHaveBeenCalledWith({ title: 'Deployed', description: 'ok' });
  });

  it('toasts a pending deploy as in progress with a re-check, never as an error', async () => {
    const toast = vi.fn();
    const fetchStatus = vi.fn().mockResolvedValue(status('acknowledged', 'Generation 36 is installed on 2/2 ingest host(s).'));
    toastDeployResult(toast, fetchStatus, { message: 'Published generation 36; ...', delivery: pending }, { title: 'Deployed', description: 'x' });
    const notice = toast.mock.calls[0][0];
    expect(notice.title).toBe(DELIVERY_PENDING_TITLE);
    expect(notice.variant).toBe('info');
    expect(notice.action.label).toBe('Re-check');
    notice.action.onClick();
    await vi.waitFor(() => expect(toast).toHaveBeenCalledTimes(2));
    expect(fetchStatus).toHaveBeenCalledWith(36);
    expect(toast.mock.calls[1][0]).toMatchObject({ title: 'Deployed' });
  });

  it('keeps offering a re-check while still pending and reports a rejection as an error', async () => {
    const toast = vi.fn();
    await recheckDelivery(toast, vi.fn().mockResolvedValue(status('pending')), 36);
    expect(toast.mock.calls[0][0]).toMatchObject({ title: DELIVERY_PENDING_TITLE, variant: 'info' });
    expect(toast.mock.calls[0][0].action.label).toBe('Re-check');

    await recheckDelivery(toast, vi.fn().mockResolvedValue(status('rejected')), 36);
    expect(toast.mock.calls[1][0]).toMatchObject({ variant: 'destructive' });

    await recheckDelivery(toast, vi.fn().mockRejectedValue(new Error('boom')), 36);
    expect(toast.mock.calls[2][0]).toMatchObject({ variant: 'destructive', description: 'boom' });
  });
});
