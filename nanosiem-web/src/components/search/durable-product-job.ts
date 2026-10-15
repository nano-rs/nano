// SPDX-License-Identifier: AGPL-3.0-or-later

import { abortableDelay } from '@/lib/abortable-delay';
import { api } from '@/lib/api';
import type { SearchJobStatus } from '@/lib/api/types';
import type { DurableProductJobState } from './DurableJobNotice';

/** Poll one typed product job through the shared Search Jobs API and return
 * its single typed artifact row. The object-store URI never reaches the
 * browser; the authenticated page endpoint verifies every manifest fence. */
export async function waitForDurableProductArtifact(
  jobId: string,
  expectedKind: string,
  onJob?: (job: DurableProductJobState) => void,
  isCurrent: () => boolean = () => true,
  signal?: AbortSignal,
): Promise<{ status: SearchJobStatus; row: Record<string, unknown> }> {
  for (;;) {
    if (signal?.aborted || !isCurrent()) throw new Error('Durable product job was superseded');
    const status = await api.getSearchJob(jobId, { isCancelled: () => !!signal?.aborted || !isCurrent() }, signal);
    if (signal?.aborted || !isCurrent()) throw new Error('Durable product job was superseded');
    if (status.task_kind && status.task_kind !== expectedKind) {
      throw new Error(`Durable job type changed from ${expectedKind} to ${status.task_kind}`);
    }
    onJob?.({
      jobId,
      status: status.status,
      queuePosition: status.queue_position,
      estimatedWaitSeconds: status.estimated_wait_seconds,
      progress: status.progress,
    });
    if (status.status === 'completed') {
      const page = await api.getSearchJobResultPage(jobId, 0, signal);
      if (signal?.aborted || !isCurrent()) throw new Error('Durable product job was superseded');
      const row = page.rows[0];
      if (page.total_rows !== 1 || !row) {
        throw new Error(`Durable ${expectedKind} job returned an invalid typed artifact`);
      }
      return { status, row };
    }
    if (status.status === 'failed' || status.status === 'cancelled') {
      throw new Error(status.error || `Durable ${expectedKind} job ${status.status}`);
    }
    await abortableDelay(750, signal);
  }
}
