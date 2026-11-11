// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5279: role-split deploys publish a Vector configuration generation that
 * each ingest host installs on its own poll. A deploy that outlasts the wait
 * while hosts are still installing comes back `success: true` with
 * `delivery.state = 'pending'`. That is in progress, not an error: say
 * "Deploying" (not "Deployed") and offer a re-check against
 * GET /api/log-sources/delivery-status.
 */
import type {
  EnhancedDeploymentResponse,
  GenerationDelivery,
  GenerationDeliveryStatus,
} from '@/lib/api/types';

export const DELIVERY_PENDING_TITLE = 'Deploying: not yet confirmed';

type ToastFn = (options: {
  title?: string;
  description?: string;
  variant?: 'default' | 'destructive' | 'info';
  action?: { label: string; onClick: () => void };
  duration?: number;
}) => unknown;

type StatusFetcher = (generation: number) => Promise<GenerationDeliveryStatus>;

export function pendingDelivery(
  result: Pick<EnhancedDeploymentResponse, 'delivery'> | null | undefined,
): GenerationDelivery | null {
  const delivery = result?.delivery;
  return delivery && delivery.state === 'pending' ? delivery : null;
}

/** Toast for a deploy that went live (`success: true`), pending or not. */
export function toastDeployResult(
  toast: ToastFn,
  fetchStatus: StatusFetcher,
  result: Pick<EnhancedDeploymentResponse, 'delivery' | 'message'> | null | undefined,
  fallback: { title: string; description: string },
): void {
  const pending = pendingDelivery(result);
  if (!pending) {
    toast({ title: fallback.title, description: result?.message || fallback.description });
    return;
  }
  toast({
    title: DELIVERY_PENDING_TITLE,
    description: result?.message || `Published generation ${pending.generation}; ingest hosts are still installing it.`,
    variant: 'info',
    duration: 20_000,
    action: { label: 'Re-check', onClick: () => void recheckDelivery(toast, fetchStatus, pending.generation) },
  });
}

/** One re-check of `generation`; toasts the outcome (and another re-check while pending). */
export async function recheckDelivery(
  toast: ToastFn,
  fetchStatus: StatusFetcher,
  generation: number,
): Promise<GenerationDeliveryStatus | null> {
  let status: GenerationDeliveryStatus;
  try {
    status = await fetchStatus(generation);
  } catch (cause) {
    toast({
      title: 'Could not re-check the deploy',
      description: cause instanceof Error ? cause.message : 'The delivery status request failed.',
      variant: 'destructive',
    });
    return null;
  }
  switch (status.state) {
    case 'acknowledged':
    case 'not_applicable':
      toast({ title: 'Deployed', description: status.message });
      break;
    case 'pending':
      toast({
        title: DELIVERY_PENDING_TITLE,
        description: status.message,
        variant: 'info',
        duration: 20_000,
        action: { label: 'Re-check', onClick: () => void recheckDelivery(toast, fetchStatus, generation) },
      });
      break;
    default:
      toast({ title: 'Deploy not confirmed', description: status.message, variant: 'destructive' });
  }
  return status;
}
