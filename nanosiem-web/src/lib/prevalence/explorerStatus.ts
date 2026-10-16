import type { ArtifactExplorerResponse } from '@/lib/api/types';

export function explorerStatusLabel(state: ArtifactExplorerResponse['product_state']): string | null {
  if (state?.warming) {
    const seconds = state.retry_after_s;
    if (seconds !== undefined && Number.isFinite(seconds) && seconds > 0) {
      return `Warming up — first results in about ${Math.max(1, Math.ceil(seconds / 60))} min after artifact events arrive.`;
    }
    return 'Warming up — waiting for the first artifact results.';
  }
  return state?.stale ? 'Showing an older snapshot — waiting for refreshed results.' : null;
}
