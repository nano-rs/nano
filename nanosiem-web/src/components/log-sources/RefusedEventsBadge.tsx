// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3680: "N refused" next to a source's event count. The full sentence
 * ("100 events refused by OCSF validation (constraint_failed at device)")
 * is the tooltip in `compact` mode and the text otherwise. Renders nothing
 * when the count is unknown (the lake does not record refusals per source)
 * or zero.
 */

import type { LogSourceRefusalSample } from '@/lib/api/types';
import { formatCompactNumber } from '@/lib/date-utils';
import { hasRefusals, refusalCause, refusalSentence } from '@/lib/ingest-refusal';
import { cn } from '@/lib/utils';

export function RefusedEventsBadge({
  count,
  sample,
  compact = false,
  className,
}: {
  count: number | null | undefined;
  sample?: LogSourceRefusalSample | null;
  compact?: boolean;
  className?: string;
}) {
  if (!hasRefusals(count)) return null;
  const sentence = refusalSentence(count, sample) ?? '';
  if (compact) {
    return (
      <span className={cn('text-[10px] font-mono text-red-500 tabular-nums', className)} title={sentence} data-testid="refused-events-badge">
        {formatCompactNumber(count)} refused
      </span>
    );
  }
  const cause = refusalCause(sample);
  return (
    <span className={cn('text-[11px]', className)} data-testid="refused-events-badge" title={sentence}>
      <span className="font-mono text-red-500 tabular-nums">{count.toLocaleString()}</span>
      <span className="text-muted-foreground"> {count === 1 ? 'event' : 'events'} refused by OCSF validation</span>
      {cause && <span className="font-mono text-muted-foreground"> ({cause})</span>}
    </span>
  );
}
