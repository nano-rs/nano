// SPDX-License-Identifier: AGPL-3.0-or-later

import type { EventCompleteness } from '@/lib/api/types';

export function CompletenessWatermark({ completeness }: { completeness?: EventCompleteness }) {
  const watermark = completeness?.events_complete_through_ms;
  if (watermark == null) return null;
  const time = new Date(watermark);
  if (!Number.isFinite(time.getTime())) return null;
  const timestamp = time.toISOString();
  return (
    <span
      className="font-mono text-[10.5px] text-muted-foreground normal-case tracking-normal font-normal"
      title={`Complete through ${timestamp}${completeness?.reason ? ` (${completeness.reason})` : ''}`}
    >
      complete through {timestamp.slice(11, 19)}Z
    </span>
  );
}
