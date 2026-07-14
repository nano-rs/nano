import { useMemo } from 'react';

import { formatBucketLabel } from '../lib/time';
import type { HistogramBucket } from '../lib/types';

const AXIS_LABELS = 6;

export function Histogram({ buckets }: { buckets: HistogramBucket[] }) {
  const max = useMemo(
    () => buckets.reduce((peak, bucket) => Math.max(peak, bucket.count), 0),
    [buckets]
  );

  const axis = useMemo(() => {
    if (buckets.length === 0) return [];
    const step = Math.max(1, Math.floor(buckets.length / (AXIS_LABELS - 1)));
    return buckets.filter((_, index) => index % step === 0).slice(0, AXIS_LABELS);
  }, [buckets]);

  if (buckets.length === 0) return null;

  return (
    <div className="shrink-0">
      <div className="flex h-[120px] items-end gap-[3px] px-[18px] pt-4 pb-1.5">
        {buckets.map((bucket) => (
          <div
            key={bucket.time}
            title={`${formatBucketLabel(bucket.time)} · ${bucket.count.toLocaleString()}`}
            // A non-zero bucket must never render as nothing — a 1-event bucket
            // in a 10k-event window is exactly what an analyst is hunting for.
            style={{ height: `${max > 0 ? Math.max(2, (bucket.count / max) * 100) : 0}%` }}
            className="flex-1 rounded-t-[2px] bg-accent opacity-85 hover:opacity-100"
          />
        ))}
      </div>
      <div className="flex justify-between px-[18px] pb-2 font-mono text-[10.5px] text-t4">
        {axis.map((bucket) => (
          <span key={bucket.time}>{formatBucketLabel(bucket.time)}</span>
        ))}
      </div>
    </div>
  );
}
