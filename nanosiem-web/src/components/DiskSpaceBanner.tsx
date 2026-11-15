// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5450: low disk space, in front of every admin on every page.
 *
 * Driven by `GET /api/system/disk-alert` (polled every minute for
 * `settings:system` holders). Tiers, decided server-side:
 *
 * - `warning` (80 %): nothing here; SIEM Health and Settings -> Storage show it.
 * - `critical` (90 %, or forecast to fill within 24 hours): amber banner. An
 *   admin can snooze it for an hour; it comes back until the disk is fixed.
 * - `imminent` (95 %, under 5 % free): red, cannot be dismissed, with the
 *   forecast, what happens next, and whether ingestion is paused.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { HardDrive, X } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/utils';
import {
  DISK_ALERT_QUERY_KEY,
  DISK_BANNER_SNOOZE_MS,
  DISK_BANNER_SNOOZED_KEY,
  DISK_FULL_RUNBOOK_URL,
  diskLabel,
  hoursText,
  percentText,
} from '@/lib/disk-alert';

/** NAN-5450: the ClickHouse forecast counts to the ingest pause, not to 100 %. */
function untilText(fullFraction: number | undefined): string {
  return fullFraction !== undefined && fullFraction < 1
    ? `until ingestion pauses at ${Math.round(fullFraction * 100)}%`
    : 'until full';
}

function readSnoozedUntil(): number {
  try {
    return Number(window.localStorage.getItem(DISK_BANNER_SNOOZED_KEY) ?? 0) || 0;
  } catch {
    return 0;
  }
}

function writeSnoozedUntil(until: number) {
  try {
    window.localStorage.setItem(DISK_BANNER_SNOOZED_KEY, String(until));
  } catch {
    // Storage blocked: the snooze lasts until the next render cycle only.
  }
}

export function DiskSpaceBanner() {
  const { hasPermission } = useAuth();
  const enabled = hasPermission('settings:system');
  const [snoozedUntil, setSnoozedUntil] = useState<number>(() => readSnoozedUntil());

  const { data: alert } = useQuery({
    queryKey: DISK_ALERT_QUERY_KEY,
    queryFn: () => api.systemHealth.getDiskAlert(),
    enabled,
    staleTime: 30_000,
    refetchInterval: 60_000,
    retry: false,
  });

  if (!enabled || !alert) return null;
  const imminent = alert.level === 'imminent';
  if (!imminent && alert.level !== 'critical') return null;
  if (!imminent && snoozedUntil > Date.now()) return null;

  const worst = alert.disks[0];
  if (!worst) return null;
  const hours = worst.forecast?.hours_to_full;
  const others = alert.disks.length - 1;

  return (
    <div
      role={imminent ? 'alert' : 'status'}
      data-testid="disk-banner"
      data-level={alert.level}
      className={cn(
        'mx-6 mt-3 flex items-start justify-between gap-3 rounded-md border px-3 py-2 text-[12px]',
        imminent
          ? 'border-red-300 bg-red-50 text-red-900 dark:border-red-500/40 dark:bg-red-500/15 dark:text-red-100'
          : 'border-amber-200 bg-amber-50/80 dark:border-amber-500/30 dark:bg-amber-500/10',
      )}
    >
      <div className="flex min-w-0 items-start gap-2.5">
        <HardDrive
          className={cn('mt-0.5 h-4 w-4 shrink-0', imminent ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400')}
          strokeWidth={1.5}
        />
        <div className="min-w-0 space-y-0.5">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-medium">
              {imminent ? 'Disk almost full' : worst.forecast?.escalated ? 'Disk filling fast' : 'Disk critically full'}
            </span>
            <span className="text-muted-foreground">{diskLabel(worst)}</span>
            <span className="font-mono text-[11px] tabular-nums" data-testid="disk-banner-usage">
              {percentText(worst.usage_fraction)} used
            </span>
            {hours !== undefined && (
              <span className="font-mono text-[11px] tabular-nums" data-testid="disk-banner-forecast">
                about {hoursText(hours)} {untilText(worst.forecast?.full_fraction)}
              </span>
            )}
            {others > 0 && (
              <span className="font-mono text-[10.5px] text-muted-foreground">
                +{others} more
              </span>
            )}
          </div>
          {alert.ingestion_paused ? (
            <p data-testid="disk-banner-paused">
              <span className="font-medium">Ingestion is paused</span>
              {alert.ingestion_pause_source === 'disk_pressure' ? ' by disk pressure' : ''}: senders get 503 and
              retry; nothing new is stored until space is freed.
            </p>
          ) : (
            <p className="text-muted-foreground" data-testid="disk-banner-next">
              {imminent
                ? 'Next: ingest will pause, and the oldest data will be dropped to make room. Free space or grow the disk now.'
                : 'If it keeps filling, ingest pauses and the oldest data is dropped. Free space or grow the disk.'}
            </p>
          )}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <Link to="/settings/storage" className="text-primary hover:underline">
          Storage
        </Link>
        <a href={DISK_FULL_RUNBOOK_URL} target="_blank" rel="noopener noreferrer" className="font-medium text-primary hover:underline">
          Disk-full runbook
        </a>
        {!imminent && (
          <button
            onClick={() => {
              const until = Date.now() + DISK_BANNER_SNOOZE_MS;
              writeSnoozedUntil(until);
              setSnoozedUntil(until);
            }}
            className="rounded p-1 text-muted-foreground hover:bg-muted"
            aria-label="Snooze disk warning for an hour"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}

/** NAN-5450: the 80 %+ notice on Settings -> Storage (no dismissal). */
export function DiskUsageNotice() {
  const { hasPermission } = useAuth();
  const enabled = hasPermission('settings:system');
  const { data: alert } = useQuery({
    queryKey: DISK_ALERT_QUERY_KEY,
    queryFn: () => api.systemHealth.getDiskAlert(),
    enabled,
    staleTime: 30_000,
    refetchInterval: 60_000,
    retry: false,
  });
  if (!enabled || !alert || alert.disks.length === 0) return null;
  const imminent = alert.level === 'imminent';
  return (
    <div
      role="status"
      data-testid="disk-usage-notice"
      className={cn(
        'rounded-md border px-3 py-2 text-[12px]',
        imminent
          ? 'border-red-300 bg-red-50 dark:border-red-500/40 dark:bg-red-500/15'
          : 'border-amber-200 bg-amber-50/80 dark:border-amber-500/30 dark:bg-amber-500/10',
      )}
    >
      <p className="font-medium">
        {alert.disks.length === 1 ? 'A data disk is' : `${alert.disks.length} data disks are`} above{' '}
        {Math.round(alert.warn_fraction * 100)}%
      </p>
      <ul className="mt-1 space-y-0.5">
        {alert.disks.map((d) => (
          <li key={`${d.component}:${d.host ?? '-'}:${d.name}`} className="flex flex-wrap gap-x-2">
            <span>{diskLabel(d)}</span>
            <span className="font-mono text-[11px] tabular-nums">{percentText(d.usage_fraction)}</span>
            {d.forecast?.hours_to_full !== undefined && (
              <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
                {d.forecast.full_fraction !== undefined && d.forecast.full_fraction < 1
                  ? `ingestion pauses in about ${hoursText(d.forecast.hours_to_full)}`
                  : `full in about ${hoursText(d.forecast.hours_to_full)}`}
              </span>
            )}
          </li>
        ))}
      </ul>
      <a href={DISK_FULL_RUNBOOK_URL} target="_blank" rel="noopener noreferrer" className="mt-1 inline-block text-primary hover:underline">
        Disk-full runbook
      </a>
    </div>
  );
}
