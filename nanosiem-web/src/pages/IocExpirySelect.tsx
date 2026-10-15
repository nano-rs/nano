// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3882 — optional indicator expiry: Never, 7/30/90 days, or a custom
// date/time. Expired indicators stop matching (ingest, hunts, the TI flyout)
// but stay in the list for history.

import { cn } from '@/lib/utils';

export type ExpiryChoice = 'never' | '7d' | '30d' | '90d' | 'custom';

export interface ExpiryValue {
  choice: ExpiryChoice;
  /** `datetime-local` value (local time) when `choice` is `custom`. */
  custom: string;
}

export const NO_EXPIRY: ExpiryValue = { choice: 'never', custom: '' };

const DAYS: Record<Exclude<ExpiryChoice, 'never' | 'custom'>, number> = { '7d': 7, '30d': 30, '90d': 90 };

/**
 * The expiry as an RFC 3339 instant, `null` for never, or `undefined` when
 * the custom value is missing, unparseable or not in the future.
 */
export function expiryInstant(value: ExpiryValue, now: Date = new Date()): string | null | undefined {
  if (value.choice === 'never') return null;
  if (value.choice === 'custom') {
    if (!value.custom) return undefined;
    const at = new Date(value.custom);
    if (isNaN(at.getTime()) || at.getTime() <= now.getTime()) return undefined;
    return at.toISOString();
  }
  return new Date(now.getTime() + DAYS[value.choice] * 86_400_000).toISOString();
}

export function ExpirySelect({
  value, onChange, className, label = 'Expires',
}: { value: ExpiryValue; onChange: (value: ExpiryValue) => void; className?: string; label?: string }) {
  const invalid = value.choice === 'custom' && expiryInstant(value) === undefined;
  return (
    <span className={cn('flex items-center gap-1', className)}>
      <select
        aria-label={label}
        value={value.choice}
        onChange={(e) => onChange({ ...value, choice: e.target.value as ExpiryChoice })}
        className="h-[24px] px-1 rounded border border-border bg-card text-[10.5px] font-mono"
      >
        <option value="never">never</option>
        <option value="7d">7 days</option>
        <option value="30d">30 days</option>
        <option value="90d">90 days</option>
        <option value="custom">custom…</option>
      </select>
      {value.choice === 'custom' && (
        <input
          type="datetime-local"
          aria-label={`${label} at`}
          aria-invalid={invalid}
          value={value.custom}
          onChange={(e) => onChange({ ...value, custom: e.target.value })}
          className={cn(
            'h-[24px] px-1 rounded border bg-card text-[10.5px] font-mono',
            invalid ? 'border-destructive' : 'border-border',
          )}
        />
      )}
    </span>
  );
}
