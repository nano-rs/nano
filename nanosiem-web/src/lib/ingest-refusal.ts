// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3680: rows the lake refused at strict OCSF admission, per source.
 *
 * A refused row parsed fine but never landed, so before this it showed up
 * nowhere a tenant looks. The API now reports the count per source and the
 * newest refusal as a reason code plus the OCSF attribute path (never a row
 * value). These helpers turn that into the one line every surface shows:
 * "100 events refused by OCSF validation (constraint_failed at device)".
 *
 * `null` / `undefined` counts mean the lake does not record refusals per
 * source (lean tenants today): unknown, never shown as zero.
 */

import type { LogSourceRefusalSample } from '@/lib/api/types';

/** `ocsf_constraint_failed` → `constraint_failed`; other codes as they are. */
export function refusalReasonLabel(reason: string): string {
  return reason.startsWith('ocsf_') ? reason.slice('ocsf_'.length) : reason;
}

/** `constraint_failed at device`, or just the reason when no attribute is named. */
export function refusalCause(sample: LogSourceRefusalSample | null | undefined): string | null {
  if (!sample?.reason) return null;
  const reason = refusalReasonLabel(sample.reason);
  return sample.field ? `${reason} at ${sample.field}` : reason;
}

/** True when the count is known and positive. */
export function hasRefusals(count: number | null | undefined): count is number {
  return typeof count === 'number' && count > 0;
}

/** "N events refused by OCSF validation (cause)", or null when there is nothing to say. */
export function refusalSentence(
  count: number | null | undefined,
  sample: LogSourceRefusalSample | null | undefined,
): string | null {
  if (!hasRefusals(count)) return null;
  const cause = refusalCause(sample);
  const noun = count === 1 ? 'event' : 'events';
  return `${count.toLocaleString()} ${noun} refused by OCSF validation${cause ? ` (${cause})` : ''}`;
}
