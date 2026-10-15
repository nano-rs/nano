// SPDX-License-Identifier: AGPL-3.0-or-later

import type { PlatformManagedSetting } from '@/lib/api';

/** Narrow a settings response to its verdict, if the API attached one. */
export function platformManaged(value: unknown): PlatformManagedSetting | null {
  if (!value || typeof value !== 'object') return null;
  const verdict = (value as { managed_by_platform?: unknown }).managed_by_platform;
  if (!verdict || typeof verdict !== 'object') return null;
  const v = verdict as Partial<PlatformManagedSetting>;
  return v.managed_by === 'platform' && v.reason === 'managed_by_platform' ? (v as PlatformManagedSetting) : null;
}
