// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3219: the tenant-wide AI tuning mode, shared by the settings control,
// the rule editor's Tune action / `@tune` listener and the per-rule
// auto-tune popover. The server enforces the mode; the UI only explains it.

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { AiTuningMode } from '@/lib/api/ai-tuning';

export const AI_TUNING_MODE_QUERY_KEY = ['melod', 'ai-tuning'] as const;

/** Shown wherever Tune is refused because the tenant turned AI tuning off. */
export const AI_TUNING_OFF_EXPLANATION =
  'AI tuning is turned off for this tenant. An administrator can turn it back on in Settings → AI & pivt → Models.';

/**
 * The tenant's AI tuning mode. Defaults to `on` while loading, on error, or
 * when `enabled` is false (open builds / no AI): the backend still refuses
 * anything the mode forbids.
 */
export function useAiTuningMode(enabled = true): { mode: AiTuningMode; isLoading: boolean } {
  const query = useQuery({
    queryKey: AI_TUNING_MODE_QUERY_KEY,
    queryFn: () => api.aiTuning.get(),
    enabled,
    retry: false,
    staleTime: 60_000,
  });
  return { mode: query.data?.ai_tuning_mode ?? 'on', isLoading: enabled && query.isLoading };
}
