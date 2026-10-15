// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3208: the rule editor's Tune action and pivt `@tune` dispatch
// `pivt:open-tuning-wizard`. Since NAN-484 removed the legacy editor nothing
// listened for it, so the AI tuning wizard never opened in any deployment
// mode (the analyst only saw a toast). This hook is that listener: the rule
// editor mounts it for the focused rule and opens `AiTuningPanel`.

import { useEffect, useState } from 'react';

export const TUNING_WIZARD_EVENT = 'pivt:open-tuning-wizard' as const;

export interface TuningWizardEventDetail {
  /** Rule the wizard is for. Absent when pivt `@tune` fires on the focused editor. */
  ruleId?: string;
  /** Optional analyst feedback to pre-fill (pivt `@tune <text>`). */
  prompt?: string;
}

export interface TuningWizardRequest {
  /** Bumped on every open so a repeat request re-opens a closed dialog. */
  seq: number;
  prompt?: string;
}

/**
 * Listen for `pivt:open-tuning-wizard` while `ruleId` is the focused rule.
 * Returns the latest request for this rule (or null) and a closer. Events
 * addressed to a different rule are ignored; events without a `ruleId`
 * target the focused rule.
 */
export function useTuningWizardListener(ruleId: string | undefined, enabled: boolean) {
  const [request, setRequest] = useState<TuningWizardRequest | null>(null);

  useEffect(() => {
    if (!enabled || !ruleId) return undefined;
    const handler = (event: Event) => {
      const detail = ((event as CustomEvent<TuningWizardEventDetail | undefined>).detail ?? {}) as TuningWizardEventDetail;
      if (detail.ruleId && detail.ruleId !== ruleId) return;
      const prompt = typeof detail.prompt === 'string' && detail.prompt.trim() ? detail.prompt : undefined;
      setRequest((prev) => ({ seq: (prev?.seq ?? 0) + 1, prompt }));
    };
    window.addEventListener(TUNING_WIZARD_EVENT, handler);
    return () => window.removeEventListener(TUNING_WIZARD_EVENT, handler);
  }, [ruleId, enabled]);

  // Switching rules closes a wizard opened for the previous one.
  useEffect(() => {
    setRequest(null);
  }, [ruleId]);

  return { request, close: () => setRequest(null) } as const;
}
