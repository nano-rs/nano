// SPDX-License-Identifier: AGPL-3.0-or-later

/** NAN-3512: monthly AI allowance (lean AI soft cap) helpers. */

/** The lean plan page in the nano portal, where the AI dial is raised. */
export const RAISE_AI_URL = 'https://app.nano.rs/pricing?lean=1';
export const AI_ALLOWANCE_WARNING_RATIO = 0.8;

export type AiAllowanceState = 'ok' | 'warning' | 'paused' | 'off';

/** Same wording as the server's AI-disabled 403 (NAN-3090 `AI_NOT_ENABLED_MESSAGE`). */
export const AI_NOT_ENABLED_MESSAGE = 'AI is not enabled for this tenant';

export function aiAllowanceState(used: number, limit: number | null): AiAllowanceState {
  if (limit === null) return 'ok';
  // A zero allowance is "No AI" (or an ended plan), not a spent one.
  if (limit === 0) return 'off';
  if (used >= limit) return 'paused';
  if (used >= limit * AI_ALLOWANCE_WARNING_RATIO) return 'warning';
  return 'ok';
}

/** First instant of the next UTC month: when the monthly allowance resets. */
export function nextAiAllowanceReset(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
}

/** Same wording as the server's 429 (`ai_allowance_paused_message`). */
export function aiAllowancePausedMessage(now: Date): string {
  const date = nextAiAllowanceReset(now).toLocaleDateString('en-US', {
    timeZone: 'UTC',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  return (
    `You've used this month's AI allowance. AI features are paused until ${date} ` +
    'or until you raise your AI allowance. Search, detection and alerting keep running.'
  );
}
