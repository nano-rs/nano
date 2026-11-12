// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5309: the Getting Started wizard is INSTANCE setup (sources, parsers,
 * team, SSO). Its checklist reads `/api/onboarding/status` and
 * `/api/system/config`, both gated on `settings:view`. A role without it got
 * the wizard with every card reading "nothing set up" — fallbacks for 403s —
 * and Configure buttons it could not use.
 */
export const INSTANCE_SETUP_PERMISSION = 'settings:view';

export interface SetupRedirectInput {
  isDemoUser: boolean;
  canRunSetup: boolean;
  hasProgress: boolean;
  progressLoading: boolean;
  seenThisSession: boolean;
}

/** Should `/` send this user to /getting-started (first visit only)? */
export function shouldRedirectToSetup(i: SetupRedirectInput): boolean {
  return (
    i.canRunSetup
    && !i.isDemoUser
    && !i.hasProgress
    && !i.progressLoading
    && !i.seenThisSession
  );
}
