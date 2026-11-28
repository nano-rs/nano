// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Dedicated lazy-loaded Sentry Replay chunk (internal/e2e builds only).
// Compiled out by Vite unless VITE_NANO_SENTRY_DSN, VITE_NANO_SENTRY_REPLAY=1,
// and an allowed internal/e2e VITE_NANO_SENTRY_ENVIRONMENT are all set.
import { addIntegration, replayIntegration } from '@sentry/react';
import { REPLAY_MASK_SELECTORS, scrubReplayRecordingEvent, type SentryPayload } from './scrub';

export { REPLAY_MASK_SELECTORS };

export interface ReplayGate {
  replay(event?: SentryPayload): boolean;
}

export function attachReplayIntegration(gate: ReplayGate): void {
  addIntegration(
    replayIntegration({
      maskAllText: true,
      maskAllInputs: true,
      blockAllMedia: true,
      mask: [...REPLAY_MASK_SELECTORS],
      block: [...REPLAY_MASK_SELECTORS],
      networkDetailAllowUrls: [],
      beforeAddRecordingEvent: (event) => scrubReplayRecordingEvent(event),
      beforeErrorSampling: (event) => gate.replay(event as unknown as SentryPayload),
    }),
  );
}
