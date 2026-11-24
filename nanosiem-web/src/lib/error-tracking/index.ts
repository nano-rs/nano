// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5798: opt-in Sentry error tracking for local and e2e builds.
//
// The SPA has no runtime config, so the DSN is a BUILD-time value:
// `VITE_NANO_SENTRY_DSN`. nano's release builds never set it, so there it is
// "", `SENTRY_ENABLED` is false and nothing initializes or is sent. The SDK
// lives in a lazy chunk (./sentry.ts), loaded only when a DSN is set.
// Generic SENTRY_* variables are never read.
export const SENTRY_ENABLED: boolean = Boolean(import.meta.env.VITE_NANO_SENTRY_DSN);

/** `/_sentry-test` renders a component that throws (e2e/dev builds only). */
export const SENTRY_TEST_TRIGGER: boolean = SENTRY_ENABLED && import.meta.env.VITE_NANO_SENTRY_TEST_TRIGGER === '1';

export const SENTRY_TEST_PATH = '/_sentry-test';

export function startErrorTracking(): void {
  if (!SENTRY_ENABLED) return;
  const dsn = import.meta.env.VITE_NANO_SENTRY_DSN as string;
  void import('./sentry')
    .then((m) => {
      m.initSentry(dsn);
      if (SENTRY_TEST_TRIGGER && window.location.pathname === SENTRY_TEST_PATH) {
        // The global handler path: an unhandled rejection.
        void Promise.reject(new Error(`Sentry test error web-rejection ${Date.now()}`));
      }
    })
    .catch(() => {
      // Error tracking is best effort; the app runs without it.
    });
}

/** Rendered at SENTRY_TEST_PATH: the error-boundary path. */
export function SentryTestThrow(): never {
  throw new Error(`Sentry test error web-render ${Date.now()}`);
}
