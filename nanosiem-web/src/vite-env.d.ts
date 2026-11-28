// SPDX-License-Identifier: AGPL-3.0-or-later

/// <reference types="vite/client" />

declare const __APP_VERSION__: string;
declare const __EDITION__: 'open' | 'enterprise';

// NAN-5798: opt-in error tracking (local/e2e builds only; see lib/error-tracking).
interface ImportMetaEnv {
  readonly VITE_NANO_SENTRY_DSN?: string;
  readonly VITE_NANO_SENTRY_ENVIRONMENT?: string;
  readonly VITE_NANO_SENTRY_RELEASE?: string;
  readonly VITE_NANO_SENTRY_TRACES_SAMPLE_RATE?: string;
  readonly VITE_NANO_SENTRY_TEST_TRIGGER?: string;
  readonly VITE_NANO_SENTRY_REPLAY?: string;
  readonly VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE?: string;
}
