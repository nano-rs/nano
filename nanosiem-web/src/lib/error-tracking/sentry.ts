// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5798: the ONLY module that imports @sentry/react, loaded lazily by
// ./index.ts and only when the build carries VITE_NANO_SENTRY_DSN.
import * as Sentry from '@sentry/react';
import { setErrorReporter } from './reporter';
import { createGate, scrubCrumb, sessionCounterStore, type Crumb, type LogLike, type SentryPayload } from './scrub';

/** Set by the e2e UI driver (evaluateOnNewDocument): run and test identity. */
interface E2eContext { runId?: string; test?: string }

function e2eContext(): E2eContext {
  const ctx = (window as unknown as { __NANO_E2E__?: E2eContext }).__NANO_E2E__;
  return ctx && typeof ctx === 'object' ? ctx : {};
}

function tagValue(v: unknown): string | undefined {
  if (typeof v !== 'string' || !v) return undefined;
  // Printable only: drop control characters (code points below 0x20).
  return Array.from(v).filter((c) => c.charCodeAt(0) >= 0x20).join('').slice(0, 200);
}

function tracesSampleRate(environment: string): number {
  const configured = import.meta.env.VITE_NANO_SENTRY_TRACES_SAMPLE_RATE as string | undefined;
  const raw = Number(configured);
  if (configured !== undefined && configured !== '' && Number.isFinite(raw)) {
    return Math.min(1, Math.max(0, raw));
  }
  return environment === 'local' || environment === 'e2e' ? 1.0 : 0.1;
}

export function initSentry(dsn: string): void {
  const environment = import.meta.env.VITE_NANO_SENTRY_ENVIRONMENT || 'local';
  const release = import.meta.env.VITE_NANO_SENTRY_RELEASE || `nano-web@${__APP_VERSION__}`;
  const tags = (): Record<string, string> => {
    const ctx = e2eContext();
    const out: Record<string, string> = { service: 'nano-web' };
    const runId = tagValue(ctx.runId);
    const test = tagValue(ctx.test);
    if (runId) out.run_id = runId;
    if (test) out.test = test;
    return out;
  };
  const gate = createGate({
    maxPerIssue: 5,
    maxEvents: 50,
    maxTransactions: 500,
    maxLogs: 500,
    tags,
    store: sessionCounterStore(),
  });

  Sentry.init({
    dsn,
    environment,
    release,
    // The send_default_pii=false equivalent (SDK 11 replaced sendDefaultPii
    // with dataCollection): no user info, cookies, headers or bodies.
    // Everything else is the SDK default; beforeSend* removes secrets.
    dataCollection: {
      userInfo: false,
      cookies: false,
      httpHeaders: false,
      httpBodies: [],
    },
    tracesSampleRate: tracesSampleRate(environment),
    // SDK 11 streams spans by default, which skips beforeSendTransaction and
    // so the secret scrubber (trial 1 console warning). Static: whole
    // transactions, gated below.
    traceLifecycle: 'static',
    // Trace headers only to this origin's API, never to third parties.
    tracePropagationTargets: [/^\/(?!\/)/, window.location.origin],
    maxBreadcrumbs: 50,
    integrations: [
      // History-API navigation and page loads (the app uses <BrowserRouter>,
      // which needs no router wrapper for this).
      Sentry.browserTracingIntegration(),
      // Console warn/error as Sentry logs (secrets scrubbed in beforeSendLog).
      Sentry.consoleLoggingIntegration({ levels: ['warn', 'error'] }),
    ],
    beforeSend: (event) => gate.event(event as unknown as SentryPayload) as unknown as typeof event | null,
    beforeSendTransaction: (event) => gate.transaction(event as unknown as SentryPayload) as unknown as typeof event | null,
    beforeBreadcrumb: (crumb) => scrubCrumb(crumb as Crumb) as typeof crumb,
    beforeSendLog: (log) => gate.log(log as unknown as LogLike) as unknown as typeof log | null,
  });

  setErrorReporter({
    captureBoundary(error, componentStack) {
      Sentry.captureException(error, {
        contexts: { react: { componentStack } },
        tags: { boundary: 'route' },
      });
    },
  });
}
