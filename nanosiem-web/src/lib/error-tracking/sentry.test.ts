// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Verify opt-in error-only Sentry Replay gating, lazy attachment, privacy
// masks/scrubbing, zero session recording, and hard <= 3 replays/session cap.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  init: vi.fn(),
  addIntegration: vi.fn(),
  browserTracingIntegration: vi.fn(() => ({ name: 'BrowserTracing' })),
  consoleLoggingIntegration: vi.fn(() => ({ name: 'ConsoleLogging' })),
  replayIntegration: vi.fn((opts?: Record<string, unknown>) => ({ name: 'Replay', opts })),
  captureException: vi.fn(),
}));

vi.mock('@sentry/react', () => ({
  init: mocks.init,
  addIntegration: mocks.addIntegration,
  browserTracingIntegration: mocks.browserTracingIntegration,
  consoleLoggingIntegration: mocks.consoleLoggingIntegration,
  replayIntegration: mocks.replayIntegration,
  captureException: mocks.captureException,
}));

const DSN = 'https://publickey123@o1.ingest.example.invalid/42';

async function flushDynamicImports(): Promise<void> {
  await vi.dynamicImportSettled();
  await new Promise((r) => setTimeout(r, 0));
}

describe('initSentry error-only Replay gating', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    vi.unstubAllEnvs();
    window.sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  it('does not initialize Replay when VITE_NANO_SENTRY_REPLAY is unset or not "1"', async () => {
    vi.stubEnv('VITE_NANO_SENTRY_DSN', DSN);
    vi.stubEnv('VITE_NANO_SENTRY_ENVIRONMENT', 'e2e');
    const { initSentry } = await import('./sentry');

    initSentry(DSN);
    await flushDynamicImports();
    expect(mocks.replayIntegration).not.toHaveBeenCalled();
    expect(mocks.addIntegration).not.toHaveBeenCalled();
    expect(mocks.init).toHaveBeenCalledTimes(1);
    const initOpts = mocks.init.mock.calls[0][0] as Record<string, unknown>;
    expect(initOpts.replaysSessionSampleRate).toBe(0);
    expect(initOpts.replaysOnErrorSampleRate).toBe(0);

    vi.clearAllMocks();
    vi.stubEnv('VITE_NANO_SENTRY_REPLAY', '0');
    initSentry(DSN);
    await flushDynamicImports();
    expect(mocks.replayIntegration).not.toHaveBeenCalled();
    expect(mocks.addIntegration).not.toHaveBeenCalled();

    vi.clearAllMocks();
    vi.stubEnv('VITE_NANO_SENTRY_REPLAY', 'true');
    initSentry(DSN);
    await flushDynamicImports();
    expect(mocks.replayIntegration).not.toHaveBeenCalled();
    expect(mocks.addIntegration).not.toHaveBeenCalled();
  });

  it('does not initialize Sentry or Replay when VITE_NANO_SENTRY_DSN is unset', async () => {
    vi.stubEnv('VITE_NANO_SENTRY_DSN', '');
    vi.stubEnv('VITE_NANO_SENTRY_REPLAY', '1');
    vi.stubEnv('VITE_NANO_SENTRY_ENVIRONMENT', 'e2e');

    const { SENTRY_ENABLED, startErrorTracking } = await import('./index');
    expect(SENTRY_ENABLED).toBe(false);
    startErrorTracking();
    await flushDynamicImports();
    expect(mocks.init).not.toHaveBeenCalled();
    expect(mocks.replayIntegration).not.toHaveBeenCalled();
    expect(mocks.addIntegration).not.toHaveBeenCalled();

    // Even direct initSentry() requires VITE_NANO_SENTRY_DSN for Replay.
    const { initSentry } = await import('./sentry');
    initSentry(DSN);
    await flushDynamicImports();
    expect(mocks.replayIntegration).not.toHaveBeenCalled();
    expect(mocks.addIntegration).not.toHaveBeenCalled();
  });

  it('refuses Replay when VITE_NANO_SENTRY_ENVIRONMENT is unset or empty (no fallback to local)', async () => {
    vi.stubEnv('VITE_NANO_SENTRY_DSN', DSN);
    vi.stubEnv('VITE_NANO_SENTRY_REPLAY', '1');

    const { initSentry, isReplayEnabled } = await import('./sentry');
    expect(isReplayEnabled(DSN)).toBe(false);
    initSentry(DSN);
    await flushDynamicImports();
    expect(mocks.replayIntegration).not.toHaveBeenCalled();
    expect(mocks.addIntegration).not.toHaveBeenCalled();
    const unsetOpts = mocks.init.mock.calls[0][0] as Record<string, unknown>;
    expect(unsetOpts.replaysSessionSampleRate).toBe(0);
    expect(unsetOpts.replaysOnErrorSampleRate).toBe(0);

    vi.clearAllMocks();
    vi.stubEnv('VITE_NANO_SENTRY_ENVIRONMENT', '');
    expect(isReplayEnabled(DSN)).toBe(false);
    initSentry(DSN);
    await flushDynamicImports();
    expect(mocks.replayIntegration).not.toHaveBeenCalled();
    expect(mocks.addIntegration).not.toHaveBeenCalled();
  });

  it('lazily attaches error-only Replay with strict masks, scrubbing, 0% session rate, 0.25 default error rate, and <= 3 cap', async () => {
    vi.stubEnv('VITE_NANO_SENTRY_DSN', DSN);
    vi.stubEnv('VITE_NANO_SENTRY_REPLAY', '1');
    vi.stubEnv('VITE_NANO_SENTRY_ENVIRONMENT', 'e2e');

    const randomSpy = vi.spyOn(Math, 'random');
    const {
      DEFAULT_REPLAY_ON_ERROR_RATE,
      initSentry,
      MAX_REPLAYS_PER_SESSION,
      REPLAY_MASK_SELECTORS,
    } = await import('./sentry');
    initSentry(DSN);
    await flushDynamicImports();

    expect(MAX_REPLAYS_PER_SESSION).toBe(3);
    expect(DEFAULT_REPLAY_ON_ERROR_RATE).toBe(0.25);
    expect(mocks.replayIntegration).toHaveBeenCalledTimes(1);
    expect(mocks.addIntegration).toHaveBeenCalledTimes(1);
    expect((mocks.addIntegration.mock.calls[0][0] as { name: string }).name).toBe('Replay');

    const replayOpts = mocks.replayIntegration.mock.calls[0][0] as Record<string, unknown>;
    expect(replayOpts.maskAllText).toBe(true);
    expect(replayOpts.maskAllInputs).toBe(true);
    expect(replayOpts.blockAllMedia).toBe(true);
    expect(replayOpts.mask).toEqual([
      '[data-secret]',
      'input[type="password"]',
      '[data-testid*="token"]',
      '[data-testid*="secret"]',
    ]);
    expect(replayOpts.mask).toEqual([...REPLAY_MASK_SELECTORS]);
    expect(replayOpts.block).toEqual([...REPLAY_MASK_SELECTORS]);
    expect(replayOpts.networkDetailAllowUrls).toEqual([]);
    expect(typeof replayOpts.beforeAddRecordingEvent).toBe('function');
    expect(typeof replayOpts.beforeErrorSampling).toBe('function');

    // Recording event callback scrubs tokens, nit_ keys, JWTs, and Bearer headers.
    const beforeAddRecordingEvent = replayOpts.beforeAddRecordingEvent as (e: Record<string, unknown>) => Record<string, unknown>;
    const scrubbed = beforeAddRecordingEvent({
      data: {
        payload: {
          message: 'GET /api/auth?token=secret123 nit_ABCDEFGHIJ0123456789',
          headers: { Authorization: 'Bearer supersecrettoken12345' },
          jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk',
          path: '/cases/42',
        },
      },
    });
    const serialized = JSON.stringify(scrubbed);
    expect(serialized).not.toContain('secret123');
    expect(serialized).not.toContain('nit_ABCDEFGHIJ');
    expect(serialized).not.toContain('supersecrettoken12345');
    expect(serialized).not.toContain('eyJhbGci');
    expect(serialized).toContain('/cases/42');

    // Static init() keeps Replay out of initial integrations array and passes the default 0.25 rate directly.
    const initOpts = mocks.init.mock.calls[0][0] as Record<string, unknown>;
    expect(initOpts.replaysSessionSampleRate).toBe(0);
    expect(initOpts.replaysOnErrorSampleRate).toBe(0.25);
    expect((initOpts.integrations as Array<{ name: string }>).map((i) => i.name)).not.toContain('Replay');

    // Enforce <= 3 replays per browser session, skip benign errors, and do not re-roll Math.random().
    const beforeErrorSampling = replayOpts.beforeErrorSampling as (e: Record<string, unknown>) => boolean;
    expect(beforeErrorSampling({ message: 'ResizeObserver loop limit exceeded' })).toBe(false);
    expect(beforeErrorSampling({ message: 'crash 1' })).toBe(true);
    expect(beforeErrorSampling({ message: 'crash 2' })).toBe(true);
    expect(beforeErrorSampling({ message: 'crash 3' })).toBe(true);
    expect(beforeErrorSampling({ message: 'crash 4' })).toBe(false);
    expect(randomSpy).not.toHaveBeenCalled();

    // Reloading the page in the same session still enforces the cap.
    vi.clearAllMocks();
    initSentry(DSN);
    await flushDynamicImports();
    const replayOptsAfterReload = mocks.replayIntegration.mock.calls[0][0] as Record<string, unknown>;
    const afterReload = replayOptsAfterReload.beforeErrorSampling as (e: Record<string, unknown>) => boolean;
    expect(afterReload({ message: 'crash 5 after reload' })).toBe(false);
  });

  it('passes configured VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE directly to init and disables Replay when <= 0', async () => {
    vi.stubEnv('VITE_NANO_SENTRY_DSN', DSN);
    vi.stubEnv('VITE_NANO_SENTRY_REPLAY', '1');
    vi.stubEnv('VITE_NANO_SENTRY_ENVIRONMENT', 'e2e');
    vi.stubEnv('VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE', '0.5');

    const randomSpy = vi.spyOn(Math, 'random');
    const { initSentry } = await import('./sentry');
    initSentry(DSN);
    await flushDynamicImports();

    const initOpts = mocks.init.mock.calls[0][0] as Record<string, unknown>;
    expect(initOpts.replaysSessionSampleRate).toBe(0);
    expect(initOpts.replaysOnErrorSampleRate).toBe(0.5);

    const replayOpts = mocks.replayIntegration.mock.calls[0][0] as Record<string, unknown>;
    const beforeErrorSampling = replayOpts.beforeErrorSampling as (e: Record<string, unknown>) => boolean;
    expect(beforeErrorSampling({ message: 'sampled by SDK 1' })).toBe(true);
    expect(beforeErrorSampling({ message: 'sampled by SDK 2' })).toBe(true);
    expect(beforeErrorSampling({ message: 'sampled by SDK 3' })).toBe(true);
    expect(beforeErrorSampling({ message: 'sampled by SDK 4' })).toBe(false);
    expect(randomSpy).not.toHaveBeenCalled();

    // Out-of-range values clamp to [0, 1].
    vi.clearAllMocks();
    window.sessionStorage.clear();
    vi.stubEnv('VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE', '2.5');
    initSentry(DSN);
    await flushDynamicImports();
    expect((mocks.init.mock.calls[0][0] as Record<string, unknown>).replaysOnErrorSampleRate).toBe(1);
    expect((mocks.init.mock.calls[0][0] as Record<string, unknown>).replaysSessionSampleRate).toBe(0);

    // Rate "0" and negative rates disable Replay loading completely.
    for (const disabledRate of ['0', '0.0', '-0.5']) {
      vi.clearAllMocks();
      window.sessionStorage.clear();
      vi.stubEnv('VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE', disabledRate);
      initSentry(DSN);
      await flushDynamicImports();
      expect(mocks.replayIntegration).not.toHaveBeenCalled();
      expect(mocks.addIntegration).not.toHaveBeenCalled();
      expect((mocks.init.mock.calls[0][0] as Record<string, unknown>).replaysOnErrorSampleRate).toBe(0);
    }
  });

  it.each(['production', 'customer', 'staging', 'tenant', 'prod'])(
    'never initializes Replay in %s environment even when VITE_NANO_SENTRY_REPLAY="1"',
    async (envName) => {
      vi.stubEnv('VITE_NANO_SENTRY_DSN', DSN);
      vi.stubEnv('VITE_NANO_SENTRY_REPLAY', '1');
      vi.stubEnv('VITE_NANO_SENTRY_ENVIRONMENT', envName);

      const { initSentry } = await import('./sentry');
      initSentry(DSN);
      await flushDynamicImports();
      expect(mocks.replayIntegration).not.toHaveBeenCalled();
      expect(mocks.addIntegration).not.toHaveBeenCalled();
      const initOpts = mocks.init.mock.calls[0][0] as Record<string, unknown>;
      expect(initOpts.replaysSessionSampleRate).toBe(0);
      expect(initOpts.replaysOnErrorSampleRate).toBe(0);
      expect((initOpts.integrations as Array<{ name: string }>).map((i) => i.name)).not.toContain('Replay');
    },
  );

  it.each(['local', 'e2e', 'internal'])(
    'allows error-only Replay in %s environment when DSN and flag are set',
    async (envName) => {
      vi.stubEnv('VITE_NANO_SENTRY_DSN', DSN);
      vi.stubEnv('VITE_NANO_SENTRY_REPLAY', '1');
      vi.stubEnv('VITE_NANO_SENTRY_ENVIRONMENT', envName);

      const { initSentry } = await import('./sentry');
      initSentry(DSN);
      await flushDynamicImports();
      expect(mocks.replayIntegration).toHaveBeenCalledTimes(1);
      expect(mocks.addIntegration).toHaveBeenCalledTimes(1);
      const initOpts = mocks.init.mock.calls[0][0] as Record<string, unknown>;
      expect(initOpts.replaysSessionSampleRate).toBe(0);
      expect(initOpts.replaysOnErrorSampleRate).toBe(0.25);
    },
  );
});
