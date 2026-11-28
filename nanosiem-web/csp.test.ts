// Guards the production CSP against drifting from the inline theme script in
// index.html: the browser blocks an inline script whose sha256 is not listed.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  applyCsp,
  assertInlineScriptsAllowed,
  extractInlineScripts,
  isSentryReplayBuildEnabled,
  scriptSrcOf,
  sentryConnectOrigin,
} from './csp';

const indexHtml = readFileSync(path.resolve(__dirname, 'index.html'), 'utf8');

function sha256Source(body: string): string {
  return `'sha256-${createHash('sha256').update(body, 'utf8').digest('base64')}'`;
}

describe('index.html CSP', () => {
  it('has exactly one inline script (the theme initializer)', () => {
    const scripts = extractInlineScripts(indexHtml);
    expect(scripts).toHaveLength(1);
    expect(scripts[0]).toContain('nanosiem-theme');
  });

  it('production script-src contains the sha256 of the inline theme script', () => {
    const [themeScript] = extractInlineScripts(indexHtml);
    const built = applyCsp(indexHtml, false);
    const scriptSrc = scriptSrcOf(built);
    expect(scriptSrc).not.toBeNull();
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(scriptSrc!.split(/\s+/)).toContain(sha256Source(themeScript));
    expect(() => assertInlineScriptsAllowed(built)).not.toThrow();
  });

  it('dev keeps unsafe-inline for HMR', () => {
    expect(scriptSrcOf(applyCsp(indexHtml, true))).toContain("'unsafe-inline'");
  });

  it('fails when an inline script changes after the CSP is computed', () => {
    const built = applyCsp(indexHtml, false);
    const tampered = built.replace("'nanosiem-theme'", "'nanosiem-theme-x'");
    expect(() => assertInlineScriptsAllowed(tampered)).toThrow(/not allowed by script-src/);
  });

  it('ignores external scripts', () => {
    expect(extractInlineScripts('<script type="module" src="/a.js"></script>')).toEqual([]);
  });

  // When a production build exists, check the emitted file too.
  const dist = path.resolve(__dirname, 'dist/index.html');
  it.skipIf(!existsSync(dist))('built dist/index.html allows its inline scripts', () => {
    const html = readFileSync(dist, 'utf8');
    expect(extractInlineScripts(html).length).toBeGreaterThan(0);
    expect(() => assertInlineScriptsAllowed(html)).not.toThrow();
  });
});

// NAN-5798: an opt-in Sentry DSN adds exactly its origin to connect-src; every
// other build keeps connect-src 'self'.
describe('sentry connect-src', () => {
  it('is empty without a DSN', () => {
    expect(sentryConnectOrigin(undefined)).toEqual([]);
    expect(sentryConnectOrigin('')).toEqual([]);
    expect(sentryConnectOrigin('not a url')).toEqual([]);
    expect(sentryConnectOrigin('javascript:alert(1)')).toEqual([]);
  });

  it('adds only the DSN origin (never the key or path)', () => {
    const origins = sentryConnectOrigin('https://publickey@o1.ingest.us.sentry.io/42');
    expect(origins).toEqual(['https://o1.ingest.us.sentry.io']);
    const html = applyCsp(indexHtml, false, origins);
    expect(html).toContain("connect-src 'self' https://o1.ingest.us.sentry.io;");
    expect(html).not.toContain('publickey');
    expect(applyCsp(indexHtml, false)).toContain("connect-src 'self';");
  });

  it('adds worker-src blob: strictly in Replay-enabled builds and leaves customer CSP byte-identical', () => {
    const origins = sentryConnectOrigin('https://publickey@o1.ingest.us.sentry.io/42');
    const customerHtml = applyCsp(indexHtml, false);
    const dsnOnlyHtml = applyCsp(indexHtml, false, origins, false);
    const replayOnHtml = applyCsp(indexHtml, false, origins, true);

    expect(customerHtml).not.toContain('worker-src');
    expect(dsnOnlyHtml).not.toContain('worker-src');
    expect(applyCsp(indexHtml, false, [], false)).toBe(customerHtml);
    expect(replayOnHtml).toContain("worker-src 'self' blob:;");
  });

  it('gates build-time Replay strictly on DSN, flag=1, and explicit internal/e2e environment', () => {
    const dsn = 'https://publickey@o1.ingest.us.sentry.io/42';
    expect(isSentryReplayBuildEnabled({})).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: '' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'production' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'customer' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'staging' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'tenant' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '0', VITE_NANO_SENTRY_ENVIRONMENT: 'e2e' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'e2e' })).toBe(true);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'internal' })).toBe(true);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'local' })).toBe(true);
    // Explicit rate <= 0 disables build-time Replay and CSP worker-src too.
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'e2e', VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE: '0' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'e2e', VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE: '0.0' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'e2e', VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE: '-0.25' })).toBe(false);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'e2e', VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE: '0.25' })).toBe(true);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'e2e', VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE: '1' })).toBe(true);
    expect(isSentryReplayBuildEnabled({ VITE_NANO_SENTRY_DSN: dsn, VITE_NANO_SENTRY_REPLAY: '1', VITE_NANO_SENTRY_ENVIRONMENT: 'e2e', VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE: '' })).toBe(true);
  });
});
