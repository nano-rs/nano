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
  scriptSrcOf,
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
