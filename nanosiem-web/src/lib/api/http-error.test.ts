// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4753: edge/proxy HTML error pages never reach the UI.
import { describe, expect, it, vi } from 'vitest';
import { describeHttpFailure, looksLikeHtml, normalizeErrorBody, safeErrorMessage } from './http-error';

// Shape of a Cloudflare 524 page (trimmed): scripts, footer, IP-reveal button.
const CF_524 = `<!DOCTYPE html>
<html class="no-js" lang="en-US"><head><title>au.nano.rs | 524: A timeout occurred</title>
<script>(function(){var b=document.getElementById('cf-footer-ip-reveal');})();</script></head>
<body><div id="cf-wrapper"><h1>A timeout occurred</h1>
<span class="cf-footer-item">Cloudflare Ray ID: <strong class="font-semibold">a51666239c020c02</strong></span>
<button type="button" id="cf-footer-ip-reveal">Click to reveal</button></div></body></html>`;

describe('describeHttpFailure', () => {
  it('turns a Cloudflare 524 page into one sentence with the Ray id', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const failure = describeHttpFailure({ status: 524, body: CF_524 });
    expect(failure.requestId).toBe('a51666239c020c02');
    expect(failure.message).toBe('The server took too long to answer (HTTP 524). Retry in a moment. Reference a51666239c020c02.');
    expect(failure.message).not.toMatch(/[<>]/);
    expect(warn).toHaveBeenCalledWith('[api] non-JSON error response', { status: 524, requestId: 'a51666239c020c02' });
    warn.mockRestore();
  });

  it('prefers the cf-ray / x-request-id header for the reference', () => {
    const headers = new Headers({ 'cf-ray': 'abc123def4567890-SYD' });
    const failure = describeHttpFailure({ status: 502, body: '<html><body>Bad gateway</body></html>', headers });
    expect(failure.requestId).toBe('abc123def4567890-SYD');
    expect(failure.message).toContain('HTTP 502');
  });

  it('keeps a short plain-text body and replaces HTML or empty bodies', () => {
    expect(describeHttpFailure({ status: 400, body: 'sample_logs must not be empty' }).message).toBe('sample_logs must not be empty');
    expect(describeHttpFailure({ status: 500, body: '' }).message).toBe('Request failed (HTTP 500).');
    expect(describeHttpFailure({ status: 418, body: '<div>teapot</div>' }).message).toBe('Request failed (HTTP 418).');
  });
});

describe('safeErrorMessage', () => {
  it('never passes markup through', () => {
    expect(looksLikeHtml(CF_524)).toBe(true);
    expect(safeErrorMessage(CF_524, 'pivt could not draft the parser.')).toBe(
      'pivt could not draft the parser. Reference a51666239c020c02.',
    );
    expect(safeErrorMessage('Draft incomplete: pivt hit its output limit.')).toBe('Draft incomplete: pivt hit its output limit.');
    expect(safeErrorMessage(undefined, 'fallback')).toBe('fallback');
  });
});

describe('normalizeErrorBody', () => {
  it('sanitizes markup inside JSON errors and untrusted reference headers', () => {
    expect(normalizeErrorBody(500, JSON.stringify({ error: { message: CF_524 } })).message)
      .toBe('Request failed (HTTP 500). Retry in a moment. Reference a51666239c020c02.');
    expect(normalizeErrorBody(500, JSON.stringify({ message: '<img src=x onerror=bad()>' })).message)
      .toBe('Request failed (HTTP 500). Retry in a moment.');
    expect(describeHttpFailure({ status: 524, headers: new Headers({ 'x-request-id': '<img src=x>' }) }).message)
      .not.toMatch(/[<>]/);
  });

  it('keeps every JSON envelope and replaces HTML', () => {
    expect(normalizeErrorBody(400, JSON.stringify({ error: { code: 'BAD', message: 'nope', details: { f: 1 } } })))
      .toEqual({ code: 'BAD', message: 'nope', details: { f: 1 } });
    expect(normalizeErrorBody(401, JSON.stringify({ error: 'unauthorized', message: 'Invalid key' })))
      .toEqual({ code: 'unauthorized', message: 'Invalid key' });
    expect(normalizeErrorBody(409, JSON.stringify({ code: 'CONFLICT', message: 'taken' })))
      .toEqual({ code: 'CONFLICT', message: 'taken', details: undefined });
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(normalizeErrorBody(524, CF_524)).toEqual({
      code: 'UNKNOWN_ERROR',
      message: 'The server took too long to answer (HTTP 524). Retry in a moment. Reference a51666239c020c02.',
      details: { request_id: 'a51666239c020c02' },
    });
  });
});
