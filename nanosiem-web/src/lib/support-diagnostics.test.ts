// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5253: support-report context is useful and never carries secrets.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  MAX_FAILED_CALLS,
  buildSupportReport,
  collectSupportContext,
  getConsoleErrors,
  getFailedCalls,
  installSupportCapture,
  recordConsoleError,
  redactText,
  resetSupportCapture,
  sanitizeApiPath,
  sanitizeRoute,
  supportMailto,
  FEEDBACK_URL_MAX,
  decodeFeedbackPayload,
  feedbackUrl,
  recordFailedCall,
} from './support-diagnostics';

const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c3JfMDEifQ.c2lnbmF0dXJlLXZhbHVl';

describe('redactText', () => {
  it.each([
    [`Authorization: Bearer ${JWT}`, JWT],
    ['bearer abcdefghijklmnop0123', 'abcdefghijklmnop0123'],
    [`token ${JWT} expired`, JWT],
    ['postgres://nanosiem:hunter2hunter2@db:5432/x', 'hunter2hunter2'],
    ['GET /x?token=abc123secret&from=-24h', 'abc123secret'],
    ['{"password":"s3cr3t-value"}', 's3cr3t-value'],
    ['LICENSE_TOKEN=Zk3q9V_r8XyT2mN4pL6sA1bC5dE7fG9hJ0kQwErTyUi', 'Zk3q9V_r8XyT2mN4'],
    ['ingest with nit_AbCdEf0123456789xyz', 'nit_AbCdEf0123456789xyz'],
    ['-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----', 'MIIEvQIBADANBgkq'],
  ])('removes the secret from %s', (input, secret) => {
    expect(redactText(input)).not.toContain(secret);
  });

  it('leaves ordinary text alone', () => {
    const text = 'Rule "Brute force > 10" failed to save: HTTP 500';
    expect(redactText(text)).toBe(text);
  });
});

describe('paths and routes', () => {
  it('masks share tokens but keeps IDs', () => {
    expect(sanitizeApiPath('/api/search/shared/Q2hhbmdlTWVQbGVhc2VUaGlzSXNBVG9rZW4xMjM0')).toBe('/api/search/shared/:token');
    expect(sanitizeApiPath('/api/rules/rule_01h455vb4pex5vsknk084sn02q')).toBe('/api/rules/rule_01h455vb4pex5vsknk084sn02q');
    expect(sanitizeApiPath('/api/cases/0190f3c2-1111-7abc-8def-0123456789ab/notes'))
      .toBe('/api/cases/0190f3c2-1111-7abc-8def-0123456789ab/notes');
  });

  it('omits query values unless the key is known-safe, and drops the fragment', () => {
    expect(sanitizeRoute('/search', '?q=user%3Dalice&from=-24h&token=abc')).toBe('/search?q=[omitted]&from=-24h&token=[omitted]');
    expect(sanitizeRoute('/rules', '')).toBe('/rules');
  });
});

describe('capture', () => {
  const realFetch = vi.fn();

  beforeAll(() => {
    window.fetch = realFetch as unknown as typeof fetch;
    installSupportCapture(window);
  });

  afterEach(() => {
    resetSupportCapture();
    realFetch.mockReset();
  });

  it('records failed same-origin API calls with request id, without query or body', async () => {
    realFetch.mockResolvedValueOnce(new Response('{"error":"boom secret"}', {
      status: 500, headers: { 'x-request-id': '0190f3c2-aaaa-7abc-8def-0123456789ab' },
    }));
    const res = await window.fetch('/api/rules?filter=secretvalue', { method: 'post', body: '{"password":"x"}' });
    expect(res.status).toBe(500);
    const [call] = getFailedCalls();
    expect(call).toMatchObject({ method: 'POST', path: '/api/rules', status: 500, requestId: '0190f3c2-aaaa-7abc-8def-0123456789ab' });
    expect(JSON.stringify(getFailedCalls())).not.toContain('secretvalue');
  });

  it('ignores successes, other origins and aborts; records network errors', async () => {
    realFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }));
    await window.fetch('/api/ok');
    realFetch.mockResolvedValueOnce(new Response('no', { status: 503 }));
    await window.fetch('https://cdn.example.com/api/x');
    realFetch.mockRejectedValueOnce(new DOMException('aborted', 'AbortError'));
    await expect(window.fetch('/api/slow')).rejects.toThrow();
    realFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    await expect(window.fetch('/api/down')).rejects.toThrow();
    expect(getFailedCalls()).toEqual([expect.objectContaining({ path: '/api/down', status: 0 })]);
  });

  it('keeps only the last 20 calls', async () => {
    for (let i = 0; i < MAX_FAILED_CALLS + 5; i += 1) {
      realFetch.mockResolvedValueOnce(new Response('', { status: 404 }));
      await window.fetch(`/api/item/${i}`);
    }
    const calls = getFailedCalls();
    expect(calls).toHaveLength(MAX_FAILED_CALLS);
    expect(calls[0].path).toBe('/api/item/5');
  });

  it('records console errors redacted and trimmed', () => {
    const spy = vi.spyOn(console, 'error');
    console.error('request failed', new Error(`Authorization: Bearer ${JWT}`), 'x'.repeat(500));
    spy.mockRestore();
    const [entry] = getConsoleErrors();
    expect(entry.message).not.toContain(JWT);
    expect(entry.message.length).toBeLessThanOrEqual(301);
  });

  it('never throws or recurses on hostile console.error arguments (NAN-5273)', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const hostile = { toJSON() { throw new Error('toJSON'); }, toString() { throw new Error('toString'); } };
    const logging = { toJSON() { console.error('nested'); return 'logged'; } };
    const spy = vi.spyOn(console, 'error');
    expect(() => console.error('ctx', circular, hostile, Object.create(null), logging)).not.toThrow();
    spy.mockRestore();
    expect(getConsoleErrors()).toHaveLength(1);
    expect(getConsoleErrors()[0].message).toContain('[unprintable]');
    expect(() => window.dispatchEvent(new ErrorEvent('error', { error: hostile }))).not.toThrow();
  });
});

describe('report', () => {
  afterEach(() => resetSupportCapture());

  it('formats the user fields and context, redacting free text', () => {
    recordConsoleError(['boom']);
    const context = collectSupportContext({ appVersion: '2.0.11', edition: 'enterprise' });
    const report = buildSupportReport({
      kind: 'bug', whatHappened: `Saving failed; my token=supersecret1 and ${JWT}`, expected: 'It saves',
      when: '2026-11-10 14:05 EST', affected: 'rule: Brute force > 10', context,
    });
    expect(report).toContain('# nano Bug report');
    expect(report).toContain('rule: Brute force > 10');
    expect(report).toContain('nano version: 2.0.11');
    expect(report).toContain('scripts/nano support-bundle');
    expect(report).toContain('boom');
    expect(report).not.toContain('supersecret1');
    expect(report).not.toContain(JWT);
  });

  it('builds a bounded mailto link', () => {
    const link = supportMailto('x'.repeat(5000), 'support', 'Cannot add a log source\nmore');
    expect(link.startsWith('mailto:support@nano.rs?subject=nano%20support%20request%3A%20Cannot%20add%20a%20log%20source&body=')).toBe(true);
    expect(decodeURIComponent(link.split('body=')[1])).toContain('full report is on your clipboard');
    expect(link.length).toBeLessThan(2400);
  });
});

describe('app.nano.rs feedback link (fragment schema v1)', () => {
  afterEach(() => resetSupportCapture());

  const input = (over: Record<string, unknown> = {}) => ({
    kind: 'bug' as const, whatHappened: 'Rule save fails\nwith 500', expected: 'It saves', when: '2026-11-10 14:05 EST',
    affected: 'rule: Brute force > 10',
    context: { ...collectSupportContext({ appVersion: '2.0.11', edition: 'enterprise' }), deploymentId: 'deploy_01h455vb4pex5vsknk084sn02q' },
    ...over,
  });

  it('puts type and deployment in the query and the report in the fragment', () => {
    const { url, truncated } = feedbackUrl(input());
    expect(truncated).toBe(false);
    const [base, fragment] = url.split('#r=');
    expect(base).toBe('https://app.nano.rs/feedback/new?type=bug&deployment=deploy_01h455vb4pex5vsknk084sn02q');
    expect(fragment).toMatch(/^[A-Za-z0-9_-]+$/);
    const payload = decodeFeedbackPayload(fragment);
    expect(payload).toMatchObject({ v: 1, type: 'bug', summary: 'Rule save fails', expected: 'It saves',
      affected: 'rule: Brute force > 10' });
    expect(payload.severity).toBeUndefined();
    expect(payload.context.app_version).toBe('2.0.11');
  });

  it('omits a malformed deployment ID and redacts free text', () => {
    const { url } = feedbackUrl(input({
      whatHappened: `token=supersecret1 ${JWT}`,
      context: { ...collectSupportContext({}), deploymentId: 'not-a-deployment' },
    }));
    expect(url).not.toContain('deployment=');
    const payload = decodeFeedbackPayload(url.split('#r=')[1]);
    expect(JSON.stringify(payload)).not.toContain('supersecret1');
    expect(JSON.stringify(payload)).not.toContain(JWT);
  });

  it('stays under 8 KB, dropping console errors before failed calls', () => {
    for (let i = 0; i < 20; i += 1) recordConsoleError([`error ${i} ${'e'.repeat(280)}`]);
    for (let i = 0; i < 20; i += 1) {
      recordFailedCall({ at: new Date().toISOString(), method: 'GET', path: `/api/item/${i}`, status: 500,
        requestId: `0190f3c2-aaaa-7abc-8def-0123456789${String(i).padStart(2, '0')}`, durationMs: 5 });
    }
    const big = input({ context: collectSupportContext({ appVersion: '2.0.11', edition: 'enterprise' }) });
    const { url, truncated } = feedbackUrl(big);
    expect(url.length).toBeLessThanOrEqual(FEEDBACK_URL_MAX);
    expect(truncated).toBe(true);
    const payload = decodeFeedbackPayload(url.split('#r=')[1]);
    expect(payload.truncated).toBe(true);
    expect(payload.context.failed_calls).toHaveLength(20);
    expect(payload.context.console_errors.length).toBeLessThan(20);
    expect(payload.context.console_errors.at(-1)?.message).toContain('error 19');
  });

  it('shortens free text when even an empty context does not fit', () => {
    const { url, truncated } = feedbackUrl(input({ whatHappened: 'w'.repeat(20000), expected: 'x'.repeat(20000) }));
    expect(url.length).toBeLessThanOrEqual(FEEDBACK_URL_MAX);
    expect(truncated).toBe(true);
  });

  it('carries severity for support and in the text report', () => {
    const support = input({ kind: 'support', severity: 'SEV2' });
    expect(decodeFeedbackPayload(feedbackUrl(support).url.split('#r=')[1]).severity).toBe('SEV2');
    expect(buildSupportReport(support)).toContain('SEV2 (Degraded)');
  });
});
