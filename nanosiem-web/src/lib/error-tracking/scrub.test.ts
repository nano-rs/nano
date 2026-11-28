// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5798: secrets in each field are removed; normal messages, URLs, names
// and fields pass through unchanged. Plus the caps.
import { describe, expect, it } from 'vitest';
import {
  createGate, FILTERED, issueKey, memoryCounterStore, scrubCrumb, scrubLog, scrubPayload,
  scrubReplayRecordingEvent, scrubText,
  type SentryPayload,
} from './scrub';

const gate = (over: Partial<Parameters<typeof createGate>[0]> = {}) =>
  createGate({
    maxPerIssue: 5, maxEvents: 50, maxTransactions: 2, maxLogs: 2,
    tags: () => ({ service: 'nano-web', run_id: 'run-1' }),
    store: memoryCounterStore(),
    ...over,
  });

const err = (value: string, type = 'Error'): SentryPayload => ({ exception: { values: [{ type, value }] } });

describe('scrubText', () => {
  it.each([
    ['Authorization: Bearer abcdefghijklmnop', 'abcdefghijklmnop'],
    ['Cookie: a=1; session=real_secret; csrf=xyz', 'real_secret'],
    ['set-cookie: sid=s3cr3tvalue; Path=/', 's3cr3tvalue'],
    ['token nit_ABCDEFGHIJ0123456789 rejected', 'nit_ABCDEFGHIJ'],
    ['jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk', 'eyJhbGci'],
    ['-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----', 'MIIabc'],
    ['access_token=t1q refresh_token=t2q client_secret=t3q password=t4q api_key=t5q', 'q '],
    ['GET /api/oidc/callback?code=c0de&state=ok', 'c0de'],
    ['https://h.test/x?token=abc123&sig=s1g&q=alice', 's1g'],
    ['postgres://nanosiem:hunter2@db:5432/x', 'hunter2'],
    ['https://publickey123@o1.ingest.sentry.io/42', 'publickey123'],
    ['{"Cookie": "a=1; session=real_secret; csrf=xyz"}', 'real_secret'],
    ['{"Set-Cookie": "nano_session=s3cr3tvalue; Path=/; HttpOnly"}', 's3cr3tvalue'],
    ['{"Authorization": "Splunk my-hec-secret-123"}', 'my-hec-secret-123'],
    ['Cookie="nano_session=s3cr3t; csrf=xyz"', 's3cr3t'],
    ["password='hunter2' rejected", 'hunter2'],
    ["WHERE client_secret = 'top secret phrase'", 'top secret'],
    ["{'api_key': 'sk-123456', 'host': 'dc01'}", 'sk-123456'],
    ['postgres://user:p@ss@db.internal/x', 'ss@db'],
  ])('%s', (input, secret) => expect(scrubText(input)).not.toContain(secret));

  it('keeps normal text unchanged', () => {
    for (const keep of [
      "search failed for alice: Code: 27. DB::Exception: Cannot parse 'dc01,10.1.2.3'. (CANNOT_PARSE_INPUT_ASSERTION_FAILED)",
      '/hunts/0198f7a2-1c3e-7d4b-9a10-3b5c7e9f0a12?tab=findings&page=2',
      "Cannot read properties of undefined (reading 'alice')",
      'peer 2001:db8::1 and 10.20.30.40 refused',
      'login for analyst@example.com failed',
    ]) expect(scrubText(keep)).toBe(keep);
  });
});

describe('payload paths', () => {
  it('event: secrets go, everything else stays', () => {
    const e = scrubPayload({
      message: 'lookup failed for 10.20.30.40 with password=hunter2',
      transaction: '/hunts/abc123?token=tok2',
      fingerprint: ['{{ default }}', 'alice'],
      request: { url: 'https://h.test/api/users/alice?api_key=k3y&q=1', headers: { Authorization: 'Bearer t', Accept: 'json' }, cookies: 'session=abc' },
      user: { id: '7', ip_address: '10.9.9.9' },
      tags: { api_key: 'sk-1', run_id: 'r1' },
      extra: { attempt: 2, nested: { client_secret: 'cs1', host: 'dc01' } },
      contexts: { trace: { op: 'pageload', data: { query: 'user=alice', token: 'tk5' } } },
      exception: { values: [{ type: 'TypeError', value: "Cannot read 'dc01' token=tok4", stacktrace: { frames: [{ filename: '/assets/a.js', function: 'f' }] } }] },
      breadcrumbs: [{ category: 'console', message: 'Authorization: Bearer abcdefghijklmnop' }, { category: 'fetch', data: { url: '/api/x?code=c0de&page=1' } }],
    });
    const text = JSON.stringify(e);
    for (const secret of ['hunter2', 'tok2', 'k3y', 'Bearer t"', 'session=abc', '10.9.9.9', 'sk-1', 'cs1', 'tk5', 'tok4', 'abcdefghijklmnop', 'c0de']) {
      expect(text, secret).not.toContain(secret);
    }
    for (const kept of ['lookup failed for 10.20.30.40', '/hunts/abc123?token=', 'alice', 'json', 'r1', 'dc01', 'user=alice', 'pageload', 'TypeError', '/assets/a.js', 'page=1']) {
      expect(text, kept).toContain(kept);
    }
    expect(e.fingerprint).toEqual(['{{ default }}', 'alice']);
  });

  it('request query_string (no leading ?, or [key, value] pairs)', () => {
    const asString = scrubPayload({ request: { url: '/x', query_string: 'code=c0de&sig=s1g&page=2' } });
    expect(asString.request).toEqual({ url: '/x', query_string: `code=${FILTERED}&sig=${FILTERED}&page=2` });
    const asPairs = scrubPayload({ request: { query_string: [['code', 'c0de'], ['session', 's3'], ['page', '2']] } });
    expect((asPairs.request as Record<string, unknown>).query_string).toEqual([['code', FILTERED], ['session', FILTERED], ['page', '2']]);
  });

  it('transaction spans', () => {
    const tx = scrubPayload({ type: 'transaction', transaction: '/search', spans: [
      { op: 'http.client', description: 'POST /api/search?token=tok6', data: { url: '/api/search?token=tok6', 'http.response.status_code': 200 } }] });
    expect(JSON.stringify(tx)).not.toContain('tok6');
    expect((tx.spans as Array<Record<string, unknown>>)[0]).toMatchObject({ op: 'http.client', description: `POST /api/search?token=${FILTERED}` });
  });

  it('breadcrumbs keep DOM and console text, lose secrets', () => {
    expect(scrubCrumb({ category: 'ui.click', message: 'button[aria-label="Delete hunt"]' })).toEqual({ category: 'ui.click', message: 'button[aria-label="Delete hunt"]' });
    expect(scrubCrumb({ category: 'console', message: 'failed', data: { arguments: ['Bearer abcdefghij999'] } }).data)
      .toEqual({ arguments: ["Bearer [REDACTED]"] }); // support-diagnostics redactText runs first
  });

  it('logs: body, template and parameters lose secrets', () => {
    const log = scrubLog({ message: 'rate limited alice, Cookie: sid=c00kie', attributes: {
      'sentry.message.template': 'rate limited {}, Cookie: sid=c00kie', 'sentry.message.parameter.0': 'Bearer abcdefghij999', access_token: 'a7', user: 'alice' } });
    expect(JSON.stringify(log)).not.toMatch(/c00kie|abcdefghij999|"a7"/);
    expect(log.message).toBe(`rate limited alice, Cookie: ${FILTERED}`);
    expect(log.attributes?.user).toBe('alice');
  });

  it('replay recording events scrub URLs, tokens, JWTs, headers, and secret keys', () => {
    const rec = scrubReplayRecordingEvent({
      type: 5,
      timestamp: 1700000000,
      data: {
        tag: 'breadcrumb',
        payload: {
          category: 'navigation',
          message: 'GET /api/oidc/callback?token=tok999&page=2 with nit_ABCDEFGHIJ0123456789',
          data: {
            from: '/login?code=c0de123',
            to: '/hunts?tab=findings',
            authorization: 'Bearer abcdefghijklmnop',
            jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk',
            note: 'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk',
          },
        },
      },
    });
    const text = JSON.stringify(rec);
    for (const secret of ['tok999', 'nit_ABCDEFGHIJ', 'c0de123', 'abcdefghijklmnop', 'eyJhbGci']) {
      expect(text, secret).not.toContain(secret);
    }
    expect(text).toContain('/hunts?tab=findings');
    expect(text).toContain('page=2');
  });
});

describe('gate', () => {
  it('drops benign browser noise', () => {
    const g = gate();
    expect(g.event(err('ResizeObserver loop completed with undelivered notifications.'))).toBeNull();
    expect(g.event(err('Failed to fetch dynamically imported module: /assets/x.js', 'TypeError'))).toBeNull();
    expect(g.event(err('signal is aborted without reason', 'AbortError'))).toBeNull();
    expect(g.event(err('Cannot read properties of undefined'))).not.toBeNull();
  });

  it('caps per issue (numbers normalized) and per session', () => {
    const g = gate();
    expect(Array.from({ length: 20 }, (_, i) => g.event(err(`row ${i} missing`))).filter(Boolean)).toHaveLength(5);
    expect(issueKey(err('row 1 missing'))).toBe(issueKey(err('row 2 missing')));
    const store = memoryCounterStore();
    const small = gate({ maxEvents: 3, store });
    expect(Array.from({ length: 10 }, (_, i) => small.event(err(`distinct ${'x'.repeat(i)}`))).filter(Boolean)).toHaveLength(3);
    expect(gate({ maxEvents: 3, store }).event(err('after reload'))).toBeNull();
  });

  it('tags events, caps transactions and logs', () => {
    const g = gate();
    expect(g.event({ ...err('boom'), tags: { boundary: 'route' } })?.tags).toEqual({ boundary: 'route', service: 'nano-web', run_id: 'run-1' });
    expect(g.transaction({ transaction: '/cases/1?tab=x' })?.transaction).toBe('/cases/1?tab=x');
    expect(g.transaction({})).not.toBeNull();
    expect(g.transaction({})).toBeNull();
    expect(g.log({ message: 'a', attributes: {} })?.attributes).toMatchObject({ run_id: 'run-1' });
    expect(g.log({ message: 'b' })).not.toBeNull();
    expect(g.log({ message: 'c' })).toBeNull();
  });

  it('caps error-only replays per session (default 3) and skips benign noise', () => {
    const store = memoryCounterStore();
    const g = gate({ store });
    expect(g.replay(err('ResizeObserver loop completed with undelivered notifications.'))).toBe(false);
    expect(store.get('replays')).toBe(0);
    expect(g.replay(err('real crash 1'))).toBe(true);
    expect(g.replay(err('real crash 2'))).toBe(true);
    expect(g.replay(err('real crash 3'))).toBe(true);
    expect(g.replay(err('real crash 4'))).toBe(false);
    // Persisted counter survives page reload within the same browser session.
    expect(gate({ store }).replay(err('after reload'))).toBe(false);
  });
});
