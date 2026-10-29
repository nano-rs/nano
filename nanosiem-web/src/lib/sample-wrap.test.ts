// SPDX-License-Identifier: AGPL-3.0-or-later

/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  describeSampleSplit, detectWrappedLines, joinWrappedLines, parserDraftStage,
} from './sample-wrap.ts';

// The FP paste from 10-28 (NAN-4792): 8 syslog lines, each soft-wrapped by the
// terminal, so the tail landed on its own line.
const EVENTS = [
  ['<134>Oct 28 14:02:11 fw01 traffic: action=allow src=10.0.4.12 dst=172.217.4.46 dport=443 proto=tcp', 'bytes_out=1832 bytes_in=48211 user=alice'],
  ['<134>Oct 28 14:02:12 fw01 traffic: action=allow src=10.0.4.18 dst=140.82.112.3 dport=443 proto=tcp', 'bytes_out=912 bytes_in=10233 user=bob'],
  ['<132>Oct 28 14:02:13 fw01 traffic: action=deny src=10.0.9.4 dst=45.33.32.156 dport=22 proto=tcp', 'bytes_out=0 bytes_in=0 user=-'],
  ['<134>Oct 28 14:02:14 fw01 traffic: action=allow src=10.0.4.12 dst=8.8.8.8 dport=53 proto=udp', 'bytes_out=74 bytes_in=122 user=alice'],
  ['<134>Oct 28 14:02:15 fw01 traffic: action=allow src=10.0.4.30 dst=52.84.150.11 dport=443 proto=tcp', 'bytes_out=2210 bytes_in=90012 user=carol'],
  ['<132>Oct 28 14:02:16 fw01 traffic: action=deny src=10.0.9.7 dst=185.220.101.4 dport=9001 proto=tcp', 'bytes_out=0 bytes_in=0 user=-'],
  ['<134>Oct 28 14:02:17 fw01 traffic: action=allow src=10.0.4.18 dst=151.101.1.69 dport=443 proto=tcp', 'bytes_out=1501 bytes_in=33870 user=bob'],
  ['<134>Oct 28 14:02:18 fw01 traffic: action=allow src=10.0.4.44 dst=104.16.132.229 dport=443 proto=tcp', 'bytes_out=640 bytes_in=5120 user=dave'],
];
// The api log showed sample 2 as "  bytes_out=1832 ..." (indented tail).
const WRAPPED = EVENTS.map(([head, tail]) => `${head}\n  ${tail}`).join('\n');
const CLEAN = EVENTS.map(([head, tail]) => `${head} ${tail}`).join('\n');

test('the wrapped FP paste: 16 lines, 8 flagged tails, join gives the 8 events', () => {
  const a = detectWrappedLines(WRAPPED);
  assert.equal(a.lineCount, 16);
  assert.deepEqual(a.continuations, [1, 3, 5, 7, 9, 11, 13, 15]);
  assert.equal(joinWrappedLines(WRAPPED), CLEAN);
  assert.deepEqual(detectWrappedLines(joinWrappedLines(WRAPPED)).continuations, []);
});

test('an unindented tail (hard cut at the terminal column) rejoins exactly', () => {
  const text = EVENTS.map(([head, tail]) => `${head} bytes_o\n${tail.slice(7)}`).join('\n');
  const a = detectWrappedLines(text);
  assert.equal(a.continuations.length, 8);
  assert.equal(joinWrappedLines(text), CLEAN);
});

test('a single wrapped line in an otherwise clean paste is flagged', () => {
  const lines = CLEAN.split('\n');
  lines.splice(3, 1, `${EVENTS[3][0]}`, `  ${EVENTS[3][1]}`);
  assert.deepEqual(detectWrappedLines(lines.join('\n')).continuations, [4]);
});

test('clean syslog: nothing flagged', () => {
  assert.deepEqual(detectWrappedLines(CLEAN), { lineCount: 8, continuations: [] });
  const rfc3164 = [
    'Oct 28 14:02:11 web01 sshd[1234]: Accepted password for alice from 10.0.4.12 port 51022 ssh2',
    'Oct 28 14:02:14 web01 sshd[1234]: pam_unix(sshd:session): session opened for user alice',
    'Oct  8 09:00:01 web01 CRON[2211]: (root) CMD (run-parts /etc/cron.hourly)',
  ].join('\n');
  assert.deepEqual(detectWrappedLines(rfc3164).continuations, []);
});

test('pretty-printed JSON (one object, several objects, an array) is never flagged', () => {
  const one = JSON.stringify({ timestamp: '2026-10-28T14:02:11Z', user: 'alice', action: 'login' }, null, 2);
  assert.deepEqual(detectWrappedLines(one).continuations, []);
  assert.deepEqual(detectWrappedLines(`${one}\n${one}\n${one}`).continuations, []);
  const arr = JSON.stringify([{ a: 1 }, { a: 2 }, { a: 3 }], null, 2);
  assert.deepEqual(detectWrappedLines(arr).continuations, []);
});

test('compact multiline JSON records preserve their legal newlines', () => {
  for (const text of [
    '{"a": 1,\n "b": 2}\n{"a": 3,\n "b": 4}',
    '{"a":\n 1}\n{"a":\n 2}',
    '{"message":"first"}\n{"a": 1,\n "b": 2}\n{"message":"last"}',
  ]) {
    assert.deepEqual(detectWrappedLines(text).continuations, []);
    assert.equal(joinWrappedLines(text), text);
  }
});

test('NDJSON is not flagged', () => {
  const nd = ['{"ts":"2026-10-28T14:02:11Z","user":"alice"}', '{"ts":"2026-10-28T14:02:12Z","user":"bob"}', '{"ts":"2026-10-28T14:02:13Z","user":"carol"}'].join('\n');
  assert.deepEqual(detectWrappedLines(nd).continuations, []);
});

test('a Java stack trace stays one event and is not flagged', () => {
  const trace = [
    '2026-10-28 14:02:11,442 ERROR [http-nio-8080-exec-3] c.a.OrderService - order failed',
    'java.lang.IllegalStateException: inventory unavailable',
    '\tat com.acme.OrderService.place(OrderService.java:88)',
    '\tat com.acme.OrderController.post(OrderController.java:41)',
    'Caused by: java.net.SocketTimeoutException: Read timed out',
    '\tat java.base/java.net.SocketInputStream.socketRead0(Native Method)',
    '\t... 42 more',
    '2026-10-28 14:02:12,001 INFO  [http-nio-8080-exec-4] c.a.OrderService - order placed',
  ].join('\n');
  assert.deepEqual(detectWrappedLines(trace).continuations, []);
});

test('a Python traceback is not flagged', () => {
  const tb = [
    '2026-10-28 14:02:11 ERROR worker crashed',
    'Traceback (most recent call last):',
    '  File "/app/worker.py", line 12, in run',
    '    do()',
    'ValueError: bad input',
    '2026-10-28 14:02:12 INFO worker restarted',
  ].join('\n');
  assert.deepEqual(detectWrappedLines(tb).continuations, []);
});

test('short or unindented stack traces are never offered for joining', () => {
  for (const exception of [
    'java.lang.IllegalStateException: inventory unavailable',
    'Exception in thread "main" java.lang.IllegalStateException: failed',
    'at com.acme.OrderService.place(OrderService.java:88)',
    'Suppressed: java.io.IOException: failed',
  ]) {
    const text = `2026-10-28T14:02:11Z request failed\n${exception}\n2026-10-28T14:02:12Z ok`;
    assert.deepEqual(detectWrappedLines(text).continuations, []);
    assert.equal(joinWrappedLines(text), text);
  }
});

test('Windows XML events are not flagged', () => {
  const xml = [
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
    '  <System>',
    '    <EventID>4624</EventID>',
    '    <TimeCreated SystemTime="2026-10-28T14:02:11.000Z"/>',
    '  </System>',
    '</Event>',
  ].join('\n');
  assert.deepEqual(detectWrappedLines(xml).continuations, []);
});

test('CSV with a header is not flagged', () => {
  const csv = [
    'timestamp,src_ip,dest_ip,action,bytes',
    '2026-10-28T14:02:11Z,10.0.4.12,8.8.8.8,allow,74',
    '2026-10-28T14:02:12Z,10.0.4.18,1.1.1.1,allow,120',
    '2026-10-28T14:02:13Z,10.0.9.4,45.33.32.156,deny,0',
  ].join('\n');
  assert.deepEqual(detectWrappedLines(csv).continuations, []);
  const plain = ['user,action,count', 'alice,login,3', 'bob,logout,1', 'carol,login,9'].join('\n');
  assert.deepEqual(detectWrappedLines(plain).continuations, []);
});

test('CSV quoted multiline fields, escaped quotes and indentation are preserved', () => {
  for (const text of [
    'timestamp,message\n2026-10-28T14:02:11Z,"request failed\n  retry after backoff"\n2026-10-28T14:02:12Z,"ok"\n2026-10-28T14:02:13Z,"ok"',
    '2026-10-28T14:02:11Z,"request failed\n  retry after backoff"\n2026-10-28T14:02:12Z,"ok"',
    'timestamp,message\n2026-10-28T14:02:11Z,"request said ""failed""\n  retry, then wait"\n2026-10-28T14:02:12Z,"ok"',
    'user,action\n  alice,login\nbob,logout',
    'alice,"login\n  failed\n  again"',
  ]) {
    assert.deepEqual(detectWrappedLines(text).continuations, []);
    assert.equal(joinWrappedLines(text), text);
  }
});

test('mixed formats are not flagged', () => {
  const mixed = [
    '<134>Oct 28 14:02:11 fw01 traffic: action=allow',
    '{"ts":"2026-10-28T14:02:12Z","user":"bob"}',
    '2026-10-28T14:02:13Z host=web01 msg="ok"',
    'date=2026-10-28 time=14:02:14 devname=fgt01 action=accept',
    'CEF:0|Acme|FW|1.0|100|blocked|5|src=10.0.0.1',
    'date=2026-10-28 time=14:02:15 devname=fgt01 action=deny',
  ].join('\n');
  assert.deepEqual(detectWrappedLines(mixed).continuations, []);
  const dominantMixed = [
    '<134>Oct 28 14:02:11 fw01 action=allow',
    '{"user":"alice"}',
    'standalone event without a timestamp',
    '<134>Oct 28 14:02:12 fw01 action=allow',
    '<134>Oct 28 14:02:13 fw01 action=deny',
  ].join('\n');
  assert.deepEqual(detectWrappedLines(dominantMixed).continuations, []);
  assert.equal(joinWrappedLines(dominantMixed), dominantMixed);
});

test('shapeless key=value logs: an indented tail is flagged, an indented block is not', () => {
  const kv = [
    'date=2026-10-28 time=14:02:11 devname=fgt01 action=accept srcip=10.0.4.12',
    '  dstip=8.8.8.8 dstport=53',
    'date=2026-10-28 time=14:02:12 devname=fgt01 action=accept srcip=10.0.4.18 dstip=1.1.1.1 dstport=53',
    'date=2026-10-28 time=14:02:13 devname=fgt01 action=deny srcip=10.0.9.4 dstip=45.33.32.156 dstport=22',
  ].join('\n');
  assert.deepEqual(detectWrappedLines(kv).continuations, [1]);
  const block = ['header line', '  nested: 1', '  nested: 2', 'footer line', 'another line'].join('\n');
  assert.deepEqual(detectWrappedLines(block).continuations, []);
});

test('join never touches text with nothing flagged', () => {
  assert.equal(joinWrappedLines(CLEAN), CLEAN);
  assert.equal(joinWrappedLines(''), '');
});

test('the live split label', () => {
  assert.equal(describeSampleSplit('', 0), 'No samples');
  assert.equal(describeSampleSplit(WRAPPED, 16), '16 sample lines · one event per line');
  assert.equal(describeSampleSplit('a', 1), '1 sample line · one event per line');
  assert.equal(describeSampleSplit('[{"a":1},{"a":2}]', 2), '2 sample events · JSON');
});

test('draft stage comes from the job text, never a percentage', () => {
  assert.equal(parserDraftStage('AI model is reasoning (900 characters so far)...'), 'reasoning');
  assert.equal(parserDraftStage('AI model is writing the answer (40 characters so far)...'), 'writing VRL');
  assert.equal(parserDraftStage('Validating the revision'), 'validating');
  assert.equal(parserDraftStage('Working...'), 'working');
  assert.equal(parserDraftStage(undefined), 'working');
});
