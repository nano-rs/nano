// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { JSDOM } from 'jsdom';
import { watchForNewBuild } from './build-update.ts';

test('build watcher compares the loaded ID, ignores failed probes, and prompts once', async () => {
  const dom = new JSDOM('<meta name="nano-build-id" content="loaded">', { pretendToBeVisual: true });
  const originals = { document: globalThis.document, window: globalThis.window, DOMParser: globalThis.DOMParser, fetch: globalThis.fetch };
  Object.assign(globalThis, { document: dom.window.document, window: dom.window, DOMParser: dom.window.DOMParser });
  let calls = 0;
  let notifications = 0;
  let reply = new Response('<meta name="nano-build-id" content="loaded">', { headers: { 'content-type': 'text/html' } });
  globalThis.fetch = async (url, options) => {
    calls++;
    assert.equal(url, '/index.html');
    assert.equal(options?.cache, 'no-cache');
    return reply.clone();
  };
  const stop = watchForNewBuild(() => { notifications++; }, 60_000);
  const probe = async () => {
    document.dispatchEvent(new dom.window.Event('visibilitychange'));
    await new Promise(resolve => setTimeout(resolve, 20));
  };
  try {
    await probe();
    assert.equal(notifications, 0);
    reply = new Response('<meta name="nano-build-id" content="new">', { status: 503, headers: { 'content-type': 'text/html' } });
    await probe();
    reply = new Response('<meta name="nano-build-id" content="new">', { headers: { 'content-type': 'text/plain' } });
    await probe();
    reply = new Response('<html>Login gateway</html>', { headers: { 'content-type': 'text/html' } });
    await probe();
    globalThis.fetch = async () => { throw new Error('offline'); };
    await probe();
    assert.equal(notifications, 0);
    globalThis.fetch = async () => {
      calls++;
      return new Response('<meta name="nano-build-id" content="new">', { headers: { 'content-type': 'text/html' } });
    };
    await probe();
    assert.equal(notifications, 1);
    const notifiedCalls = calls;
    await probe();
    assert.equal(calls, notifiedCalls);
    stop();
    await probe();
    assert.equal(calls, notifiedCalls);
    document.querySelector('meta').remove();
    const stopWithoutId = watchForNewBuild(() => { notifications++; }, 1);
    await probe();
    stopWithoutId();
    assert.equal(calls, notifiedCalls);
  } finally {
    stop();
    dom.window.close();
    Object.assign(globalThis, originals);
  }
});

test('periodic probes skip hidden tabs, avoid overlap, and abort on cleanup', async () => {
  const dom = new JSDOM('<meta name="nano-build-id" content="loaded">', { pretendToBeVisual: true });
  const originals = { document: globalThis.document, window: globalThis.window, DOMParser: globalThis.DOMParser, fetch: globalThis.fetch };
  Object.assign(globalThis, { document: dom.window.document, window: dom.window, DOMParser: dom.window.DOMParser });
  let visible = false;
  Object.defineProperty(document, 'visibilityState', { get: () => visible ? 'visible' : 'hidden' });
  let calls = 0;
  let signal;
  let finish;
  let notifications = 0;
  globalThis.fetch = async (_url, options) => {
    calls++;
    signal = options.signal;
    return new Promise(resolve => { finish = resolve; });
  };
  const stop = watchForNewBuild(() => { notifications++; }, 5);
  try {
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(calls, 0);
    visible = true;
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(calls, 1);
    stop();
    assert.equal(signal.aborted, true);
    finish(new Response('<meta name="nano-build-id" content="new">', { headers: { 'content-type': 'text/html' } }));
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(notifications, 0);
    assert.equal(calls, 1);
  } finally {
    stop();
    dom.window.close();
    Object.assign(globalThis, originals);
  }
});
