// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />
//
// NAN-2453: a protected request is never sent unauthenticated. Every request
// that carries a bearer goes through authenticatedFetch(), which waits for an
// in-flight refresh, replays a 401 once and expires the session once per tab.
// A hand-rolled `fetch(` that attaches `Authorization` itself skips all of
// that: it races the refresh, can go out with no bearer, and turns its 401
// into a second "session expired". This guard keeps them from coming back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('../', import.meta.url).pathname;
const EXEMPT = new Set([
  'lib/authenticated-fetch.ts',  // the transport itself
  'contexts/AuthContext.tsx',    // login / refresh / me own their credentials
  // First-admin setup runs before any session exists: its bearer is the
  // installer's one-time setup token (0f359328a, NAN-5237), not a session
  // credential, so authenticatedFetch's refresh/replay/expiry must not apply.
  'pages/Setup.tsx',
]);

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) && !/\.d\.ts$/.test(name)) out.push(p);
  }
  return out;
}

test('no raw fetch() attaches its own bearer outside authenticatedFetch', () => {
  const offenders: string[] = [];
  for (const file of walk(ROOT, [])) {
    const rel = file.slice(ROOT.length);
    if (EXEMPT.has(rel)) continue;
    const src = readFileSync(file, 'utf8');
    let from = 0;
    for (;;) {
      const start = src.indexOf('fetch(', from);
      if (start === -1) break;
      // refetch(, this.fetch(, authenticatedFetch( are not raw fetches.
      if (start > 0 && /[\w.]/.test(src[start - 1])) { from = start + 6; continue; }
      let depth = 0; let end = start + 5;
      for (; end < src.length; end++) {
        if (src[end] === '(') depth++;
        else if (src[end] === ')' && --depth === 0) break;
      }
      const call = src.slice(start + 6, end);
      if (/Authorization|Bearer|getAuthHeaders\(\)|authHeaders\(\)|getAccessToken/.test(call)) {
        offenders.push(`${rel}:${src.slice(0, start).split('\n').length}`);
      }
      from = end;
    }
    // A bearer assembled into a headers object ahead of a raw fetch.
    if (/\bfetch\(/.test(src.replace(/\w+fetch\(|\.fetch\(/gi, '')) && /Bearer \$\{/.test(src)) {
      offenders.push(`${rel}: builds a Bearer header next to a raw fetch()`);
    }
  }
  assert.deepEqual(offenders, [], `raw fetch() carries its own bearer:\n${offenders.join('\n')}`);
});
