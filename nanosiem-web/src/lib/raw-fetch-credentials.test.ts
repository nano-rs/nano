// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-2361: shared auth refuses two credentials (Bearer + cookie) with 401.
// Every raw `fetch(` that sets an Authorization header must therefore decide
// its cookie policy through `requestCredentials()`. The JSON transport in
// lib/api/index.ts does; this guards the hand-rolled fetches (tuning, meloD
// streams, uploads, lookup tables, search history, …) that black-boxed 401s
// on the hosted-shared tenant on 2026-09-16.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('../', import.meta.url).pathname;
const EXEMPT = new Set([
  'lib/api/index.ts',            // the transport itself
  'lib/request-credentials.ts',
  'contexts/AuthContext.tsx',    // login/refresh own their cookie policy
  'contexts/CapabilitiesProvider.tsx',
  'pages/Setup.tsx',             // first-run initialize: no session exists yet
]);

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) && !/\.d\.ts$/.test(name)) out.push(p);
  }
  return out;
}

test('every Bearer-bearing raw fetch decides its cookie policy via requestCredentials', () => {
  const offenders: string[] = [];
  for (const file of walk(ROOT, [])) {
    const rel = file.slice(ROOT.length);
    if (EXEMPT.has(rel) || rel.startsWith('lib/enterprise-shared-') || rel.startsWith('pages/EnterpriseShared')) continue;
    const src = readFileSync(file, 'utf8');
    let from = 0;
    for (;;) {
      const start = src.indexOf('fetch(', from);
      if (start === -1) break;
      if (start > 0 && /[\w.]/.test(src[start - 1])) { from = start + 6; continue; } // refetch(, this.fetch(
      // balanced-paren extraction of the call's argument list
      let depth = 0; let end = start + 5;
      for (; end < src.length; end++) {
        if (src[end] === '(') depth++;
        else if (src[end] === ')' && --depth === 0) break;
      }
      const call = src.slice(start + 6, end);
      const sendsBearer = /Authorization|getAuthHeaders\(\)|\bheaders\b/.test(call);
      if (sendsBearer && !/credentials\s*:/.test(call)) offenders.push(`${rel}:${src.slice(0, start).split('\n').length}`);
      from = end;
    }
  }
  assert.deepEqual(offenders, [], `raw fetch() sends headers without a credentials policy:\n${offenders.join('\n')}`);
});
