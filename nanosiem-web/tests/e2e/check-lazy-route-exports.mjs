#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-2190 — static gate: every `lazyWithRetryNamed(() => import('@/x'), 'Name')`
// call site must name an export the target module actually has.
//
// The export name is a STRING argument, so TypeScript cannot check it. A
// mismatch compiles, builds, and passes CI, then throws the moment a user
// navigates to that route:
//
//   Uncaught Error: lazyWithRetryNamed: module is missing named export 'X'.
//
// That is exactly how the /integrations page shipped broken in NAN-2189, past
// `tsc --noEmit`, `vite build`, and a green CI run. This is the sibling of
// check-dead-links.mjs: same class of "route renders wrong," same pure-text
// approach, no build and no browser.
//
// Not a ratchet. Unlike dead links there is no legitimate reason to carry a
// broken one, and at the time of writing all 61 call sites pass — so any
// failure here is a regression introduced by the PR under test.

import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, '../..');
const srcRoot = join(webRoot, 'src');
const appPath = join(srcRoot, 'App.tsx');

/**
 * `@/foo/bar` → absolute path, trying each extension the bundler would.
 * Mirrors the `@` → `src` alias in vite.config.ts / tsconfig paths.
 */
function resolveAlias(spec) {
  if (!spec.startsWith('@/')) return null;
  const base = join(srcRoot, spec.slice(2));
  for (const candidate of [`${base}.tsx`, `${base}.ts`, join(base, 'index.tsx'), join(base, 'index.ts')]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Does `source` export `name`?
 *
 * Deliberately permissive — this gate exists to catch "only exported default,"
 * not to reimplement ES module resolution. A false pass is survivable; a false
 * failure would block unrelated PRs, so anything ambiguous counts as present.
 */
function hasNamedExport(source, name) {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    // export function X / export const X / export class X (incl. async, default-less)
    new RegExp(`export\\s+(?:async\\s+)?(?:function|const|let|var|class)\\s+${n}\\b`),
    // export { X } / export { Y as X } — brace list, possibly multiline
    new RegExp(`export\\s*\\{[^}]*\\b${n}\\b[^}]*\\}`, 's'),
    // export type/interface X — not renderable, but resolving is the caller's problem
    new RegExp(`export\\s+(?:type|interface)\\s+${n}\\b`),
    // export * from './x' — can re-export anything; treat as opaque and pass
    /export\s+\*\s+from/,
  ];
  return patterns.some((re) => re.test(source));
}

const app = readFileSync(appPath, 'utf8');

// lazyWithRetryNamed(() => import('@/pages/Foo'), 'Foo')
// Tolerates whitespace/newlines between args and either quote style.
const CALL_SITE =
  /lazyWithRetryNamed\s*\(\s*\(\s*\)\s*=>\s*import\(\s*['"]([^'"]+)['"]\s*\)\s*,\s*['"]([^'"]+)['"]/g;

const failures = [];
let checked = 0;

for (const [, spec, exportName] of app.matchAll(CALL_SITE)) {
  checked += 1;
  const file = resolveAlias(spec);

  if (!file) {
    failures.push(`  ${spec} → module not found (expected '${exportName}')`);
    continue;
  }

  if (!hasNamedExport(readFileSync(file, 'utf8'), exportName)) {
    failures.push(
      `  ${spec} has no named export '${exportName}'\n` +
        `      → add \`export function ${exportName}\` (keep the default too, as Marketplace.tsx does),\n` +
        `        or register the route with lazyWithRetry instead.`,
    );
  }
}

// Coverage assertion. CALL_SITE is deliberately strict, so a registration
// written any other way — an inline comment inside import(), a helper wrapper —
// would be skipped in silence, and a partial miss reads exactly like success.
// Every real call site is a `const X = lazyWithRetryNamed(` assignment, so that
// count is what the parser owes us. Without this, verifying the gate's own
// coverage is a manual step, which is the thing a gate exists to remove.
const expected = (app.match(/=\s*lazyWithRetryNamed\s*\(/g) ?? []).length;

if (expected === 0) {
  console.error(
    'check-lazy-route-exports: found 0 lazyWithRetryNamed assignments in App.tsx.\n' +
      'The registration pattern changed — update this gate, or it is silently passing.',
  );
  process.exit(1);
}

if (checked !== expected) {
  console.error(
    `check-lazy-route-exports: parsed ${checked} of ${expected} call sites.\n` +
      `${expected - checked} use a form this gate does not recognise and were NOT checked.\n` +
      'Widen CALL_SITE rather than lowering the expectation — an unchecked route is how this bug ships.',
  );
  process.exit(1);
}

if (failures.length > 0) {
  console.error(`\nlazyWithRetryNamed export mismatches (${failures.length}):\n`);
  console.error(failures.join('\n'));
  console.error(
    '\nThese throw at runtime when the route is visited. tsc cannot catch them —\n' +
      'the export name is a string argument.\n',
  );
  process.exit(1);
}

console.log(`check-lazy-route-exports: ${checked} call sites OK`);
