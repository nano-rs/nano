#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-2356 — static gate: a core file that renders a SILENT enterprise stub
// must consult capabilities first.
//
// In open builds `@/enterprise/*` aliases to `src/enterprise-stubs/`. Some of
// those stubs `return null` by design — the enterprise feature simply isn't
// there. That is fine when the *call site* knows to hide its affordance, and a
// silent failure when it doesn't: the button renders, it's clickable, and
// nothing happens. Nothing throws, so tsc, `vite build`, and every existing
// suite stay green.
//
// That is exactly how "+ New Dashboard" shipped inert to every open-core
// install (NAN-2356). `Dashboards.tsx` imported the enterprise
// DashboardGenerationWizard, which stubs to `return null`, and never checked a
// capability — so all four create affordances flipped state and rendered
// nothing. Reported twice from the field before anyone caught it, because a
// developer's localhost is an ENTERPRISE build where it works.
//
// The rule: if a core file imports a symbol whose open stub renders nothing, it
// must reference `useCapabilities`. That's a heuristic, not a proof — it can't
// verify the gate covers the right JSX — but it forces the author to make a
// deliberate decision instead of inheriting an inert control by accident. The
// real behavioural check is the open-edition E2E smoke in NAN-2359.
//
// Sibling of check-lazy-route-exports.mjs: same "route/control renders wrong"
// class, same pure-text approach, no build and no browser.
//
// Not a ratchet: every call site passes at the time of writing, so any failure
// here is a regression introduced by the PR under test.

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, '../..');
const srcRoot = join(webRoot, 'src');
const stubRoot = join(srcRoot, 'enterprise-stubs');

// Symbols exempt from the gate.
//
// Deliberately EMPTY. The first draft exempted `PivtIcon` as "just decoration",
// which was wrong: `WhatsNew.tsx` renders it as the entire content of an icon
// button, so a null icon left an invisible-but-clickable control. The fix was to
// stop stubbing the icon at all (it now lives in core), not to exempt it —
// which is the right instinct for this whole category. It also carried
// `SsoIcon`/`SsoIcons`, neither of which is an exported symbol anywhere; dead
// entries in an allowlist are worse than no allowlist, because they read as
// considered decisions.
//
// If you are about to add something here, prefer one of these instead:
//   - make the stub render a real neutral fallback (best for icons/labels), or
//   - move the symbol into core if it isn't actually an enterprise feature, or
//   - gate the call site, which is what this check is asking for.
const EXEMPT_SYMBOLS = new Set([]);

/** Recursively list .ts/.tsx files under dir. */
function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

// ---------------------------------------------------------------------------
// 1. Which stubs render nothing?
// ---------------------------------------------------------------------------

// A stub is "silent" when it returns null — i.e. mounting it produces no DOM.
// Stubs that render the shared EnterprisePagePlaceholder are explicitly NOT
// silent: they tell the user the surface is paid-only, which is a fine outcome.
const SILENT = /(^|\s)return null;|=>\s*null[;,)\s]/;

const silentSymbols = new Map(); // exported name -> stub path (repo-relative)
const silentModules = new Set(); // stub paths that also have a default export

for (const file of walk(stubRoot)) {
  const src = readFileSync(file, 'utf8');
  if (!SILENT.test(src)) continue;
  if (src.includes('EnterprisePagePlaceholder')) continue;

  const rel = relative(webRoot, file);
  for (const m of src.matchAll(/export\s+(?:async\s+)?function\s+([A-Za-z0-9_]+)/g)) {
    silentSymbols.set(m[1], rel);
  }
  for (const m of src.matchAll(/export\s+const\s+([A-Za-z0-9_]+)/g)) {
    silentSymbols.set(m[1], rel);
  }
  // Every silent stub also has a default export. A consumer importing the
  // default binds it under a name of its own choosing, so record the MODULE
  // and match on the specifier rather than the symbol.
  if (/export\s+default\s/.test(src)) {
    silentModules.add(rel);
  }
}

if (silentSymbols.size === 0) {
  console.error(
    'check-enterprise-stub-gating: found no silent stubs at all. Either every ' +
      'stub now renders a placeholder (great — delete this gate) or the ' +
      'detection regexes went stale. Failing loudly rather than passing blind.',
  );
  process.exit(1);
}

/**
 * `@/enterprise/foo/Bar` -> `src/enterprise-stubs/foo/Bar.{tsx,ts}` if it exists.
 *
 * Handles an explicit extension first: `tsconfig.app.json` sets
 * `allowImportingTsExtensions`, so `'@/enterprise/…/AnalyzeView.tsx'` is a legal
 * import. Blindly appending would look for `AnalyzeView.tsx.tsx`, find nothing,
 * and wave the import through — a gate that can be bypassed by spelling the
 * extension out is not a gate.
 */
function stubPathForSpecifier(spec) {
  const sub = spec.replace(/^@\/enterprise\//, '');
  const candidates = /\.tsx?$/.test(sub)
    ? [sub]
    : [`${sub}.tsx`, `${sub}.ts`, `${sub}/index.tsx`, `${sub}/index.ts`];
  for (const candidate of candidates) {
    const full = join(stubRoot, candidate);
    if (existsSync(full)) return relative(webRoot, full);
  }
  return null;
}

// ---------------------------------------------------------------------------
// 2. Which core files import them?
// ---------------------------------------------------------------------------

const violations = [];
let checkedSites = 0;

for (const file of walk(srcRoot)) {
  const rel = relative(webRoot, file);
  // Enterprise code may use its own components freely — it never resolves to
  // the stub tree. Skip the stub tree itself too.
  if (rel.includes('src/enterprise/') || rel.includes('src/enterprise-stubs/')) continue;

  const src = readFileSync(file, 'utf8');
  if (!src.includes('@/enterprise/')) continue;

  const gated = src.includes('useCapabilities');
  const lines = src.split('\n');

  // Named imports from an @/enterprise specifier, single- or multi-line.
  for (const m of src.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"]@\/enterprise\/[^'"]+['"]/g)) {
    const names = m[1]
      .split(',')
      .map(n => n.replace(/\btype\b/, '').trim().split(/\s+as\s+/)[0].trim())
      .filter(Boolean);

    for (const name of names) {
      if (!silentSymbols.has(name)) continue;
      if (EXEMPT_SYMBOLS.has(name)) continue;
      checkedSites += 1;
      if (gated) continue;

      const lineNo = lines.findIndex(l => l.includes(name)) + 1;
      violations.push({
        file: rel,
        line: lineNo,
        symbol: name,
        stub: silentSymbols.get(name),
      });
    }
  }

  // Default imports: `import Foo from '@/enterprise/...'`. The local name tells
  // us nothing, so match on the module the specifier resolves to.
  for (const m of src.matchAll(
    /import\s+([A-Za-z0-9_$]+)\s*(?:,\s*\{[^}]*\}\s*)?from\s*['"](@\/enterprise\/[^'"]+)['"]/g,
  )) {
    const [, localName, spec] = m;
    const stub = stubPathForSpecifier(spec);
    if (!stub || !silentModules.has(stub)) continue;
    if (EXEMPT_SYMBOLS.has(localName)) continue;
    checkedSites += 1;
    if (gated) continue;
    violations.push({
      file: rel,
      line: lines.findIndex(l => l.includes(spec)) + 1,
      symbol: `${localName} (default)`,
      stub,
    });
  }
}

// ---------------------------------------------------------------------------
// 3. Report
// ---------------------------------------------------------------------------

if (violations.length > 0) {
  console.error(
    `\ncheck-enterprise-stub-gating: ${violations.length} ungated silent enterprise import(s).\n`,
  );
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}`);
    console.error(`    imports '${v.symbol}', which renders nothing in open builds (${v.stub})`);
    console.error(`    but this file never calls useCapabilities().\n`);
  }
  console.error(
    'In an open-core build this renders a control that does nothing and logs no\n' +
      'error. Gate the affordance on the owning capability, e.g.:\n\n' +
      "    const { capabilities } = useCapabilities();\n" +
      '    {capabilities.melod && <TheEnterpriseThing />}\n\n' +
      'If the symbol is not really an enterprise feature, move it into core; if\n' +
      'the stub just needs to render something neutral, fix the stub. See the\n' +
      'EXEMPT_SYMBOLS note in this script before reaching for an exemption.\n',
  );
  process.exit(1);
}

console.log(
  `check-enterprise-stub-gating: OK — ${checkedSites} core import site(s) of ` +
    `${silentSymbols.size} silent stub(s), all capability-gated.`,
);
