// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Static dead-internal-link check (NAN-1934) — the CI-friendly half of the
// dead-route defense. Unlike the Puppeteer crawler it needs NO running stack,
// NO browser, NO auth: pure text analysis, ~1s, deterministic.
//
// WHAT IT DOES
//   1. Extracts the React Router route table from App.tsx (`<Route path="…">`),
//      dropping the `*` / `/*` splat catch-alls (falling through to those IS the
//      404).
//   2. Scans the FE (nanosiem-web/src) and the Rust backend (nanosiem-*/src) for
//      literal internal app-path targets — `to=/href=/navigate(...)/href:` in
//      TS/TSX, and `link: Some("…")` / `"url": "…"` in Rust.
//   3. Normalizes each (strip query/hash; `${…}` / `{…}` / `:x` → wildcard) and
//      matches it against the route table. A target matching NO route is a dead
//      link — the same class as NAN-1933.
//   4. Ignores anything in dead-links-baseline.json, so the gate fails only on
//      NEW dead links.
//
// Exit 1 on any un-baselined dead link. `--update-baseline` rewrites the baseline
// from current findings (use when intentionally accepting them).
//
// PRECISION-FIRST (a noisy merge gate gets disabled). Known coverage gaps, left
// to the crawler / manual review:
//   - fully-dynamic targets (`to={item.href}`) — unresolvable statically
//   - Rust nav strings built outside `link:`/`"url":` (bare `format!`, `.to_string()`)
//   - webhook/email deep-links built without a leading slash

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../../..'); // nanosiem-web/tests/e2e -> repo root
const APP_TSX = path.join(REPO, 'nanosiem-web/src/App.tsx');
const BASELINE = path.join(HERE, 'dead-links-baseline.json');
const UPDATE = process.argv.includes('--update-baseline');

const FE_ROOTS = ['nanosiem-web/src'];
const BE_ROOTS = ['nanosiem-core/src', 'nanosiem-api/src', 'nanosiem-enterprise/src', 'nanosiem-search/src'];
const SKIP_DIRS = new Set(['node_modules', 'target', '.git', 'dist', 'build', '.next']);

// Valid non-SPA destinations that intentionally leave the router (served by the
// backend or the static host). Not dead links.
const IGNORE_EXACT = new Set(['/swagger-ui', '/swagger-ui/']);

// ---------- fs walk ----------
function walk(root, exts, out = []) {
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name.startsWith('.')) continue;
    const full = path.join(root, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(full, exts, out); }
    else if (exts.some((x) => e.name.endsWith(x))) out.push(full);
  }
  return out;
}

// ---------- path normalization + matching ----------
const stripQH = (p) => p.split('#')[0].split('?')[0];
function toSegs(p) {
  let s = stripQH(p).trim();
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
  if (s === '/' || s === '') return [''];
  return s.replace(/^\//, '').split('/');
}
// A segment is a wildcard if it's a route param (:x), a splat (*), or contains a
// JS/Rust interpolation (`${…}` or `{…}`).
const isWild = (seg) => seg === '*' || seg.startsWith(':') || /\$\{[^}]*\}/.test(seg) || /\{[^}]*\}/.test(seg);
const normSeg = (seg) => (isWild(seg) ? '*' : seg);
const normalizePath = (p) => '/' + toSegs(p).map(normSeg).join('/');

// A candidate we can't meaningfully check: not app-internal, an API path, a
// static asset (has a file extension in the last segment), or an allow-listed
// non-route destination.
function ignorable(raw) {
  if (!raw.startsWith('/') || raw.startsWith('//')) return true;
  if (raw.startsWith('/api/') || raw === '/api') return true;
  if (IGNORE_EXACT.has(stripQH(raw))) return true;
  const last = toSegs(raw).at(-1) || '';
  if (/\.[A-Za-z0-9]+$/.test(last)) return true; // e.g. Sync-ADUsers.ps1, foo.pdf
  return false;
}

function extractRoutes(src) {
  const routes = new Set();
  const re = /<Route\s+[^>]*?\bpath=["']([^"']+)["']/g;
  let m;
  while ((m = re.exec(src))) {
    const p = m[1];
    if (p === '*' || p === '/*') continue; // catch-all == 404, never a valid dest
    routes.add(p);
  }
  return [...routes].map((r) => ({ raw: r, segs: toSegs(r) }));
}

// Precision-first (deliberate): a wildcard on EITHER side skips that segment's
// comparison. So a dynamic candidate like `/settings/${tab}` is accepted by the
// static `/settings/ai` route. That under-reports a `${tab}` that could resolve
// to a bad value at runtime — but the stricter alternative (dynamic candidate
// must match a dynamic route) false-positives on the many legit `/base/${x}`
// navigations here, and a noisy merge gate gets turned off. Runtime coverage of
// that case is the crawler's job, not this gate's.
function matchesAnyRoute(candPath, routeSegs) {
  const c = toSegs(candPath);
  return routeSegs.some(({ segs: r }) => {
    if (r.length !== c.length) return false;
    for (let i = 0; i < r.length; i++) {
      if (isWild(r[i]) || isWild(c[i])) continue;
      if (r[i] !== c[i]) return false;
    }
    return true;
  });
}

// ---------- candidate extraction ----------
// Each rule captures a full delimited string literal (group `g`) so template
// interpolations (`${…}`) are preserved, then normalized to a wildcard.
const DELIM = `(["'\\\`])((?:(?!\\1)[\\s\\S])*?)\\1`; // group1=delim, group2=content
const FE_RULES = [
  { re: new RegExp(`\\b(?:to|href)=\\{?${DELIM}`, 'g'), g: 2 },
  { re: new RegExp(`\\bnavigate\\(\\s*${DELIM}`, 'g'), g: 2 },
  { re: new RegExp(`\\bhref:\\s*${DELIM}`, 'g'), g: 2 },
];
const BE_RULES = [
  { re: /\blink:\s*Some\(\s*(?:format!\(\s*)?"([^"]*)"/g, g: 1 },
  { re: /"url":\s*(?:format!\(\s*)?"([^"]*)"/g, g: 1 },
];

const lineOf = (content, index) => content.slice(0, index).split('\n').length;

function extractCandidates(file, rules) {
  const rel = path.relative(REPO, file);
  // Scan the whole file, not line-by-line: a `to=` / `navigate(` / `format!(`
  // literal can span multiple lines, and the DELIM regexes already match across
  // newlines. Map the match offset back to a line number for reporting.
  const content = fs.readFileSync(file, 'utf8');
  const out = [];
  for (const { re, g } of rules) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(content))) {
      const raw = m[g];
      if (!raw || ignorable(raw)) continue;
      out.push({ raw, norm: normalizePath(raw), src: `${rel}:${lineOf(content, m.index)}` });
    }
  }
  return out;
}

// ---------- main ----------
function loadBaseline() {
  try { return new Set(JSON.parse(fs.readFileSync(BASELINE, 'utf8')).baseline.map((b) => b.path)); }
  catch { return new Set(); }
}

function main() {
  if (!fs.existsSync(APP_TSX)) { console.error(`ERROR: App.tsx not found at ${APP_TSX}`); process.exit(2); }
  const routeSegs = extractRoutes(fs.readFileSync(APP_TSX, 'utf8'));
  console.log(`[dead-links] ${routeSegs.length} routes from App.tsx`);

  const candidates = [];
  for (const r of FE_ROOTS) for (const f of walk(path.join(REPO, r), ['.ts', '.tsx'])) candidates.push(...extractCandidates(f, FE_RULES));
  for (const r of BE_ROOTS) for (const f of walk(path.join(REPO, r), ['.rs'])) candidates.push(...extractCandidates(f, BE_RULES));
  console.log(`[dead-links] ${candidates.length} internal-link references scanned`);

  const dead = new Map(); // norm -> Set(src)
  for (const c of candidates) {
    if (matchesAnyRoute(c.norm, routeSegs)) continue;
    if (!dead.has(c.norm)) dead.set(c.norm, new Set());
    dead.get(c.norm).add(c.src);
  }

  if (UPDATE) {
    const baseline = [...dead.keys()].sort().map((p) => ({ path: p, note: 'TODO: fix or confirm intentional' }));
    fs.writeFileSync(BASELINE, JSON.stringify({ _comment: 'Known dead internal links (target matches no App.tsx route). Fix the link and delete the entry; new entries require review. Regenerate with --update-baseline.', baseline }, null, 2) + '\n');
    console.log(`[dead-links] wrote baseline with ${baseline.length} entries`);
    process.exit(0);
  }

  const baselined = loadBaseline();
  const violations = [...dead.entries()].filter(([p]) => !baselined.has(p)).sort();
  // Stale = baselined but no longer present in the code. Fail so a fixed link's
  // grandfather entry can't linger and silently re-admit the path later.
  const stale = [...baselined].filter((p) => !dead.has(p)).sort();

  console.log(`\n=== dead internal links: ${dead.size} total · ${baselined.size} baselined · ${violations.length} NEW · ${stale.length} stale ===\n`);
  for (const [p, srcs] of violations) {
    console.log(`  ✗ NEW  ${p}`);
    for (const s of [...srcs].sort()) console.log(`            ${s}`);
  }
  for (const p of stale) console.log(`  ⚠ STALE baseline entry (no longer in code — delete it): ${p}`);

  if (violations.length === 0 && stale.length === 0) {
    console.log('  no new dead internal links ✓');
    process.exit(0);
  }
  if (violations.length) {
    console.log(`\nEach ✗ target matches no route in App.tsx and would render the 404 page.`);
    console.log(`Fix the link, or (if intentional) run:  node nanosiem-web/tests/e2e/check-dead-links.mjs --update-baseline`);
  }
  if (stale.length) {
    console.log(`\nRemove the stale entries from dead-links-baseline.json (or re-run with --update-baseline).`);
  }
  process.exit(1);
}

main();
