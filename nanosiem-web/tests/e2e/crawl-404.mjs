// SPDX-License-Identifier: AGPL-3.0-or-later
//
// nano SPA dead-route / 404 crawler (NAN-1934) — the repo's first FE E2E check.
//
// WHY A BROWSER, NOT curl: the SPA serves `200 index.html` for every path and
// React Router decides 404 client-side. `response.status()` is therefore 200
// even for a dead route — detection MUST be DOM-based (the NotFoundPage marker
// below), never HTTP-status-based. A headless browser also surfaces two signals
// curl cannot: runtime `/api` 4xx/5xx (page.on('response')) and client crashes
// (page.on('pageerror')).
//
// WHAT IT DOES:
//   1. Logs in through the real /login terminal prompt (creds from env).
//   2. BFS-crawls internal links starting from a seed set of app routes,
//      following every same-origin <a href> it discovers.
//   3. Flags any visited URL that renders NotFoundPage, plus per-page network
//      responses >= 400 and console/page errors.
//   4. Writes crawl-404-report.json and prints a summary; exit code 1 if any
//      dead route (or, with STRICT=1, any runtime error) is found.
//
// USAGE:
//   NANO_E2E_USER=you@example.com NANO_E2E_PASS=… \
//   node tests/e2e/crawl-404.mjs
//
// ENV:
//   BASE_URL   (default http://localhost:5173)
//   NANO_E2E_USER / NANO_E2E_PASS   (required)
//   CHROME_PATH   explicit Chrome executable; else tries common paths / channel
//   MAX_PAGES  (default 250)   HEADLESS (default 1)   STRICT (default 0)
//   NAV_TIMEOUT_MS (default 20000)

import puppeteer from 'puppeteer-core';
import fs from 'node:fs';
import path from 'node:path';

const BASE_URL = (process.env.BASE_URL || 'http://localhost:5173').replace(/\/$/, '');
const USER = process.env.NANO_E2E_USER;
const PASS = process.env.NANO_E2E_PASS;
const MAX_PAGES = Number(process.env.MAX_PAGES || 250);
const HEADLESS = process.env.HEADLESS !== '0';
const STRICT = process.env.STRICT === '1';
const NAV_TIMEOUT = Number(process.env.NAV_TIMEOUT_MS || 20000);

if (!USER || !PASS) {
  console.error('ERROR: set NANO_E2E_USER and NANO_E2E_PASS'); process.exit(2);
}

// Protected, param-free routes to seed the crawl (from App.tsx). Public/auth/
// external/logout routes are deliberately excluded. Link-discovery fans out
// from here to reach dynamic and data-dependent pages.
const SEED_ROUTES = [
  '/', '/getting-started', '/dashboards', '/reports', '/search', '/observability',
  '/rules', '/rules/editor', '/rules/editor/new', '/rules/coverage', '/rules/repositories',
  '/rules/marketplace', '/rules/tuning', '/rules/lookup-tables', '/rules/lookup-tables/new',
  '/rules/retro-hunt/new', '/risk', '/prevalence', '/platform/health', '/alerts', '/inbox',
  '/cases', '/cases/search', '/playbooks', '/playbooks/new', '/playbooks/repositories',
  '/notebooks', '/marketplace', '/enrichments', '/enrichments/custom/new', '/upload',
  '/ingestion/log-sources', '/ingestion/log-sources/new', '/ingestion/log-sources/wizard',
  '/ingestion/log-sources/repositories', '/ingestion/credentials',
  '/ingestion/source-configurations', '/settings', '/settings/user', '/settings/notifications',
  '/settings/search', '/settings/storage', '/settings/ai', '/settings/prevalence',
  '/settings/risk', '/settings/cases', '/settings/cases/queues', '/settings/source-scopes',
  '/settings/access-control', '/settings/oidc', '/settings/audit', '/settings/gdpr',
  '/settings/airgap-import',
];

// Never enqueue these (auth/session-destroying/external/non-nav).
const SKIP_PREFIXES = ['/login', '/logout', '/setup', '/mfa-setup', '/denied', '/demo', '/d/', '/auth/', '/docs'];
const isInternal = (href) => href && href.startsWith('/') && !href.startsWith('//') && !href.startsWith('/api/');
const skip = (p) => SKIP_PREFIXES.some((s) => p === s || p.startsWith(s));
// Collapse a concrete path to a crawl key so we don't re-crawl 500 sibling
// detail pages: keep the routing shape, treat the last id-ish segment as one.
const normalizePath = (p) => p.split('#')[0].split('?')[0].replace(/\/$/, '') || '/';

function chromePath() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const candidates = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  ];
  return candidates.find((c) => { try { return fs.existsSync(c); } catch { return false; } });
}

async function login(page) {
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT });
  // Email step: one focused terminal input.
  await page.waitForSelector('form input:not([disabled])', { timeout: NAV_TIMEOUT });
  await page.click('form input:not([disabled])').catch(() => {});
  await page.keyboard.type(USER, { delay: 8 });
  await page.keyboard.press('Enter');
  // Password step: identified by autocomplete="current-password".
  await page.waitForSelector('input[autocomplete="current-password"]:not([disabled])', { timeout: NAV_TIMEOUT });
  await page.click('input[autocomplete="current-password"]').catch(() => {});
  await page.keyboard.type(PASS, { delay: 8 });
  await page.keyboard.press('Enter');
  // Success = navigated off /login. MFA prompt = we can't proceed headless.
  try {
    await page.waitForFunction(() => !location.pathname.startsWith('/login'), { timeout: NAV_TIMEOUT });
  } catch {
    const onMfa = await page.evaluate(() => document.body.innerText.toLowerCase().includes('authenticator'));
    throw new Error(onMfa ? 'login stuck on MFA step — E2E user must have MFA disabled' : 'login did not leave /login');
  }
  // Leaving /login isn't enough: a redirect to /mfa-setup or /denied means we're
  // NOT authenticated, and crawling from there would report a false-clean.
  const dest = new URL(page.url()).pathname;
  if (dest.startsWith('/mfa-setup')) throw new Error('login requires MFA — the E2E user must have MFA disabled');
  if (dest.startsWith('/denied')) throw new Error('login landed on /denied — the E2E user lacks access');
}

async function inspect(page, url, buffers) {
  buffers.network.length = 0; buffers.console.length = 0;
  let httpStatus = null;
  try {
    // domcontentloaded (not networkidle) — the SIEM polls constantly, so the
    // network never goes idle and networkidle2 would hang every page to timeout.
    const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT });
    httpStatus = resp ? resp.status() : null;
  } catch (e) {
    return { url, error: `navigation: ${e.message}`, is404: false, finalUrl: url, httpStatus, links: [] };
  }
  // Wait for React to mount the route (lazy Suspense chunk + component), then a
  // short settle for the route body to paint.
  await page
    .waitForFunction(() => { const r = document.getElementById('root'); return r && r.children.length > 0; }, { timeout: NAV_TIMEOUT })
    .catch(() => {});
  await new Promise((r) => setTimeout(r, 700));

  const { is404, links, title } = await page.evaluate(() => {
    const marker = !!document.querySelector('[data-testid="not-found-404"]');
    const textHit = document.body && document.body.innerText.includes('Nothing here, detective');
    const hrefs = [...document.querySelectorAll('a[href]')]
      .map((a) => a.getAttribute('href'))
      .filter(Boolean);
    return { is404: marker || textHit, links: hrefs, title: document.title };
  });

  return {
    url,
    finalUrl: normalizePath(new URL(page.url()).pathname),
    httpStatus,
    is404,
    title,
    network: [...buffers.network],
    console: [...buffers.console],
    links,
  };
}

async function main() {
  const exe = chromePath();
  if (!exe) { console.error('ERROR: no Chrome found; set CHROME_PATH'); process.exit(2); }
  console.log(`[crawl] chrome: ${exe}`);
  console.log(`[crawl] base:   ${BASE_URL}`);

  const browser = await puppeteer.launch({
    executablePath: exe,
    headless: HEADLESS ? 'new' : false,
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--window-size=1440,900'],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  // Per-page buffers, filled by listeners, reset before each navigation.
  const buffers = { network: [], console: [] };
  page.on('response', (r) => {
    try {
      const u = new URL(r.url());
      if (r.status() >= 400 && u.origin === new URL(BASE_URL).origin) {
        buffers.network.push({ status: r.status(), method: r.request().method(), url: u.pathname + u.search });
      }
    } catch { /* ignore */ }
  });
  page.on('console', (m) => { if (m.type() === 'error') buffers.console.push(m.text().slice(0, 300)); });
  page.on('pageerror', (e) => buffers.console.push(`pageerror: ${String(e).slice(0, 300)}`));

  console.log('[crawl] logging in…');
  await login(page);
  console.log('[crawl] logged in OK');

  const queue = [];
  const seen = new Set();
  const parents = new Map(); // path -> Set(source pages)
  for (const r of SEED_ROUTES) { queue.push(r); seen.add(r); parents.set(r, new Set(['(seed)'])); }

  const results = [];
  let visited = 0;
  while (queue.length && visited < MAX_PAGES) {
    const p = queue.shift();
    if (skip(p)) continue;
    const url = `${BASE_URL}${p}`;
    const res = await inspect(page, url, buffers);
    visited++;
    res.pathKey = p;
    res.sources = [...(parents.get(p) || [])];
    results.push(res);
    const flag = res.is404 ? '404!' : res.error ? 'ERR ' : res.network.length ? 'net ' : 'ok  ';
    console.log(`[${String(visited).padStart(3)}/${queue.length + visited}] ${flag} ${p}`);

    for (const href of res.links || []) {
      const norm = normalizePath(href);
      if (!isInternal(href) || skip(norm) || seen.has(norm)) continue;
      seen.add(norm);
      parents.set(norm, new Set([p]));
      queue.push(norm);
    }
    // record additional parents for already-seen links (for better attribution)
    for (const href of res.links || []) {
      const norm = normalizePath(href);
      if (isInternal(href) && !skip(norm) && parents.has(norm)) parents.get(norm).add(p);
    }
  }

  const deadRoutes = results.filter((r) => r.is404).map((r) => ({ path: r.pathKey, sources: r.sources }));
  const navErrors = results.filter((r) => r.error).map((r) => ({ path: r.pathKey, error: r.error }));
  const networkErrors = results
    .filter((r) => r.network && r.network.length)
    .map((r) => ({ path: r.pathKey, responses: r.network }));
  const consoleErrors = results
    .filter((r) => r.console && r.console.length)
    .map((r) => ({ path: r.pathKey, errors: r.console }));

  const report = {
    base: BASE_URL,
    crawledAt: new Date().toISOString(),
    pagesVisited: visited,
    queuedButUnvisited: queue.length,
    summary: {
      deadRoutes: deadRoutes.length,
      navErrors: navErrors.length,
      pagesWithNetworkErrors: networkErrors.length,
      pagesWithConsoleErrors: consoleErrors.length,
    },
    deadRoutes, navErrors, networkErrors, consoleErrors,
  };

  const out = path.join(process.cwd(), 'crawl-404-report.json');
  fs.writeFileSync(out, JSON.stringify(report, null, 2));

  console.log('\n================ CRAWL REPORT ================');
  console.log(`pages visited: ${visited}  (unvisited in queue: ${queue.length})`);
  console.log(`DEAD ROUTES (rendered NotFoundPage): ${deadRoutes.length}`);
  for (const d of deadRoutes) console.log(`   ✗ ${d.path}   ← linked from: ${d.sources.join(', ')}`);
  console.log(`NAV ERRORS: ${navErrors.length}`);
  for (const n of navErrors) console.log(`   ! ${n.path}: ${n.error}`);
  console.log(`PAGES WITH /api ${'>='}400: ${networkErrors.length}`);
  for (const n of networkErrors) console.log(`   ~ ${n.path}: ${n.responses.map((x) => `${x.status} ${x.method} ${x.url}`).join('; ')}`);
  console.log(`PAGES WITH CONSOLE ERRORS: ${consoleErrors.length}`);
  console.log(`\nfull report: ${out}`);
  console.log('=============================================');

  await browser.close();
  const fail = deadRoutes.length > 0 || navErrors.length > 0 || (STRICT && (networkErrors.length || consoleErrors.length));
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error('FATAL', e); process.exit(2); });
