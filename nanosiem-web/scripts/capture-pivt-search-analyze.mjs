// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4589 review-only: Search Analyze running in the real pivt panel next to
// the real Search page, with synthetic API responses (search + meloD job), no
// live IO. Start `npx vite --host 127.0.0.1 --port 5187`, then run this with
// node. Screenshots land in docs-internal/reviews/NAN-4589/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5187';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4589/', import.meta.url));
mkdirSync(output, { recursive: true });
const contract = readFileSync(new URL('../src/lib/tenant-capabilities.ts', import.meta.url), 'utf8');
const codes = (name) => [...contract.match(new RegExp('export const ' + name + ' = \\[([\\s\\S]*?)\\] as const;'))[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
const tenant = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'design-review' };
const user = { id: '018f6f72-84b6-7a10-9f11-7ab36f022001', name: 'Review Admin', email: 'admin@example.com', roles: ['admin'], permissions: ['*'], deployment_mode: 'enterprise_shared', active_tenant: tenant };
const bootstrap = {
  edition: 'enterprise', version: '1.0.9', deploymentMode: 'enterprise_shared', tenant,
  identity: { userId: user.id, roles: user.roles, permissions: user.permissions, authorizationRevision: 3 },
  plan: { code: 'lean-soar', revision: 1, assignmentRevision: 2 },
  limits: { ha_enabled: true, retention_days: 30 }, haEnabled: true,
  components: Object.fromEntries([...codes('TENANT_COMPONENT_CODES'), 'soar'].map((code) => [code, { enabled: true, configuration: {} }])),
  featureFlags: { revision: 4, flags: Object.fromEntries(codes('ENTERPRISE_SHARED_FEATURE_FLAG_CODES').map((code) => [code, false])) },
};
const ROWS = [
  ['2026-10-26T13:41:07.112Z', 'auth-gw-01', '203.0.113.50', 'root', 'failure', 'Failed password for root from 203.0.113.50 port 51122 ssh2'],
  ['2026-10-26T13:41:05.870Z', 'auth-gw-01', '203.0.113.50', 'admin', 'failure', 'Failed password for admin from 203.0.113.50 port 51098 ssh2'],
  ['2026-10-26T13:40:59.004Z', 'auth-gw-02', '203.0.113.50', 'oracle', 'failure', 'Failed password for invalid user oracle from 203.0.113.50 port 50911 ssh2'],
  ['2026-10-26T13:40:51.337Z', 'auth-gw-01', '203.0.113.50', 'root', 'failure', 'Failed password for root from 203.0.113.50 port 50876 ssh2'],
  ['2026-10-26T13:38:12.450Z', 'bastion-01', '10.20.4.17', 'deploy', 'success', 'Accepted publickey for deploy from 10.20.4.17 port 40022 ssh2'],
  ['2026-10-26T13:36:44.019Z', 'auth-gw-02', '198.51.100.23', 'jdoe', 'failure', 'Failed password for jdoe from 198.51.100.23 port 61210 ssh2'],
  ['2026-10-26T13:35:02.781Z', 'bastion-01', '10.20.4.17', 'deploy', 'success', 'Accepted publickey for deploy from 10.20.4.17 port 40011 ssh2'],
  ['2026-10-26T13:31:18.260Z', 'auth-gw-01', '203.0.113.50', 'test', 'failure', 'Failed password for invalid user test from 203.0.113.50 port 49880 ssh2'],
].map(([timestamp, src_host, src_ip, user, auth_result, message]) => ({ timestamp, src_host, src_ip, user, auth_result, message, source_type: 'linux_auth' }));
const QUERY = 'source_type="linux_auth" (Failed OR Accepted)';
const searchResponse = (q) => ({
  results: q.includes('203.0.113.50') ? ROWS.filter((r) => r.src_ip === '203.0.113.50') : ROWS,
  total_count: q.includes('203.0.113.50') ? 5 : 1284, fields: [], execution_time_ms: 38, display_type: 'events',
});
const summary = {
  narrative: 'Most failures in this window come from one external address, **203.0.113.50**, cycling through privileged and default account names (root, admin, oracle, test) every few seconds. The only successful logins are the `deploy` key from the internal bastion, which matches its normal schedule.',
  key_findings: [
    { category: 'auth', title: 'Password spraying against privileged accounts', description: '5 of 8 sampled failures target root/admin/default names from 203.0.113.50.', importance: 'high', related_fields: ['src_ip', 'user'] },
    { category: 'auth', title: 'No success from the spraying source', description: 'No Accepted event from 203.0.113.50 in this window.', importance: 'medium', related_fields: ['src_ip', 'auth_result'] },
  ],
  suspicious_items: [
    { field: 'src_ip', anomaly_type: 'dominance', title: 'One source dominates failures', description: '', value: '203.0.113.50', percentage: 71.4, severity: 'high' },
    { field: 'user', anomaly_type: 'rare_value', title: 'Default account name', description: '', value: 'oracle', percentage: 12.5, severity: 'medium' },
  ],
  suggested_queries: [
    { description: 'Everything from the spraying source', query: 'src_ip="203.0.113.50"', rationale: '', priority: 'high' },
    { description: 'Any success for the targeted accounts', query: 'auth_result="success" user IN ("root","admin","oracle","test") | stats count by user, src_ip', rationale: '', priority: 'high' },
  ],
  risk_assessment: { level: 'high', explanation: 'Privileged accounts are being guessed from the internet; no successful login from that source yet.', indicators: [] },
};
const responses = {
  '/api/auth/refresh': { access_token: 'synthetic-review-session', refresh_token: 'synthetic-review-session', expires_in: 3600 },
  '/api/auth/me': user,
  '/api/notebooks/tabs': [],
  '/api/notebooks/active': null,
  '/api/schema/fields': { fields: [] },
  '/api/notifications/unread-count': { count: 0 },
  '/api/auth/tenant-bootstrap': bootstrap,
  '/api/system/config': { deployment_mode: 'enterprise_shared', air_gap: false, auth_enabled: true },
  '/api/setup/status': { initialized: true, has_users: true },
  '/api/settings/ai-availability': { connected: true, model_available: true },
  '/api/settings/tier': { limits: { tier: 'unrestricted', sso_enabled: true, api_access: 'full' }, ai_usage: {} },
  '/api/users/me/preferences': { theme: 'dark', timezone: 'UTC' },
  '/api/search/histogram': { histogram: Array.from({ length: 24 }, (_, i) => ({ time: new Date(Date.parse('2026-10-25T14:00:00Z') + i * 3600_000).toISOString(), count: i > 20 ? 260 : 18 + (i % 5) })) },
  '/api/search/field-stats': { fields: [] },
  '/api/search/history': [],
  '/api/saved-searches': [],
};
let job = { state: 'running', progress: 'Scoring rare values and dominant sources' };
const jobBody = () =>
  job.state === 'running' ? { job_id: 'j1', status: 'running', progress: job.progress }
  : job.state === 'done' ? { job_id: 'j1', status: 'completed', result: summary }
  : { job_id: 'j1', status: 'failed', error: 'The AI provider timed out after 60s. Try again, or narrow the search first.' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
const missing = new Set();
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 940, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.setRequestInterception(true);
  page.on('request', async (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) { await request.abort(); return; }
    if (!url.pathname.startsWith('/api/')) { await request.continue(); return; }
    let body = responses[url.pathname];
    if (url.pathname === '/api/search') {
      const q = JSON.parse(request.postData() ?? '{}').query ?? '';
      body = searchResponse(q);
    }
    if (url.pathname === '/api/melod/summarize') body = { job_id: 'j1', status: 'pending' };
    if (url.pathname === '/api/melod/jobs/j1') body = jobBody();
    if (body === undefined) {
      missing.add(`${request.method()} ${url.pathname}`);
      await request.respond({ status: 404, contentType: 'application/json', body: '{"message":"no fixture"}' });
      return;
    }
    await request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  const shots = [];
  const searchPath = `/search#q=${encodeURIComponent(QUERY)}&time=${encodeURIComponent('Last 24 hours')}`;
  for (const theme of ['dark', 'light']) {
    await page.evaluateOnNewDocument((value) => {
      if (location.protocol === 'about:') return;
      localStorage.setItem('nanosiem-theme', value);
      localStorage.setItem('nano-pivt-open', '0');
      localStorage.setItem('nano-pivt-mode', 'dock');
      localStorage.setItem('nano-pivt-dock-width', '400');
    }, theme);
    const load = async (path) => {
      // A hash-only change keeps the document (and pivt's session runs); start clean.
      await page.goto('about:blank');
      await page.goto(`${origin}/t/${tenant.slug}${path}`, { waitUntil: 'networkidle0' });
      await page.evaluate((value) => { document.documentElement.classList.toggle('dark', value === 'dark'); document.documentElement.style.colorScheme = value; }, theme);
      await page.waitForFunction(() => [...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Analyze'), { timeout: 30000 });
    };
    const shot = async (name) => { await page.evaluate(() => document.fonts.ready); await sleep(400); const p = `${output}${name}-${theme}.png`; await page.screenshot({ path: p }); shots.push(p); };
    const clickAnalyze = () => page.evaluate(() => [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Analyze')?.click());

    // 1. Results with the Analyze button; pivt closed.
    await load(searchPath);
    await shot('01-search-results-analyze');

    // 2. Analyze → pivt opens, progress in the panel, results stay.
    job = { state: 'running', progress: 'Scoring rare values and dominant sources' };
    await clickAnalyze();
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="running"]');
    await sleep(2600); // one poll → progress stage
    await shot('02-pivt-analyzing');

    // 3. Done: the analysis card with pivots, results still on the page.
    job = { state: 'done' };
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="done"]', { timeout: 10000 });
    await sleep(600);
    await page.evaluate(() => document.querySelector('[data-testid="pivt-draft-run"]')?.scrollIntoView({ block: 'start' }));
    await shot('03-pivt-analysis-card');
    await page.evaluate(() => document.querySelector('[data-testid="pivt-pivot-query"]')?.scrollIntoView({ block: 'center' }));
    await shot('03b-pivt-analysis-pivots');

    // 4. A pivot writes the query bar and runs it in the same window.
    await page.evaluate(() => document.querySelector('[data-testid="pivt-pivot-query"]')?.click());
    await page.waitForFunction(() => decodeURIComponent(location.hash).includes('203.0.113.50'), { timeout: 10000 });
    await sleep(1500);
    await shot('04-pivot-ran');

    // 5. @summarize with a focus, failed job → reported in pivt.
    job = { state: 'failed' };
    await load(searchPath);
    await page.evaluate(() => window.dispatchEvent(new CustomEvent('pivt:open-panel', { detail: {} })));
    await page.waitForSelector('textarea[aria-label="Message pivt"]', { visible: true, timeout: 10000 });
    await page.focus('textarea[aria-label="Message pivt"]');
    await page.keyboard.type('@summarize privileged accounts');
    await page.keyboard.press('Enter');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="failed"]', { timeout: 10000 });
    await shot('05-pivt-analysis-failed');
  }
  if (missing.size) console.error('Unfixtured API calls (404):\n  ' + [...missing].join('\n  '));
  if (errors.length) throw new Error('Browser errors: ' + [...new Set(errors)].join('; '));
  console.log(shots.join('\n'));
} finally { await browser.close(); }
