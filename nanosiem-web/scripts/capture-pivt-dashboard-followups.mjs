// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4607 review-only: @dashboard follow-ups in the real pivt panel, with
// synthetic API responses (meloD jobs included), no live IO: a typed
// multi-choice answer that is not an offered option, and a failed follow-up
// round that keeps the answers on a Retry card. Start
// `npx vite --host 127.0.0.1 --port 5187`, then run this with node.
// Screenshots land in docs-internal/reviews/NAN-4607/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5187';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4607/', import.meta.url));
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
  components: Object.fromEntries(codes('TENANT_COMPONENT_CODES').map((code) => [code, { enabled: true, configuration: {} }])),
  featureFlags: { revision: 4, flags: Object.fromEntries(codes('ENTERPRISE_SHARED_FEATURE_FLAG_CODES').map((code) => [code, false])) },
};
const BRIEF = 'create a dashboard of failed logins by country for the last 7 days';
const questions = {
  session_id: 'sess-1', message: '', is_complete: false,
  clarifying_questions: [
    { id: 'window', question: 'Which time window should the panels default to?', question_type: 'single_choice', options: ['24h', '7d', '30d'], required: true },
    { id: 'sources', question: 'Which auth sources should it include?', question_type: 'multi_choice', options: ['okta', 'vpn', 'active-directory'], required: true },
    { id: 'geo', question: 'Group by country or by ASN?', question_type: 'free_text', default_answer: 'country', required: false },
  ],
};
const dashboard = {
  name: 'Failed logins by country',
  description: 'Failed authentication over 7 days from okta and vpn, by source country.',
  explanation: '',
  panels: [
    { id: 'p1', title: 'Failed logins over time', query: 'auth_result=failure | timechart span=1h count', query_mode: 'piped', visualization_type: 'line', visualization_config: {} },
    { id: 'p2', title: 'Failed logins', query: 'auth_result=failure | stats count', query_mode: 'piped', visualization_type: 'single_value', visualization_config: {} },
    { id: 'p3', title: 'Top source countries', query: 'auth_result=failure | stats count by enriched_src_country | sort -count', query_mode: 'piped', visualization_type: 'bar', visualization_config: {} },
    { id: 'p4', title: 'Top targeted users', query: 'auth_result=failure | stats count by user | sort -count | head 20', query_mode: 'piped', visualization_type: 'table', visualization_config: {} },
  ],
  layout: { columns: 12, row_height: 100, items: [
    { panel_id: 'p1', x: 0, y: 0, w: 8, h: 3 }, { panel_id: 'p2', x: 8, y: 0, w: 4, h: 3 },
    { panel_id: 'p3', x: 0, y: 3, w: 6, h: 3 }, { panel_id: 'p4', x: 6, y: 3, w: 6, h: 3 },
  ] },
  variables: [{ name: 'country', label: 'Country', variable_type: 'text' }],
  refresh_interval: 300,
  is_complete: true,
};
let generateCalls = 0;
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
  '/api/melod/status': { connected: true },
  '/api/dashboards': [],
};
let job = { state: 'running', progress: 'Validating panel queries against your schema' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 940, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('dialog', (dialog) => void dialog.accept());
  await page.setRequestInterception(true);
  page.on('request', async (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) { await request.abort(); return; }
    if (!url.pathname.startsWith('/api/')) { await request.continue(); return; }
    let body = responses[url.pathname];
    if (url.pathname === '/api/melod/dashboard/generate') {
      generateCalls += 1;
      body = { job_id: `jd${generateCalls}`, status: 'running' };
    }
    const jobMatch = /^\/api\/melod\/jobs\/jd(\d+)$/.exec(url.pathname);
    if (jobMatch) {
      const n = Number(jobMatch[1]);
      body = job.state === 'running'
        ? { job_id: `jd${n}`, status: 'running', progress: job.progress }
        : n % 3 === 1
          ? { job_id: `jd${n}`, status: 'completed', result: questions }
          : n % 3 === 2
            ? { job_id: `jd${n}`, status: 'failed', error: 'The dashboard agent timed out after 90 s. Try again.' }
            : { job_id: `jd${n}`, status: 'completed', result: { session_id: 'sess-1', message: '', is_complete: true, dashboard } };
    }
    if (body === undefined) { await request.respond({ status: 404, contentType: 'application/json', body: '{"message":"no fixture"}' }); return; }
    await request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  const shots = [];
  for (const theme of ['dark', 'light']) {
    generateCalls = 0;
    await page.evaluateOnNewDocument((value) => {
      localStorage.setItem('nanosiem-theme', value);
      localStorage.setItem('nano-pivt-open', '1');
      localStorage.setItem('nano-pivt-mode', 'dock');
      localStorage.setItem('nano-pivt-dock-width', '420');
    }, theme);
    const load = async (path) => {
      await page.goto(`${origin}/t/${tenant.slug}${path}`, { waitUntil: 'networkidle2' });
      await page.waitForSelector('textarea[aria-label="Message pivt"]', { timeout: 30000 });
      await page.evaluate((value) => { document.documentElement.classList.toggle('dark', value === 'dark'); document.documentElement.style.colorScheme = value; }, theme);
    };
    const shot = async (name) => { await page.evaluate(() => document.fonts.ready); await sleep(400); const p = `${output}${name}-${theme}.png`; await page.screenshot({ path: p }); shots.push(p); };
    const clickText = (selector, text) => page.evaluate((sel, t) => {
      const el = [...document.querySelectorAll(sel)].find((b) => b.textContent.trim() === t || b.textContent.trim().includes(t));
      el?.click();
      return !!el;
    }, selector, text);
    const scrollLastCard = () => page.evaluate(() => {
      const cards = [...document.querySelectorAll('[data-testid="pivt-run-card"]')];
      cards[cards.length - 1]?.scrollIntoView({ block: 'end' });
    });

    // 1. A typed multi-choice answer that is not an offered option.
    await load('/dashboards');
    if (!(await clickText('button', 'Generate with pivt'))) throw new Error('no Generate with pivt button');
    await page.waitForFunction(() => document.activeElement?.getAttribute('aria-label') === 'Message pivt' && document.activeElement.value === '@dashboard ');
    job = { state: 'done' };
    await page.keyboard.type(BRIEF.replace(/^create a dashboard of /, ''));
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => document.body.textContent.includes('questions before pivt builds the dashboard'), { timeout: 10000 });
    await clickText('[data-testid="pivt-run-card"] button', '7d');
    await sleep(300);
    await page.type('textarea[aria-label="Which auth sources should it include?"]', 'okta, syslog');
    await clickText('[data-testid="pivt-run-card"] button', 'Answer');
    await page.waitForFunction(() => document.body.textContent.includes('Not an option: syslog'), { timeout: 10000 });
    await scrollLastCard();
    await shot('01-pivt-multi-choice-not-an-option');

    // 2. Valid answers; the follow-up round fails and keeps them on a Retry card.
    await page.click('textarea[aria-label="Which auth sources should it include?"]');
    await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
    await page.keyboard.type('OKTA, vpn');
    await clickText('[data-testid="pivt-run-card"] button', 'Answer');
    await sleep(300);
    await clickText('[data-testid="pivt-run-card"] button', 'Use default');
    await page.waitForFunction(() => document.body.textContent.includes('Your answers are kept'), { timeout: 10000 });
    await scrollLastCard();
    await shot('02-pivt-followup-failed-answers-kept');
  }
  if (errors.length) throw new Error('Browser errors: ' + [...new Set(errors)].join('; '));
  console.log(shots.join('\n'));
} finally { await browser.close(); }
