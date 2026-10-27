// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4596 review-only: the real pivt panel drafting a response playbook
// inline next to the real /playbooks/new page (Start → Build), with synthetic
// API responses (meloD job included), no live IO. NAN-4597 adds the
// replace-unsaved-work guard (shot 04). Start
// `npx vite --host 127.0.0.1 --port 5187`, then run this with node.
// Screenshots land in docs-internal/reviews/NAN-4597/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5187';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4597/', import.meta.url));
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
const BRIEF = 'credential reuse by an offboarded employee: logins after the HR termination date, containment needs approval';
const draft = {
  doc: '---\ntitle: Credential reuse by offboarded account\ncategory: identity\n---\n',
  title: 'Credential reuse by offboarded account',
  subtitle: 'Logins from accounts HR has already terminated',
  category: 'identity',
  match_signals: ['iam.credential_reuse', 'auth.offboarded_login', 'okta.session_after_termination'],
  tags: ['offboarding', 'insider'],
  danger_policy: { 'action:high': 'approval' },
  review_cadence: '90d',
  parsed: {
    title: 'Credential reuse by offboarded account', intro: [], steps: [],
    phases: [
      { heading: 'Triage', body: [], steps: [
        { id: 's1', kind: 'query', label: 'Pull auth events for the account', params: { from: 'auth-events', where: 'user = "{{entity.user}}"', window: '7d' } },
        { id: 's2', kind: 'enrichment', label: 'Look up HR termination record', params: { source: 'hr-directory' } },
        { id: 'd1', kind: 'decision', label: 'Login after termination?', params: {}, options: ['yes', 'no'], decision_id: 'd1' },
      ] },
      { heading: 'Investigate', body: [], steps: [
        { id: 's4', kind: 'pivot', label: 'Pivot to source IPs and devices', params: { on: 'src_ip' } },
      ] },
      { heading: 'Contain', body: [], steps: [
        { id: 's5', kind: 'action', label: 'Disable the account', params: { danger: 'high' }, when: { ref: 'd1', op: '=', values: ['yes'] } },
        { id: 's6', kind: 'action', label: 'Revoke active sessions', params: { danger: 'medium' }, when: { ref: 'd1', op: '=', values: ['yes'] } },
      ] },
      { heading: 'Close', body: [], steps: [
        { id: 's7', kind: 'note', label: 'Record HR follow-up', params: {} },
      ] },
    ],
  },
  step_count: 7,
  repaired: false,
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
  '/api/melod/status': { connected: true },
  '/api/groups': { groups: [{ id: 'g1', name: 'soc-tier2' }] },
};
let job = { state: 'running', progress: 'Validating nPL query steps' };
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
    if (url.pathname === '/api/melod/playbook/draft') body = { job_id: 'jp', status: 'pending' };
    if (url.pathname === '/api/melod/jobs/jp') {
      body = job.state === 'running'
        ? { job_id: 'jp', status: 'running', progress: job.progress }
        : { job_id: 'jp', status: 'completed', result: draft };
    }
    if (body === undefined) { await request.respond({ status: 404, contentType: 'application/json', body: '{"message":"no fixture"}' }); return; }
    await request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  const shots = [];
  for (const theme of ['dark', 'light']) {
    await page.evaluateOnNewDocument((value) => {
      // Fresh authoring state per theme (one page load each).
      ['pb-new-draft-v2', 'pb-new-phase', 'pb-new-choice'].forEach((k) => localStorage.removeItem(k));
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
      const el = [...document.querySelectorAll(sel)].find((b) => b.textContent.trim().includes(t));
      el?.click();
      return !!el;
    }, selector, text);

    // 1. /playbooks/new Start → "Draft with pivt" focuses pivt with @playbook.
    await load('/playbooks/new');
    await page.waitForFunction(() => document.body.textContent.includes('How does this playbook begin?'));
    if (!(await clickText('button', 'Draft with pivt'))) throw new Error('no Draft with pivt option');
    await page.waitForFunction(() => document.activeElement?.getAttribute('aria-label') === 'Message pivt' && document.activeElement.value === '@playbook ');
    await shot('01-start-draft-with-pivt');

    // 2. Drafting in the panel.
    job = { state: 'running', progress: 'Validating nPL query steps' };
    await page.keyboard.type(BRIEF);
    await page.keyboard.press('Enter');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="running"]');
    await sleep(2600);
    await shot('02-pivt-drafting-playbook');

    // 3. Summary in pivt; the page lands on Build with the draft.
    job = { state: 'done' };
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="done"]', { timeout: 10000 });
    await page.waitForFunction(() => document.body.textContent.includes('Revoke active sessions'), { timeout: 10000 });
    await sleep(600);
    await shot('03-pivt-summary-build-phase');

    // 4. NAN-4597: edit the canvas, then draft again: pivt asks before it
    // replaces unsaved work. The Here card names the page (not Home).
    job = { state: 'done' };
    const title = await page.waitForSelector('input[placeholder="e.g. Offboarded contractor + dormant key"]');
    await title.click();
    await page.keyboard.down('Control');
    await page.keyboard.press('KeyA');
    await page.keyboard.up('Control');
    await page.keyboard.type('Credential reuse (my edits)');
    await page.focus('textarea[aria-label="Message pivt"]');
    await page.keyboard.type('@playbook credential reuse, tighter containment');
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => document.body.textContent.includes('Replace current draft'), { timeout: 10000 });
    await page.evaluate(() => {
      const cards = [...document.querySelectorAll('[data-testid="pivt-run-card"]')];
      cards[cards.length - 1]?.scrollIntoView({ block: 'end' });
    });
    await shot('04-pivt-replace-guard');
  }
  if (errors.length) throw new Error('Browser errors: ' + [...new Set(errors)].join('; '));
  console.log(shots.join('\n'));
} finally { await browser.close(); }
