// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4588 review-only: the real pivt panel drafting a SOAR flow inline, with
// synthetic API responses (meloD job included), no live IO. Start
// `npx vite --host 127.0.0.1 --port 5187`, then run this with node.
// Screenshots land in docs-internal/reviews/NAN-4588/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5187';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4588/', import.meta.url));
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
const FLOW_ID = 'f0000000-0000-4000-8000-000000000001';
const CONN = 'c0000000-0000-4000-8000-000000000001';
const action = (name, display, effect, forced) => ({
  name, display_name: display, description: '', effect, approval_required: effect !== 'read', approval_forced: forced, idempotent: true,
  inputs: [{ name: 'hostname', type: 'string', required: true, pattern: null }], require_one_of: [], rollback: null,
});
const pack = {
  origin: 'upstream', availability: 'available', name: 'crowdstrike', display_name: 'CrowdStrike Falcon', description: 'EDR', vendor: 'CrowdStrike', categories: ['edr'],
  version: '1.2.0', installed_version: '1.2.0', installed: true, upstream_changed: false, upstream_version: null, enabled: true, withdrawn: false, change_summary: '',
  actions: [action('get_host', 'Get host details', 'read', false), action('contain_host', 'Contain host', 'destructive', true)], test_action: 'get_host', per_minute: 60, per_day: 1000,
};
const flow = {
  id: FLOW_ID, name: 'High-sev alert entity hunt', version: 3, status: 'draft', trigger: { on: 'alert', match: null, cron: null },
  created_at: '2026-10-20T10:00:00Z', updated_at: '2026-10-26T10:00:00Z', next_run_at: null,
  definition: {
    summary: 'Contain', description: '',
    value: {
      modules: [
        { id: 'spread', summary: 'Spread', value: { type: 'search', query: 'process_name=powershell.exe host={{flow_input.alert.entities.host}} | stats count by host', window: '24h', limit: 100 } },
        { id: 'lookup', summary: 'Look up', value: { type: 'action', pack: 'crowdstrike', action: 'get_host', connection: CONN, input_transforms: { hostname: { type: 'expr', expr: 'flow_input.alert.entities.host' } }, approval: 'default' } },
        {
          id: 'route',
          value: {
            type: 'branchone',
            branches: [{ expr: 'flow_input.alert.severity in [high, critical]', summary: 'then', modules: [{ id: 'contain', value: { type: 'action', pack: 'crowdstrike', action: 'contain_host', connection: CONN, input_transforms: { hostname: { type: 'expr', expr: 'flow_input.alert.entities.host' } }, approval: 'required' } }] }],
            default: [],
          },
        },
      ],
    },
  },
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
  '/api/soar/settings': { soar_enabled: true, revision: 7, ai_daily_token_budget: 0, ai_usage: { day: '2026-10-26', budget_tokens: 0, reported_tokens: 0, inferences: 0, cache_hits: 0, denied: 0 } },
  '/api/soar/packs': { upstream_changed_count: 0, catalog_status: 'fresh', catalog_expires_at: null, packs: [pack] },
  '/api/soar/connections': { connections: [{ id: CONN, pack_name: 'crowdstrike', label: 'Falcon US-1', status: 'ok', config: {}, created_at: '2026-10-20T10:00:00Z', updated_at: '2026-10-20T10:00:00Z' }] },
  '/api/soar/runs': { runs: [], limit: 100, offset: 0 },
  [`/api/soar/flows/${FLOW_ID}`]: flow,
  '/api/soar/flows': { flows: [], event_overflow_count: 0, last_event_overflow_at: null, admission_backpressure: null },
  '/api/soar/flows/stats': { flows: [] },
  '/api/soar/catalog': { packs: [pack] },
  '/api/rules/validate': { valid: true, errors: [], effective_mode: 'scheduled', creates_materialized_view: false, mode_reason: '', realtime_eligible: false, referenced_fields: [] },
  '/api/alerts': [
    { id: 'a0000000-0000-4000-8000-0000000000a1', rule_id: 'r1', rule_name: 'Suspicious PowerShell download cradle', severity: 'high', status: 'new', matched_events: [{ host: 'FIN-LT-0388', user: 'jdoe', src_ip: '10.20.4.17' }], created_at: '2026-10-26T11:02:00Z' },
    { id: 'a0000000-0000-4000-8000-0000000000a2', rule_id: 'r2', rule_name: 'Impossible travel sign-in', severity: 'medium', status: 'new', matched_events: [{ user: 'akim', src_ip: '203.0.113.50' }], created_at: '2026-10-26T10:41:00Z' },
    { id: 'a0000000-0000-4000-8000-0000000000a3', rule_id: 'r3', rule_name: 'LSASS memory access', severity: 'critical', status: 'new', matched_events: [{ host: 'DC-02' }], created_at: '2026-10-26T09:15:00Z' },
  ],
  '/api/cases': { cases: [{ id: 'c5000000-0000-4000-8000-000000000042', case_number: 42, title: 'Ransomware precursor on FIN-LT-0388', severity: 'critical', status: 'in_progress', alert_count: 3, entity_count: 2, created_at: '2026-10-26T09:00:00Z' }], total_count: 1, limit: 10, offset: 0 },
};
const DAN = 'I want to create an automation flow that will check for a high sev alert, then search up important entities in npl search';
const created = { flow_id: FLOW_ID, name: 'High-sev alert entity hunt', version: 1, status: 'draft', trigger: { on: 'alert', match: 'severity >= high', cron: null }, module_count: 3, approval_gates: 1, repaired: false };
let job = { state: 'running', progress: 'Matching steps to your installed packs' };
const jobBody = () =>
  job.state === 'running' ? { job_id: 'j1', status: 'running', progress: job.progress }
  : job.state === 'done' ? { job_id: 'j1', status: 'completed', result: created }
  : { job_id: 'j1', status: 'failed', error: 'No installed pack provides an action for "isolate host". Install the CrowdStrike Falcon pack and add a connection, then try again.' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
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
    if (url.pathname === '/api/melod/flow/draft') body = { job_id: 'j1', status: 'pending' };
    if (url.pathname === '/api/melod/jobs/j1') body = jobBody();
    if (body === undefined) { await request.respond({ status: 404, contentType: 'application/json', body: '{"message":"no fixture"}' }); return; }
    await request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  const shots = [];
  for (const theme of ['dark', 'light']) {
    await page.evaluateOnNewDocument((value) => {
      localStorage.setItem('nanosiem-theme', value);
      localStorage.setItem('nano-pivt-open', '1');
      localStorage.setItem('nano-pivt-mode', 'dock');
      localStorage.setItem('nano-pivt-dock-width', '400');
    }, theme);
    const load = async (path) => {
      await page.goto(`${origin}/t/${tenant.slug}${path}`, { waitUntil: 'networkidle0' });
      await page.waitForSelector('textarea[aria-label="Message pivt"]', { timeout: 30000 });
      await page.evaluate((value) => { document.documentElement.classList.toggle('dark', value === 'dark'); document.documentElement.style.colorScheme = value; }, theme);
    };
    const shot = async (name) => { await page.evaluate(() => document.fonts.ready); await sleep(400); const p = `${output}${name}-${theme}.png`; await page.screenshot({ path: p }); shots.push(p); };
    const type = async (text) => { await page.focus('textarea[aria-label="Message pivt"]'); await page.keyboard.type(text); };

    // 1. "Draft with pivt" on Flows → pivt focused with @flow.
    await load('/automation/flows');
    await page.evaluate(() => [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Draft with pivt')?.click());
    await page.waitForFunction(() => document.activeElement?.getAttribute('aria-label') === 'Message pivt' && document.activeElement.value === '@flow ');
    await shot('01-draft-with-pivt-button');

    // 2. Dan's sentence, typed as free text, drafting in the panel.
    job = { state: 'running', progress: 'Matching steps to your installed packs' };
    await load('/automation/flows');
    await type(DAN);
    await page.keyboard.press('Enter');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="running"]');
    await sleep(2600); // one poll → progress stage
    await shot('02-pivt-drafting');

    // 3. Success: summary in pivt, page on the saved draft.
    job = { state: 'done' };
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="done"]', { timeout: 10000 });
    await page.waitForFunction((id) => location.pathname.endsWith(`/automation/flows/${id}`), {}, FLOW_ID);
    await sleep(800);
    await shot('03-pivt-drafted-opened');

    // 4. Failure: missing pack, reported in pivt.
    job = { state: 'failed' };
    await load('/automation/flows');
    await type('@flow On critical EDR alerts, isolate the host after an approval');
    await page.keyboard.press('Enter');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="failed"]', { timeout: 10000 });
    await shot('04-pivt-draft-failed');
  }
  if (errors.length) throw new Error('Browser errors: ' + [...new Set(errors)].join('; '));
  console.log(shots.join('\n'));
} finally { await browser.close(); }
