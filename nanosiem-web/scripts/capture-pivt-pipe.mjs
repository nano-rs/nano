// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4609 review-only: the real pivt panel working on a Pipe step next to
// the real Pipelines page (pivt button → @pipe → proposal diff card → Apply
// to step), with synthetic API responses, no live IO. Start
// `npx vite --host 127.0.0.1 --port 5188`, then run this with node.
// Screenshots land in docs-internal/reviews/NAN-4609/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5188';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4609/', import.meta.url));
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

const HEADER = '# nano-pipe-v2 ';
const PLAN_BODY = '# Processing plan compiled by Nano at publication.\nnano_pipe_plan_v2()';
const steps = [
  { id: 'p', name: 'Parse JSON', kind: 'parse', enabled: true, config: { format: 'json', field: 'message' } },
  { id: 'v', name: 'Tag severity', kind: 'vrl', enabled: true, config: { code: '.severity = upcase(.sev)\n.severity_rank = to_int(.rank)' } },
  { id: 'd', name: 'Drop health checks', kind: 'vrl', enabled: true, config: { code: 'if .path == "/healthz" { abort }' } },
];
const now = new Date().toISOString();
const source = {
  id: 's1', name: 'Edge firewall', description: 'Perimeter firewall events', namespace: 'onprem:dc-east', timezone: 'UTC',
  source_type: 'syslog', parser_vrl: HEADER + JSON.stringify({ version: 2, revision: 4, steps }) + '\n' + PLAN_BODY,
  enabled: true, created_at: now, updated_at: now, has_draft_changes: false, active_version_number: 3,
};
const SAMPLES = [
  '{"sev":"high","rank":"3","src":"10.0.0.8","dst":"203.0.113.9","path":"/login"}',
  '{"rank":"1","src":"10.0.0.9","dst":"203.0.113.9","path":"/login"}',
  '{"sev":"low","rank":"2","src":"10.0.0.12","dst":"198.51.100.4","path":"/healthz"}',
];
const FIXED = '.severity = upcase(string(.sev) ?? "unknown")\n.severity_rank = to_int(.rank) ?? 0';
const editResult = {
  session_id: 'sess-1',
  message: 'Event 2 has no `.sev`, so `upcase` receives `null` and the step aborts. Coerce `.sev` to a string with a fallback, and give `to_int` a default so a non-numeric `.rank` does not fail the step either.',
  updated_vrl: FIXED,
  validation: { valid: true, errors: [] },
  test_results: SAMPLES.map((input) => ({ input, success: true })),
};
let jobs = 0;
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
  '/api/log-sources/s1/draft-status': source,
  '/api/log-sources/s1': source,
  '/api/log-sources/s1/pipe-capabilities': {
    engine: 'vector-vrl', supported_step_kinds: ['vrl', 'parse', 'set', 'rename', 'drop', 'filter', 'route', 'sample'], preview_enabled: true,
    capture: { stages: ['input'], default_duration_seconds: 30, max_duration_seconds: 120, default_max_events: 50, max_events: 200, max_bytes: 1048576, enabled: false, reason: 'Capture is off in this review.' },
    warnings: [],
  },
  '/api/log-sources/s1/rollouts': [],
  '/api/parser-rollouts': [],
  '/api/log-sources/rollouts': [],
  '/api/license': { valid: true },
  '/api/log-sources/s1/versions': [],
  '/api/log-sources/s1/samples': { log_source_id: 's1', publication_id: null, version_id: 3, version_number: 3, samples: SAMPLES, updated_at: now, max_samples: 20, max_sample_bytes: 65536 },
  '/api/log-sources/s1/pipe-inputs': { log_source_id: 's1', source_slugs: ['edge-firewall'], push: [], pull: [], connectors: [], mixed_processes: false },
  '/api/log-sources/pipe-inputs': { sources: [] },
};
const missing = new Set();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1600, height: 960, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error.stack ?? error.message).slice(0, 700)));
  page.on('dialog', (dialog) => void dialog.accept());
  await page.setRequestInterception(true);
  page.on('request', async (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) { await request.abort(); return; }
    if (!url.pathname.startsWith('/api/')) { await request.continue(); return; }
    let body = responses[url.pathname];
    if (url.pathname === '/api/log-sources/s1/pipe-preview') {
      const req = JSON.parse(request.postData() ?? '{}');
      body = {
        draft_revision: req.draft_revision, draft_hash: 'h', engine: 'vector-vrl', warnings: [],
        results: (req.events ?? []).map((input, index) => index === 1
          ? { index, input, disposition: 'error', error: 'function call error for "upcase" at (12:21): expected string, got null', steps: [{ step_id: 'p', output: {}, bypassed: false }, { step_id: 'v', error: 'function call error for "upcase" at (12:21): expected string, got null', bypassed: false }] }
          : { index, input, output: { ...JSON.parse(String(input.message ?? input)), severity: 'HIGH' }, disposition: index === 2 ? 'filtered' : 'retained', steps: req.steps.map((s) => ({ step_id: s.id, output: {}, bypassed: false })) }),
      };
    }
    if (url.pathname === '/api/melod/parser/edit') { jobs += 1; body = { job_id: `j${jobs}`, status: 'running' }; }
    const jobMatch = url.pathname.match(/^\/api\/melod\/jobs\/(j\d+)/);
    if (jobMatch) {
      await sleep(700);
      body = { job_id: jobMatch[1], status: 'completed', result: editResult };
    }
    if (body === undefined) { missing.add(`${request.method()} ${url.pathname}`); await request.respond({ status: 404, contentType: 'application/json', body: '{"message":"no fixture"}' }); return; }
    await request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  const shots = [];
  for (const theme of ['dark', 'light']) {
    await page.evaluateOnNewDocument((value) => {
      localStorage.setItem('nanosiem-theme', value);
      localStorage.setItem('nano-pivt-open', '0');
      localStorage.setItem('nano-pivt-mode', 'dock');
      localStorage.setItem('nano-pivt-dock-width', '440');
    }, theme);
    await page.goto(`${origin}/t/${tenant.slug}/ingestion/pipelines/s1`, { waitUntil: 'networkidle2' });
    await page.evaluate((value) => { document.documentElement.classList.toggle('dark', value === 'dark'); document.documentElement.style.colorScheme = value; }, theme);
    const shot = async (name) => { await page.evaluate(() => document.fonts.ready); await sleep(400); const p = `${output}${name}-${theme}.png`; await page.screenshot({ path: p }); shots.push(p); };
    const clickText = (selector, text) => page.evaluate((sel, t) => {
      const el = [...document.querySelectorAll(sel)].find((b) => b.textContent.trim() === t || b.textContent.trim().includes(t));
      el?.click();
      return !!el;
    }, selector, text);
    try {
      await page.waitForFunction(() => document.body.textContent.includes('Tag severity'), { timeout: 30000 });
    } catch (error) {
      await page.screenshot({ path: `${output}debug-load.png` });
      console.log(JSON.stringify({ missing: [...missing], errors, text: (await page.evaluate(() => document.body.innerText)).slice(0, 600) }, null, 2));
      throw error;
    }
    // Select the step and run the draft preview so the error is on screen.
    await page.evaluate(() => {
      const el = [...document.querySelectorAll('span, div, button')].find((x) => x.textContent.trim() === 'Tag severity');
      el?.click();
    });
    await page.evaluate(() => {
      const select = [...document.querySelectorAll('select')].find((x) => [...x.options].some((o) => o.textContent.includes('Saved source samples')));
      if (!select) return;
      const option = [...select.options].find((o) => o.textContent.includes('Saved source samples'));
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
      setter.call(select, option.value);
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await sleep(300);
    await clickText('button', 'Run preview');
    await sleep(1000);
    if (process.env.DEBUG) await shot('00-debug');
    // 1. The editor's pivt button opens the panel with @pipe ready; the Here card names the step.
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === 'pivt' && x.parentElement?.hasAttribute('title'));
      b?.click();
    });
    await page.waitForSelector('textarea[aria-label="Message pivt"]', { timeout: 15000 });
    await shot('01-pivt-button-opens-panel');
    // 2. Here card suggestion: fix the preview error → proposal diff card.
    await page.evaluate(() => { const ta = document.querySelector('textarea[aria-label="Message pivt"]'); if (ta) ta.blur(); });
    const fixed = await clickText('button', 'Fix the preview error in this pipeline step');
    if (!fixed) { await page.click('textarea[aria-label="Message pivt"]'); await page.keyboard.type('fix the preview error'); await page.keyboard.press('Enter'); }
    await page.waitForFunction(() => document.body.textContent.includes('Apply to step'), { timeout: 20000 });
    await page.evaluate(() => {
      const cards = [...document.querySelectorAll('[data-testid="pivt-run-card"]')];
      cards[0]?.scrollIntoView({ block: 'start' });
    });
    await shot('02-proposal-diff-card');
    // 3. Apply: the step's VRL in the editor changes, unsaved.
    await clickText('button', 'Apply to step');
    await page.waitForFunction(() => document.body.textContent.includes('In the draft, unsaved'), { timeout: 10000 });
    await page.evaluate(() => {
      const cards = [...document.querySelectorAll('[data-testid="pivt-run-card"]')];
      cards[cards.length - 1]?.scrollIntoView({ block: 'end' });
    });
    await shot('03-applied-unsaved');
  }
  console.log(JSON.stringify({ shots, errors, missing: [...missing] }, null, 2));
} finally {
  await browser.close();
}
