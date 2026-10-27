// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4595 review-only: the real pivt panel drafting detection rules inline
// next to the real Rules list and rule editor, with synthetic API responses
// (meloD job included), no live IO. Start
// `npx vite --host 127.0.0.1 --port 5187`, then run this with node.
// Screenshots land in docs-internal/reviews/NAN-4595/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5187';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4595/', import.meta.url));
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
const NARRATIVE = 'create a detection for kerberoasting from non-service accounts, especially RC4 TGS requests';
const candidates = [
  { name: 'kerberoast_rc4_tgs_requests', description: 'RC4-encrypted TGS requests for service accounts from a user that is not itself a service account.', query: 'event_id=4769 ticket_encryption_type="0x17"\n  NOT user=/^svc_/ NOT service_name="krbtgt"', severity: 'high', mitre_tactics: ['credential-access'], mitre_techniques: ['T1558.003'] },
  { name: 'kerberoast_tgs_burst_per_user', description: 'One user requests tickets for more than 10 distinct services in 10 minutes.', query: 'event_id=4769 NOT user=/^svc_/\n  | stats dc(service_name) as services by user, src_ip\n  | where services > 10', severity: 'medium', mitre_tactics: ['credential-access'], mitre_techniques: ['T1558.003'] },
  { name: 'kerberoast_honey_spn_request', description: 'Any ticket request for the honey SPN svc_honey_sql.', query: 'event_id=4769 service_name="svc_honey_sql"', severity: 'critical', mitre_tactics: ['credential-access'], mitre_techniques: ['T1558.003'] },
];
const ruleOf = (id, c, mode = 'staging') => ({
  id, name: c.name, description: c.description, query: c.query, severity: c.severity, mode, detection_mode: 'scheduled', schedule_cron: '* * * * *',
  mitre_tactics: c.mitre_tactics, mitre_techniques: c.mitre_techniques, tags: [], created_at: '2026-10-26T14:00:00Z', updated_at: '2026-10-26T14:00:00Z', match_count: 0,
});
const existing = [
  ruleOf('d0000000-0000-4000-8000-000000000001', { name: 'powershell_download_cradle', description: '', query: 'process_name="powershell.exe"', severity: 'high', mitre_tactics: ['execution'], mitre_techniques: ['T1059.001'] }, 'alerting'),
  ruleOf('d0000000-0000-4000-8000-000000000002', { name: 'lsass_memory_access', description: '', query: 'event_id=10 target_image="*lsass.exe"', severity: 'critical', mitre_tactics: ['credential-access'], mitre_techniques: ['T1003.001'] }, 'alerting'),
];
let rules = [...existing];
let created = 0;
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
  '/api/rules/stats': {},
  '/api/folder-settings': { icons: {} },
  '/api/mitre': { tactics: [], techniques: [] },
  '/api/rules/validate': { valid: true, errors: [], effective_mode: 'scheduled', creates_materialized_view: false, mode_reason: '', realtime_eligible: false, referenced_fields: [] },
};
let job = { state: 'running', progress: 'Validating candidate queries against your schema' };
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
    if (url.pathname === '/api/rules' && request.method() === 'POST') {
      const req = JSON.parse(request.postData() ?? '{}');
      created += 1;
      const rule = ruleOf(`e0000000-0000-4000-8000-00000000000${created}`, req);
      rules = [...rules, rule];
      body = rule;
    } else if (url.pathname === '/api/rules') {
      body = rules;
    }
    if (url.pathname === '/api/melod/detection') body = { job_id: 'jd', status: 'pending' };
    if (url.pathname === '/api/melod/jobs/jd') {
      body = job.state === 'running'
        ? { job_id: 'jd', status: 'running', progress: job.progress }
        : { job_id: 'jd', status: 'completed', result: { session_id: 's', message: '', detections: candidates } };
    }
    if (body === undefined) { await request.respond({ status: 404, contentType: 'application/json', body: '{"message":"no fixture"}' }); return; }
    await request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  const shots = [];
  for (const theme of ['dark', 'light']) {
    rules = [...existing];
    created = 0;
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
      const el = [...document.querySelectorAll(sel)].find((b) => b.textContent.trim().includes(t));
      el?.click();
      return !!el;
    }, selector, text);

    // 1. Rules → Draft with pivt: pivt focused with @detection.
    await load('/rules');
    await page.waitForFunction(() => document.body.textContent.includes('powershell_download_cradle'));
    if (!(await clickText('button', 'Draft with pivt'))) throw new Error('no Draft with pivt button');
    await page.waitForFunction(() => document.activeElement?.getAttribute('aria-label') === 'Message pivt' && document.activeElement.value === '@detection ');
    await shot('01-rules-draft-with-pivt');

    // 2. Free-text narrative drafting in the panel.
    job = { state: 'running', progress: 'Validating candidate queries against your schema' };
    await page.evaluate(() => { const el = document.activeElement; el.select?.(); });
    await page.keyboard.press('Backspace');
    await page.keyboard.type(NARRATIVE);
    await page.keyboard.press('Enter');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="running"]');
    await sleep(2600);
    await shot('02-pivt-drafting-detections');

    // 3. Candidates as cards.
    job = { state: 'done' };
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="done"]', { timeout: 10000 });
    await page.evaluate(() => document.querySelector('[data-testid="pivt-run-card"]')?.scrollIntoView({ block: 'start' }));
    await shot('03-pivt-detection-candidates');

    // 4. Open the first in the new-rule editor (unsaved).
    await clickText('[data-testid="pivt-run-card"] button', 'Open in editor');
    await page.waitForFunction(() => location.pathname.endsWith('/rules/editor/new') && document.body.textContent.includes('kerberoast_rc4_tgs_requests'));
    await sleep(600);
    await shot('04-pivt-candidate-opened-in-editor');

    // 5. Create the remaining 2 in staging → filtered rule list.
    await clickText('[data-testid="pivt-run-card"] button', 'Create 2');
    await page.waitForFunction(() => location.pathname.endsWith('/rules') && location.search.includes('ids='), { timeout: 10000 });
    await page.waitForFunction(() => document.body.textContent.includes('kerberoast_honey_spn_request'));
    await sleep(600);
    await shot('05-pivt-created-filtered-list');
  }
  if (errors.length) throw new Error('Browser errors: ' + [...new Set(errors)].join('; '));
  console.log(shots.join('\n'));
} finally { await browser.close(); }
