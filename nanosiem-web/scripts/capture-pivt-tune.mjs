// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4590 review-only: the real pivt panel tuning a rule and drafting triage
// hints inline next to the real rule editor, with synthetic API responses
// (meloD jobs included), no live IO. Start
// `npx vite --host 127.0.0.1 --port 5187`, then run this with node.
// Screenshots land in docs-internal/reviews/NAN-4590/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5187';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4590/', import.meta.url));
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
const RULE_ID = 'd0000000-0000-4000-8000-000000000007';
const QUERY = 'process_name="powershell.exe"\n  command_line=/.*(DownloadString|DownloadFile|Invoke-WebRequest).*/';
const TUNED = `${QUERY}\n  NOT src_host IN ("sccm-dp-01", "sccm-dp-02")`;
const rule = {
  id: RULE_ID, name: 'powershell_download_cradle', description: 'PowerShell download cradle (T1059.001)', query: QUERY,
  severity: 'high', mode: 'alerting', detection_mode: 'scheduled', schedule_cron: '* * * * *', lookback_minutes: 5,
  mitre_tactics: ['execution'], mitre_techniques: ['T1059.001'], tags: ['windows'], folder: 'Windows',
  created_at: '2026-10-01T10:00:00Z', updated_at: '2026-10-24T10:00:00Z', match_count: 412,
  ai_triage_hints: { ignore_when: [], suspicious_when: [] },
};
const alerts = [
  { id: 'a1', rule_id: RULE_ID, rule_name: rule.name, severity: 'high', status: 'closed', disposition: 'false_positive', matched_events: [{ src_host: 'sccm-dp-01' }], created_at: '2026-10-25T02:10:00Z' },
  { id: 'a2', rule_id: RULE_ID, rule_name: rule.name, severity: 'high', status: 'closed', disposition: 'false_positive', matched_events: [{ src_host: 'sccm-dp-02' }], created_at: '2026-10-25T02:12:00Z' },
  { id: 'a3', rule_id: RULE_ID, rule_name: rule.name, severity: 'high', status: 'new', matched_events: [{ src_host: 'FIN-LT-0388' }], created_at: '2026-10-26T11:02:00Z' },
];
const tuned = {
  session_id: 's1', message: '',
  detection: {
    name: rule.name, description: rule.description, query: QUERY, severity: 'high', mitre_tactics: [], mitre_techniques: [],
    historical_analysis: { total_matches: 412, days_analyzed: 30, daily_average: 13.7 },
    noise_assessment: { level: 'high', daily_average: 13.7, peak_daily_matches: 40, estimated_daily_alerts: 13, alert_fatigue_risk: 'high', explanation: 'Most matches come from the two SCCM distribution points during the Tuesday patch window.', threshold_suggestions: [] },
    tuning_suggestions: [
      { issue: 'SCCM distribution points trigger this nightly', suggestion: 'Exclude sccm-dp-01 and sccm-dp-02; they pull packages with Invoke-WebRequest by design.', modified_query: TUNED },
      { issue: 'Matches cluster in the patch window', suggestion: 'If exclusions are not enough, suppress Tuesdays 01:00–04:00 UTC with a schedule exclusion.' },
    ],
  },
};
const hints = {
  session_id: 's2',
  message: JSON.stringify({
    ignore_when: ['Parent process is the SCCM client (CcmExec.exe)', 'Destination is an internal package mirror'],
    suspicious_when: ['Download target is a raw IP or a newly registered domain', 'User is not in an IT admin group', 'Followed by a child process from %TEMP%'],
    context: 'Download cradles are common in commodity loaders and red-team tooling; SCCM and Intune scripts are the usual false positives.',
  }),
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
  '/api/melod/settings/ai-tuning': { ai_tuning_mode: 'on' },
  '/api/rules': [rule],
  [`/api/rules/${RULE_ID}`]: rule,
  [`/api/rules/${RULE_ID}/versions`]: [],
  [`/api/rules/${RULE_ID}/matches`]: { total: 412, matches: Array.from({ length: 20 }, (_, i) => ({ id: `m${i}`, event_count: 1 })) },
  '/api/rules/stats': {},
  '/api/folder-settings': { icons: {} },
  '/api/mitre': { tactics: [], techniques: [] },
  '/api/rules/validate': { valid: true, errors: [], effective_mode: 'scheduled', creates_materialized_view: false, mode_reason: '', realtime_eligible: false, referenced_fields: [] },
  '/api/alerts': alerts,
};
let jobs = { jt: { state: 'running', progress: 'Replaying 30 days of matches' }, jc: { state: 'running', progress: 'Drafting conditions' } };
const results = { jt: tuned, jc: hints };
const jobBody = (id) => (jobs[id].state === 'running' ? { job_id: id, status: 'running', progress: jobs[id].progress } : { job_id: id, status: 'completed', result: results[id] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 940, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  // The applied tune leaves the editor dirty; accept its leave-page guard.
  page.on('dialog', (dialog) => void dialog.accept());
  await page.setRequestInterception(true);
  page.on('request', async (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) { await request.abort(); return; }
    if (!url.pathname.startsWith('/api/')) { await request.continue(); return; }
    let body = responses[url.pathname];
    if (url.pathname === '/api/melod/detection/tune') body = { job_id: 'jt', status: 'pending' };
    if (url.pathname === '/api/melod/chat') body = { job_id: 'jc', status: 'pending' };
    const job = url.pathname.match(/^\/api\/melod\/jobs\/(\w+)$/);
    if (job) body = jobBody(job[1]);
    if (body === undefined) { await request.respond({ status: 404, contentType: 'application/json', body: '{"message":"no fixture"}' }); return; }
    await request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  const shots = [];
  for (const theme of ['dark', 'light']) {
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

    // 1. Rule editor → Rule actions → AI tune rule: pivt tunes in the panel.
    jobs.jt = { state: 'running', progress: 'Replaying 30 days of matches' };
    await load(`/rules/editor/${RULE_ID}`);
    await page.waitForFunction(() => document.body.textContent.includes('DownloadString'));
    await page.click('button[aria-label="Rule actions"]');
    await page.waitForSelector('[role="menuitem"]');
    if (!(await clickText('[role="menuitem"]', 'AI tune rule'))) throw new Error('no AI tune rule menu item');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="running"]');
    await sleep(2600); // one poll → progress stage
    await shot('01-pivt-tuning');

    // 2. Suggestions as cards with a query diff.
    jobs.jt = { state: 'done' };
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="done"]', { timeout: 10000 });
    await page.evaluate(() => document.querySelector('[data-testid="pivt-run-card"]')?.scrollIntoView({ block: 'start' }));
    await shot('02-pivt-tune-suggestions');

    // 3. Apply → the editor buffer has the exclusion, unsaved.
    await clickText('[data-testid="pivt-run-card"] button', 'Apply to editor');
    await page.waitForSelector('[data-testid="pivt-run-card"][data-state="applied"]');
    await shot('03-pivt-tune-applied');

    // 4. Inspector → Generate with pivt → hints card → Use hints.
    jobs.jc = { state: 'done' };
    await load(`/rules/editor/${RULE_ID}`);
    await page.waitForFunction(() => document.body.textContent.includes('DownloadString'));
    await page.click('button[aria-label="Expand inspector"]');
    await page.waitForFunction(() => [...document.querySelectorAll('button')].some((b) => b.textContent.includes('Generate with pivt')));
    await clickText('button', 'Generate with pivt');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="done"]', { timeout: 10000 });
    await shot('04-pivt-triage-hints');
    await clickText('[data-testid="pivt-run-card"] button', 'Use hints');
    await page.waitForSelector('[data-testid="pivt-run-card"][data-state="applied"]');
    await shot('05-pivt-triage-hints-applied');
  }
  if (errors.length) throw new Error('Browser errors: ' + [...new Set(errors)].join('; '));
  console.log(shots.join('\n'));
} finally { await browser.close(); }
