// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4608 review-only: the real pivt panel writing a custom integration
// collector next to the real CustomIntegrationWizard (Generate in pivt →
// candidate card → Use in editor), with synthetic API responses, no live IO. Start
// `npx vite --host 127.0.0.1 --port 5187`, then run this with node.
// Screenshots land in docs-internal/reviews/NAN-4608/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5187';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4608/', import.meta.url));
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
const result = {
  code: `// Acme audit collector: Link-header pagination, cursor per stream
export async function collect(ctx: CollectorContext): Promise<void> {
  let url = ctx.cursor('events') ?? 'https://api.acme.example/v1/audit?limit=500';
  while (url && !ctx.shouldStop()) {
    const res = await ctx.fetch(url, { headers: { Accept: 'application/json' } });
    if (res.status === 429) return ctx.backoff(Number(res.headers.get('retry-after') ?? 30));
    const page = await res.json();
    await ctx.emit('events', page.events);
    url = nextLink(res.headers.get('link'));
    if (url) await ctx.checkpoint('events', url);
  }
}

function nextLink(header: string | null): string | null {
  const m = header?.match(/<([^>]+)>;\\s*rel="next"/);
  return m ? m[1] : null;
}
`,
  explanation: 'Follows the Link header page by page, emits each page to the events stream and checkpoints the next URL; backs off on 429.',
  warnings: ['The sample response has no stable event id, so the cursor is the next-page URL.'],
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
  '/api/credentials': [],
};
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
    if (url.pathname === '/api/integrations/custom/generate-code') {
      generateCalls += 1;
      await sleep(900);
      body = result;
    }
    if (false) {
      const n = Number(jobMatch[1]);
      body = job.state === 'running'
        ? { job_id: `jd${n}`, status: 'running', progress: job.progress }
        : { job_id: `jd${n}`, status: 'completed', result: n % 2 === 1 ? questions : { session_id: 'sess-1', message: '', is_complete: true, dashboard } };
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

    const typeInto = async (selector, text) => {
      await page.click(selector);
      await page.keyboard.type(text, { delay: 0 });
    };
    const cmIn = async (placeholderPart, text) => {
      const ok = await page.evaluate((part) => {
        const el = [...document.querySelectorAll('.cm-content')].find((c) =>
          (c.closest('.cm-editor')?.querySelector('.cm-placeholder')?.textContent ?? '').includes(part));
        if (!el) return false;
        el.focus();
        return true;
      }, placeholderPart);
      if (!ok) throw new Error('no editor for ' + placeholderPart);
      await page.keyboard.type(text, { delay: 0 });
    };

    // 1. Code step: the pivt builder inputs and "Generate in pivt".
    await load('/integrations/custom/new');
    await page.waitForSelector('input[placeholder="Acme audit events"]');
    await typeInto('input[placeholder="Acme audit events"]', 'Acme audit events');
    await clickText('button', 'Continue');
    await page.waitForSelector('textarea[placeholder="api.example.com"]');
    await typeInto('textarea[placeholder="api.example.com"]', 'api.acme.example');
    await clickText('button', 'Continue');
    await sleep(200);
    await clickText('button', 'Continue');
    await page.waitForFunction(() => document.body.textContent.includes('Collector code'));
    await typeInto('textarea[placeholder^="Collect GitHub public events"]', 'Collect Acme audit events from /v1/audit. Follow the Link header, emit each page, checkpoint the next URL, back off on 429.');
    await cmIn('curl -H', 'curl -H "Authorization: Bearer $TOKEN" https://api.acme.example/v1/audit?limit=500');
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button')].find((x) => x.textContent.includes('Generate in pivt'));
      b?.scrollIntoView({ block: 'center' });
    });
    await shot('01-code-step-generate-in-pivt');

    // 2. Run in the panel → candidate card with warnings, Use in editor / Dismiss.
    await clickText('button', 'Generate in pivt');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="done"]', { timeout: 15000 });
    await scrollLastCard();
    await shot('02-pivt-collector-candidate-card');

    // 3. Use in editor → Manual code tab holds it, unsaved; validation reset.
    await clickText('[data-testid="pivt-run-card"] button', 'Use in editor');
    await page.waitForSelector('[data-testid="pivt-run-card"][data-state="applied"]', { timeout: 10000 });
    await page.evaluate(() => window.scrollTo(0, 0));
    await sleep(300);
    await shot('03-use-in-editor-manual-code');
  }
  if (errors.length) throw new Error('Browser errors: ' + [...new Set(errors)].join('; '));
  console.log(shots.join('\n'));
} finally { await browser.close(); }
