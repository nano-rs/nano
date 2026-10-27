// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4603 review-only: the real pivt panel writing custom enrichment code
// next to the real CustomEnrichmentWizard (Generate in pivt → code card →
// Use in form), with synthetic API responses, no live IO. Start
// `npx vite --host 127.0.0.1 --port 5187`, then run this with node.
// Screenshots land in docs-internal/reviews/NAN-4603/.
import puppeteer from 'puppeteer-core';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = process.env.ORIGIN ?? 'http://127.0.0.1:5187';
const output = fileURLToPath(new URL('../../docs-internal/reviews/NAN-4603/', import.meta.url));
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
  code: `// IP Intel reputation lookup (agent enrichment, Deno sandbox)
export default async function enrich(ctx: EnrichContext): Promise<EnrichResult> {
  const res = await ctx.fetch(\`https://api.ipintel.example/v1/ip/\${ctx.key}\`, {
    headers: { 'X-API-Key': ctx.secrets.api_key },
  });
  if (!res.ok) return { status: 'error', message: \`IP Intel \${res.status}\` };
  const body = await res.json();
  return {
    status: 'ok',
    fields: {
      ipintel_score: body.score,
      ipintel_categories: body.categories,
      ipintel_last_seen: body.last_seen,
    },
  };
}
`,
  explanation: 'Looks each IP up in IP Intel with the API key header and maps score, categories and last_seen.',
  detected_fields: [
    { name: 'score', description: null, suggested_mapping: 'ipintel_score' },
    { name: 'categories', description: null, suggested_mapping: 'ipintel_categories' },
    { name: 'last_seen', description: null, suggested_mapping: 'ipintel_last_seen' },
  ],
  suggested_domains: ['api.ipintel.example'],
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
  '/api/custom-enrichments/templates': { data: '// data template', agent: '// agent template' },
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
    if (url.pathname === '/api/custom-enrichments/generate-code') {
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

    // 1. Code step: the pivt tab's inputs and "Generate in pivt".
    await load('/enrichments/custom/new');
    await clickText('button', 'Next');
    await page.waitForSelector('input[placeholder="e.g., VirusTotal IP Lookup"]');
    await typeInto('input[placeholder="e.g., VirusTotal IP Lookup"]', 'IP Intel reputation');
    await clickText('button', 'Next');
    await sleep(200);
    await clickText('button', 'Next');
    await page.waitForFunction(() => document.body.textContent.includes('Enrichment Code'));
    await typeInto('textarea[placeholder^="e.g., Fetch IP reputation"]', 'Look up IP reputation in IP Intel: score, categories and last_seen for each IP');
    await cmIn('curl -H', "curl -H 'X-API-Key: $IPINTEL_KEY' https://api.ipintel.example/v1/ip/1.2.3.4");
    await cmIn('"score": 75', '{"ip":"1.2.3.4","score":75,"categories":["c2","scanner"],"last_seen":"2026-10-25T18:02:11Z"}');
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('button')].find((x) => x.textContent.includes('Generate in pivt'));
      b?.scrollIntoView({ block: 'center' });
    });
    await shot('01-code-step-generate-in-pivt');

    // 2. Run in the panel → code card with domains, Use in form / Dismiss.
    await clickText('button', 'Generate in pivt');
    await page.waitForSelector('[data-testid="pivt-draft-run"][data-status="done"]', { timeout: 15000 });
    await scrollLastCard();
    await shot('02-pivt-enrichment-code-card');

    // 3. Use in form → Manual Code tab holds the code, unsaved.
    await clickText('[data-testid="pivt-run-card"] button', 'Use in form');
    await page.waitForSelector('[data-testid="pivt-run-card"][data-state="applied"]', { timeout: 10000 });
    await sleep(300);
    await shot('03-use-in-form-manual-code');
  }
  if (errors.length) throw new Error('Browser errors: ' + [...new Set(errors)].join('; '));
  console.log(shots.join('\n'));
} finally { await browser.close(); }
