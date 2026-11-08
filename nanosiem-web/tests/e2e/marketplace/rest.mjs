// SPDX-License-Identifier: AGPL-3.0-or-later
// Cloud pull deep link, repository editor, threat-intel provider, Create / Connect editor.
import { launch, login, SHOTS, sleep, check, clickText, waitText } from './lib.mjs';
const [base, label] = process.argv.slice(2);
const edition = label;
const browser = await launch();
const page = await browser.newPage();
page.on('pageerror', e => console.log('PAGEERROR', e.message));
await page.setViewport({ width: 1440, height: 1000 });
await login(page, base, process.env.NANO_ADMIN_EMAIL, process.env.NANO_ADMIN_PASSWORD);

// 1. Cloud pull card deep-links into Log Sources → Cloud pull.
await page.goto(`${base}/marketplace?category=pull`, { waitUntil: 'networkidle2' });
await page.waitForSelector('[data-mp-slug="cloud-pull"]', { timeout: 30000 });
await page.click('[data-mp-slug="cloud-pull"]');
await page.waitForFunction(() => location.pathname === '/ingestion/log-sources/cloud-pull', { timeout: 10000 });
await page.waitForSelector('[data-testid="cloud-pull-page"]', { timeout: 15000 });
await sleep(800);
await page.screenshot({ path: `${SHOTS}/${label}-cloud-pull-deeplink-1440.png` });
check(true, 'cloud pull card → /ingestion/log-sources/cloud-pull');

// 2. First-party catalogs only (NAN-4946): the sources menu lists nano's
// catalogs with sync now; there is no way to add or edit a repository, and
// the API refuses a third-party URL.
await page.goto(`${base}/marketplace`, { waitUntil: 'networkidle2' });
await page.waitForSelector('[aria-controls="marketplace-repository-sources"]');
await page.click('[aria-controls="marketplace-repository-sources"]');
await page.waitForSelector('#marketplace-repository-sources');
await sleep(400);
const menu = await page.$eval('#marketplace-repository-sources', el => el.textContent.replace(/\s+/g, ' '));
console.log('sources menu:', menu.slice(0, 200));
check(/official/.test(menu) && !/manage repositories/i.test(menu), 'sources menu: official catalogs, no add/manage affordance');
await page.screenshot({ path: `${SHOTS}/${label}-sources-menu-1440.png` });
await clickText(page, '#marketplace-repository-sources button', 'Sync nano Enrichments');
await page.waitForFunction(() => /synced|syncing/.test(document.querySelector('#marketplace-repository-sources')?.textContent ?? ''), { timeout: 20000 });
check(true, 'sync now on a first-party catalog');
const refused = await (async () => {
  const r = await fetch(`${process.env.NANOSIEM_API_URL}/api/marketplace/repos`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': process.env.NANOSIEM_API_KEY },
    body: JSON.stringify({ name: 'Acme community', url: 'https://github.com/octocat/Hello-World', branch: 'master', enrichments_path: '.' }) });
  return { status: r.status, body: (await r.text()).slice(0, 200) };
})();
console.log('third-party create:', refused.status, refused.body);
check(refused.status === 422 && /first-party/.test(refused.body), 'API refuses a third-party repository');
await page.keyboard.press('Escape');
await sleep(400);

// 3. Create / Connect editor modes.
await page.goto(`${base}/marketplace?author=new`, { waitUntil: 'networkidle2' });
await page.waitForFunction(() => document.body.innerText.includes('Create / Connect'), { timeout: 15000 });
await sleep(1500);
const modes = await page.$$eval('[aria-pressed]', els => els.map(e => e.textContent.trim()));
console.log('editor modes:', modes.join(' | '));
await page.screenshot({ path: `${SHOTS}/${label}-create-connect-1440.png` });
if (edition === 'ent') check(modes.includes('TI / Asset provider'), 'enterprise offers provider authoring');
else check(!modes.includes('TI / Asset provider'), 'open edition hides provider authoring (no dead button)');

// 4. Threat-intel provider (enterprise only).
await page.goto(`${base}/marketplace?category=agent`, { waitUntil: 'networkidle2' });
await sleep(2000);
const ti = await page.$('[data-ti-provider="abuseipdb"]');
if (edition === 'ent') {
  check(!!ti, 'threat-intel providers section renders in the Agent filter');
  await ti.click();
  await page.waitForSelector('#ti-cred-API_KEY', { timeout: 10000 });
  await page.type('#ti-cred-API_KEY', 'mock-ti-key');
  await page.screenshot({ path: `${SHOTS}/${label}-ti-provider-1440.png` });
  await clickText(page, '[role="dialog"] button', 'Install');
  await page.waitForFunction(() => !document.querySelector('#ti-cred-API_KEY'), { timeout: 15000 }).catch(() => {});
  await sleep(1500);
  const card = await page.$eval('[data-ti-provider="abuseipdb"]', el => el.textContent.replace(/\s+/g, ' '));
  console.log('ti card:', card);
  check(!/not installed/i.test(card), 'threat-intel provider installed');
} else {
  check(!ti, 'open edition: no threat-intel providers');
}
await page.screenshot({ path: `${SHOTS}/${label}-agent-filter-1440.png`, fullPage: true });
await browser.close();
