// SPDX-License-Identifier: AGPL-3.0-or-later
// Browse + filter + screenshots: node browse.mjs <base> <label>
import { launch, login, SHOTS, sleep, check, waitText } from './lib.mjs';
const [base, label] = process.argv.slice(2);
const browser = await launch();
const page = await browser.newPage();
page.on('pageerror', e => console.log('PAGEERROR', e.message));
await page.setViewport({ width: 1440, height: 1000 });
await login(page, base, process.env.NANO_ADMIN_EMAIL, process.env.NANO_ADMIN_PASSWORD);
await page.goto(`${base}/marketplace`, { waitUntil: 'networkidle2' });
await page.waitForSelector('[data-mp-card]', { timeout: 30000 });
await sleep(1500);
const slugs = await page.$$eval('[data-mp-card]', els => els.map(e => e.getAttribute('data-mp-slug')));
console.log('cards:', slugs.join(' '));
const sections = await page.$$eval('section > div .font-mono.uppercase, section [data-testid]', els => els.map(e => e.textContent.trim()).filter(Boolean));
console.log('sections:', sections.join(' | '));
for (const w of [1440, 2560]) {
  await page.setViewport({ width: w, height: w === 1440 ? 1000 : 1400 });
  await sleep(600);
  await page.screenshot({ path: `${SHOTS}/${label}-marketplace-${w}.png`, fullPage: true });
}
await page.setViewport({ width: 1440, height: 1000 });
// Filter: Pull chip
const chip = await page.$$('button');
for (const b of chip) { const t = await b.evaluate(e => e.textContent.trim()); if (/^Pull\d+$/.test(t)) { await b.click(); break; } }
await sleep(800);
const pull = await page.$$eval('[data-mp-card]', els => els.map(e => e.getAttribute('data-mp-slug')));
console.log('pull filter:', pull.join(' '));
check(pull.length > 0 && pull.every(s => s.startsWith('collector:') || s === 'cloud-pull'), 'Pull chip shows only collectors + cloud pull');
await page.screenshot({ path: `${SHOTS}/${label}-filter-pull-1440.png` });
// Search
await page.goto(`${base}/marketplace`, { waitUntil: 'networkidle2' });
await page.waitForSelector('#marketplace-search');
await page.type('#marketplace-search', 'okta');
await sleep(600);
const okta = await page.$$eval('[data-mp-card]', els => els.map(e => e.getAttribute('data-mp-slug')));
console.log('search okta:', okta.join(' '));
check(okta.length > 0 && okta.every(s => /okta/.test(s)), 'search narrows to okta');
await page.screenshot({ path: `${SHOTS}/${label}-search-okta-1440.png` });
await browser.close();
