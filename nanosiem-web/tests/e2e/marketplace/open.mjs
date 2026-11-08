// SPDX-License-Identifier: AGPL-3.0-or-later
// Open edition: enterprise-only cards are present but stubbed with an
// entitlement panel (never a dead Install button); no threat-intel section,
// no custom-provider authoring; open cards (native feeds, pull collectors,
// cloud pull) keep working.
import { launch, login, SHOTS, sleep, check, clickText } from './lib.mjs';
const [base, label = 'open'] = process.argv.slice(2);
const browser = await launch();
const page = await browser.newPage();
page.on('pageerror', e => console.log('PAGEERROR', e.message));
await page.setViewport({ width: 1440, height: 1000 });
await login(page, base, process.env.NANO_ADMIN_EMAIL, process.env.NANO_ADMIN_PASSWORD);
await page.goto(`${base}/marketplace`, { waitUntil: 'networkidle2' });
await page.waitForSelector('[data-mp-card]', { timeout: 30000 });
await sleep(1500);
for (const w of [1440, 2560]) {
  await page.setViewport({ width: w, height: w === 1440 ? 1000 : 1400 });
  await sleep(600);
  await page.screenshot({ path: `${SHOTS}/${label}-marketplace-${w}.png`, fullPage: true });
}
await page.setViewport({ width: 1440, height: 1000 });
const footer = await page.$eval('[data-mp-slug="abuseipdb"]', el => el.textContent);
check(/Enterprise edition/.test(footer), 'enterprise-backed card footer names the edition, not Install');
check(!(await page.$('[data-ti-provider]')), 'no threat-intel providers in the open edition');
await page.click('[data-mp-slug="abuseipdb"]');
await page.waitForSelector('section[aria-label="Entitlement"]', { timeout: 10000 });
await sleep(800);
const buttons = await page.$$eval('[role="dialog"] button', els => els.map(e => e.textContent.trim()));
console.log('drawer buttons:', buttons.join(' | '));
check(!buttons.includes('Install'), 'no Install action for an enterprise-only integration');
await page.screenshot({ path: `${SHOTS}/${label}-entitlement-1440.png` });
await page.keyboard.press('Escape');
// IPinfo Lite (bundle-only, NAN-4959).
await page.goto(`${base}/marketplace?item=ipinfo_lite`, { waitUntil: 'networkidle2' });
await page.waitForSelector('[data-testid="inventory-details"]');
const native = await page.$$eval('[role="dialog"] button', els => els.map(e => e.textContent.trim()));
console.log('ipinfo buttons:', native.join(' | '));
const bundleNote = await page.$('[data-testid="inventory-bundle-note"]');
// NAN-4959: IPinfo Lite is bundle-only: no toggle, configure or uninstall.
check(Boolean(bundleNote) && !native.includes('Feed bundle') && !native.includes('Uninstall') && !native.includes('Configure'),
  'bundle-only IPinfo Lite: no toggle / configure / uninstall, managed under Platform feeds');
// Create / Connect has no provider authoring.
await page.goto(`${base}/marketplace?author=new`, { waitUntil: 'networkidle2' });
await sleep(1500);
const modes = await page.$$eval('[aria-pressed]', els => els.map(e => e.textContent.trim()));
console.log('editor modes:', modes.join(' | '));
check(!modes.includes('TI / Asset provider') && !modes.includes('Marketplace repository'), 'open editor: lookups only (no provider authoring, no repositories)');
await page.screenshot({ path: `${SHOTS}/${label}-create-connect-1440.png` });
await browser.close();
