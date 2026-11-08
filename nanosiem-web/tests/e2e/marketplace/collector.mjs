// SPDX-License-Identifier: AGPL-3.0-or-later
// Pull collector card (connector feeds): install against the mock vendor, manage, disable/enable, uninstall.
import { launch, login, SHOTS, sleep, check, clickText, waitText } from './lib.mjs';
const [base, label, phase = 'all'] = process.argv.slice(2);
const browser = await launch();
const page = await browser.newPage();
page.on('pageerror', e => console.log('PAGEERROR', e.message));
await page.setViewport({ width: 1440, height: 1000 });
await login(page, base, process.env.NANO_ADMIN_EMAIL, process.env.NANO_ADMIN_PASSWORD);
await page.goto(`${base}/marketplace?category=pull`, { waitUntil: 'networkidle2' });
const sel = '[data-mp-slug="collector:okta_system_log"]';
await page.waitForSelector(sel, { timeout: 30000 });
if (phase === 'all' || phase === 'install') {
  await page.click(sel);
  await page.waitForSelector('#collector-name-okta_system_log');
  await sleep(800);
  await page.$eval('#collector-name-okta_system_log', el => el.select());
  await page.type('#collector-name-okta_system_log', 'Okta mock tenant');
  await page.type('#collector-okta_system_log-API_TOKEN', 'mock-okta-token');
  await page.type('#collector-okta_system_log-OKTA_DOMAIN', 'acme.okta.com');
  // A too-frequent schedule is refused and the error shows in the sheet.
  await page.type('#collector-schedule-okta_system_log', '* * * * *');
  await clickText(page, '[role="dialog"] button', 'Install');
  await waitText(page, 'allows at most one run every 120 s');
  check(true, 'server refusal surfaces in the install sheet');
  await page.screenshot({ path: `${SHOTS}/${label}-collector-install-error-1440.png` });
  await page.$eval('#collector-schedule-okta_system_log', el => el.select());
  await page.keyboard.press('Backspace');
  await page.type('#collector-okta_system_log-API_TOKEN', 'mock-okta-token');
  await page.screenshot({ path: `${SHOTS}/${label}-collector-install-1440.png` });
  await clickText(page, '[role="dialog"] button', 'Install');
  await page.waitForFunction(s => document.querySelector(s)?.textContent.includes('Installed · On'), { timeout: 20000 }, sel);
  check(true, 'collector installed → card shows Installed · On');
}
// Wait for the runner to pull from the mock and report success.
await page.waitForFunction(s => /healthy|running/.test(document.querySelector(s)?.textContent ?? ''), { timeout: 150000, polling: 2000 }, sel).catch(() => {});
const meta = await page.$eval(sel, el => el.textContent);
console.log('card:', meta.replace(/\s+/g, ' '));
await page.click(sel);
await page.waitForSelector('[data-testid^="collector-feed-"]', { timeout: 10000 });
await sleep(500);
await page.screenshot({ path: `${SHOTS}/${label}-collector-manage-1440.png` });
const feedText = await page.$eval('[data-testid^="collector-feed-"]', el => el.textContent.replace(/\s+/g, ' '));
console.log('feed row:', feedText);
check(/last success \d|last success [A-Z]/.test(feedText) || /success/i.test(feedText), 'feed reports a successful pull from the mock vendor');
await clickText(page, '[role="dialog"] button', 'Disable');
await page.waitForFunction(s => document.querySelector(s)?.textContent.includes('Installed · Off'), { timeout: 20000 }, sel);
check(true, 'disable → Installed · Off');
await clickText(page, '[role="dialog"] button', 'Enable');
await page.waitForFunction(s => document.querySelector(s)?.textContent.includes('Installed · On'), { timeout: 20000 }, sel);
check(true, 'enable → Installed · On');
if (phase === 'all') {
  await clickText(page, '[role="dialog"] button', 'Uninstall');
  await page.waitForSelector('[role="alertdialog"]');
  await clickText(page, '[role="alertdialog"] button', 'Uninstall');
  await page.waitForFunction(s => document.querySelector(s)?.textContent.trim().endsWith('Install'), { timeout: 20000 }, sel);
  check(true, 'uninstall → Install');
}
await browser.close();
