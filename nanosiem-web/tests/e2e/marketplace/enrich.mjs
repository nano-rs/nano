// SPDX-License-Identifier: AGPL-3.0-or-later
// Enrichment card: install with credentials, inventory drawer, disable/enable, configure, uninstall.
import { launch, login, SHOTS, sleep, check, clickText, waitText } from './lib.mjs';
const [base, label, slug = 'abuseipdb'] = process.argv.slice(2);
const browser = await launch();
const page = await browser.newPage();
page.on('pageerror', e => console.log('PAGEERROR', e.message));
await page.setViewport({ width: 1440, height: 1000 });
await login(page, base, process.env.NANO_ADMIN_EMAIL, process.env.NANO_ADMIN_PASSWORD);
await page.goto(`${base}/marketplace`, { waitUntil: 'networkidle2' });
await page.waitForSelector(`[data-mp-slug="${slug}"]`, { timeout: 30000 });
await page.click(`[data-mp-slug="${slug}"]`);
await page.waitForSelector('[data-testid="inventory-details"]');
check(page.url().includes(`item=${slug}`), 'card opens inventory drawer at ?item=');
await page.screenshot({ path: `${SHOTS}/${label}-${slug}-drawer-before-1440.png` });
await clickText(page, 'button', 'Install');
await page.waitForSelector('input#API_KEY', { timeout: 10000 });
await page.type('input#API_KEY', 'mock-abuseipdb-key-0001');
await page.screenshot({ path: `${SHOTS}/${label}-${slug}-install-dialog-1440.png` });
await clickText(page, '[role="dialog"] button', 'Install');
await page.waitForFunction(s => document.querySelector(`[data-mp-slug="${s}"]`)?.textContent.includes('Disable'), { timeout: 20000 }, slug);
check(true, 'install with credentials → card footer Disable');
// Inventory drawer reflects installed state
await page.goto(`${base}/marketplace?item=${slug}`, { waitUntil: 'networkidle2' });
await page.waitForSelector('[data-testid="inventory-details"]');
await waitText(page, 'healthy');
await page.screenshot({ path: `${SHOTS}/${label}-${slug}-drawer-installed-1440.png` });
// Disable via confirm
await clickText(page, '[role="dialog"] button', 'Disable');
await page.waitForSelector('[role="alertdialog"]', { timeout: 10000 });
await sleep(500);
await clickText(page, '[role="alertdialog"] button', 'Disable');
await page.waitForFunction(() => [...document.querySelectorAll('[role="dialog"] button')].some(b => b.textContent.trim() === 'Enable'), { timeout: 20000 });
check(true, 'disable → drawer offers Enable');
await clickText(page, '[role="dialog"] button', 'Enable');
await page.waitForSelector('[role="alertdialog"]');
await sleep(500);
await clickText(page, '[role="alertdialog"] button', 'Enable');
await page.waitForFunction(() => [...document.querySelectorAll('[role="dialog"] button')].some(b => b.textContent.trim() === 'Disable'), { timeout: 20000 });
check(true, 're-enable');
// Configure opens the full config drawer
await clickText(page, '[role="dialog"] button', 'Configure');
await page.waitForFunction(() => location.search.includes('author=connect'), { timeout: 10000 });
await sleep(1500);
await page.screenshot({ path: `${SHOTS}/${label}-${slug}-configure-1440.png` });
check(true, 'Configure opens connection/config drawer');
await page.keyboard.press('Escape');
await sleep(800);
// Enabled-only filter shows it
await page.goto(`${base}/marketplace?installed=true`, { waitUntil: 'networkidle2' });
await page.waitForSelector('[data-mp-card]');
const enabled = await page.$$eval('[data-mp-card]', els => els.map(e => e.getAttribute('data-mp-slug')));
console.log('enabled only:', enabled.join(' '));
check(enabled.includes(slug), 'enabled-only lists the installed item');
// Uninstall
await page.goto(`${base}/marketplace?item=${slug}`, { waitUntil: 'networkidle2' });
await page.waitForSelector('[data-testid="inventory-details"]');
await clickText(page, '[role="dialog"] button', 'Uninstall');
await page.waitForSelector('[role="alertdialog"]');
await sleep(500);
await clickText(page, '[role="alertdialog"] button', 'Uninstall');
await page.waitForFunction(() => [...document.querySelectorAll('[role="dialog"] button')].some(b => b.textContent.trim() === 'Install'), { timeout: 20000 });
check(true, 'uninstall → back to Install');
await browser.close();
