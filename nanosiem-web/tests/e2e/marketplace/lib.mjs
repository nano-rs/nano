// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4946 Marketplace UI scenarios: shared puppeteer helpers. See README.md.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import puppeteer from 'puppeteer-core';
export const SHOTS = process.env.E2E_SHOTS_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'mp-shots-'));
fs.mkdirSync(SHOTS, { recursive: true });
const CHROME = process.env.CHROME_PATH || ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium'].find(p => fs.existsSync(p));
export async function launch() {
  return puppeteer.launch({ executablePath: CHROME, headless: true, args: ['--no-first-run'] });
}
export const sleep = ms => new Promise(r => setTimeout(r, ms));
export async function login(page, base, email, password) {
  await page.goto(`${base}/login`, { waitUntil: 'networkidle2' });
  await page.waitForSelector('input[autocomplete="email"]', { timeout: 20000 });
  await page.type('input[autocomplete="email"]', email);
  await page.keyboard.press('Enter');
  await page.waitForSelector('input[autocomplete="current-password"]', { timeout: 20000 });
  await page.type('input[autocomplete="current-password"]', password);
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => !location.pathname.startsWith('/login'), { timeout: 30000 });
}
export async function clickText(page, selector, text, opts = {}) {
  // Last visible match wins: overlays render after the page content.
  await page.waitForFunction((sel, t) => [...document.querySelectorAll(sel)].some(el => (el.textContent.trim() === t || el.getAttribute('aria-label') === t) && el.offsetParent !== null && !el.disabled), { timeout: opts.timeout ?? 15000 }, selector, text);
  await page.evaluate((sel, t) => { const all = [...document.querySelectorAll(sel)].filter(el => (el.textContent.trim() === t || el.getAttribute('aria-label') === t) && el.offsetParent !== null && !el.disabled); all[all.length - 1].click(); }, selector, text);
}
export async function waitText(page, text, timeout = 20000) {
  await page.waitForFunction(t => document.body.innerText.includes(t), { timeout }, text);
}
export function check(cond, msg) { if (!cond) throw new Error('CHECK FAILED: ' + msg); console.log('  ok', msg); }
