#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// nano-e2e UI driver (NAN-4937): drives the real web UI with puppeteer-core
// (the browser dependency the repo already ships, see crawl-404.mjs) on
// behalf of the Python scenario harness (e2e/nano_e2e/ui.py).
//
// Protocol: JSON lines. One request per stdin line
//   {"id": 1, "op": "search", "args": {...}}
// one response per stdout line
//   {"id": 1, "ok": true, "result": ...} | {"id": 1, "ok": false, "error": "..."}
// Each op performs a UI action and reports what the page SHOWS; the Python
// side compares that to the API/ClickHouse. Nothing else is written to
// stdout. Secrets arrive only on stdin (never argv/env) and are scrubbed from
// every artifact; fields filled with a secret are blanked before a failure
// screenshot.
//
//   CHROME_PATH   Chrome/Chromium executable (else the usual install paths)
//   E2E_UI_BASE   the SPA's base URL (nano_e2e.web.WebServer)
//   E2E_UI_HEADED=1 to watch it

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

// Mutable so an in-process importer (ui/playbooks/*) can point it at a stack.
let BASE = (process.env.E2E_UI_BASE || '').replace(/\/$/, '');
export function setBase(url) { BASE = String(url || '').replace(/\/$/, ''); }
const TIMEOUT = 20_000;
const VIEWPORT = { width: 1600, height: 2400 }; // tall: result lists are virtualized

function chromePath() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  return [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  ].find((c) => fs.existsSync(c));
}

// ------------------------------------------------------------------ secrets
const SECRETS = new Set();
const addSecret = (v) => {
  if (typeof v === 'string' && v.length >= 8) {
    SECRETS.add(v);
    SECRETS.add(JSON.stringify(v).slice(1, -1));
  }
};
function scrub(text) {
  let out = String(text);
  for (const s of [...SECRETS].sort((a, b) => b.length - a.length)) out = out.split(s).join('<redacted>');
  return out;
}

// Mask every rendered occurrence of a known secret (text nodes, form values,
// attributes) in the page; returns how many remain afterwards (0 = safe to
// photograph). The values cross into the page only for this comparison.
async function maskSecrets(page) {
  const values = [...SECRETS];
  if (!values.length) return 0;
  return page.evaluate((vals) => {
    const has = (t) => typeof t === 'string' && vals.some((v) => t.includes(v));
    const mask = (t) => { let o = t; for (const v of vals) o = o.split(v).join('•'.repeat(8)); return o; };
    const walk = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) if (has(n.nodeValue)) n.nodeValue = mask(n.nodeValue);
    for (const el of document.querySelectorAll('*')) {
      if ('value' in el && has(el.value)) el.value = mask(el.value);
      for (const a of [...el.attributes]) if (has(a.value)) el.setAttribute(a.name, mask(a.value));
    }
    const remaining = [document.documentElement.outerHTML, document.body ? document.body.innerText : '',
      ...[...document.querySelectorAll('input,textarea')].map((e) => e.value)];
    return remaining.filter(has).length;
  }, values);
}

// ------------------------------------------------------------------ sessions
let browser;
const sessions = new Map(); // sid -> {ctx, page, out, console, network, secretFields}

async function ensureBrowser() {
  if (browser) return browser;
  const exe = chromePath();
  if (!exe) throw new Error('no Chrome/Chromium found: set CHROME_PATH');
  browser = await puppeteer.launch({
    executablePath: exe,
    headless: process.env.E2E_UI_HEADED !== '1',
    args: ['--no-sandbox', '--disable-dev-shm-usage', `--window-size=${VIEWPORT.width},1000`],
  });
  return browser;
}

function sess(sid) {
  const s = sessions.get(sid);
  if (!s) throw new Error(`unknown session ${sid}`);
  return s;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(fn, { timeout = TIMEOUT, interval = 250, desc = 'condition' } = {}) {
  const end = Date.now() + timeout;
  let last;
  for (;;) {
    try {
      const v = await fn();
      if (v) return v;
      last = v;
    } catch (e) {
      last = String(e);
    }
    if (Date.now() > end) throw new Error(`timed out after ${timeout}ms waiting for ${desc}; last: ${scrub(JSON.stringify(last)).slice(0, 300)}`);
    await sleep(interval);
  }
}

// ------------------------------------------------------------------ DOM helpers (run in the page)
// One generic finder, so selectors stay readable in the ops:
//   {role, name, exact}  role ~ button|textbox|tab|option|menuitem|combobox|dialog|row|heading|table
//   {testid}  {placeholder}  {css}  {labelAfter}  {text, exact}
// `within` scopes to the first match of another finder.
const FINDER = `
window.__e2e = window.__e2e || (() => {
  const norm = (s) => (s || '').replace(/\\s+/g, ' ').trim();
  const ROLES = {
    button: 'button,[role=button]', textbox: 'input:not([type=checkbox]):not([type=radio]),textarea,[role=textbox]',
    tab: '[role=tab]', option: '[role=option]', menuitem: '[role=menuitem]', combobox: '[role=combobox],select',
    dialog: '[role=dialog],[role=alertdialog]', alertdialog: '[role=alertdialog]', row: 'tr,[role=row]',
    heading: 'h1,h2,h3,h4,[role=heading]', table: 'table,[role=table]', link: 'a[href]', cell: 'td,th,[role=cell]',
    columnheader: 'th,[role=columnheader]',
  };
  function accName(el) {
    const lb = el.getAttribute('aria-labelledby');
    if (lb) return norm(lb.split(/\\s+/).map((id) => document.getElementById(id)?.textContent || '').join(' '));
    const al = el.getAttribute('aria-label');
    if (al) return norm(al);
    if (el.id) { const l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]'); if (l) return norm(l.textContent); }
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)) {
      const wrap = el.closest('label'); if (wrap) return norm(wrap.textContent);
      return norm(el.getAttribute('placeholder') || el.getAttribute('title') || '');
    }
    return norm(el.textContent);
  }
  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && getComputedStyle(el).visibility !== 'hidden';
  function matches(text, want, exact) {
    if (want == null) return true;
    if (typeof want === 'object' && want.re) return new RegExp(want.re, want.flags || '').test(text);
    return exact ? text === norm(want) : text.includes(norm(want));
  }
  function all(f, root) {
    root = root || document;
    if (f.within) { const w = all(f.within, root)[0]; if (!w) return []; root = w; }
    let els;
    if (f.testid) els = [...root.querySelectorAll('[data-testid="' + f.testid + '"]')];
    else if (f.placeholder) els = [...root.querySelectorAll('[placeholder]')].filter((e) => matches(e.getAttribute('placeholder'), f.placeholder, true));
    else if (f.css) els = [...root.querySelectorAll(f.css)];
    else if (f.labelAfter) {
      const labels = [...root.querySelectorAll('label')].filter((l) => matches(norm(l.textContent), f.labelAfter, f.exact !== false));
      els = labels.map((l) => {
        const box = l.parentElement; return box && box.querySelector('input,textarea');
      }).filter(Boolean);
    } else if (f.role) els = [...root.querySelectorAll(ROLES[f.role] || '[role=' + f.role + ']')].filter((e) => matches(accName(e), f.name, f.exact));
    else if (f.text != null) {
      const w = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
      els = [];
      for (let n = w.currentNode; n; n = w.nextNode()) {
        if (n.children.length === 0 || [...n.childNodes].some((c) => c.nodeType === 3 && norm(c.textContent))) {
          if (matches(norm(n.textContent), f.text, f.exact)) els.push(n);
        }
      }
    } else els = [];
    if (f.has != null) els = els.filter((e) => matches(norm(e.textContent), f.has, false));
    if (f.visible !== false) els = els.filter(visible);
    if (f.nth != null) els = els.slice(f.nth, f.nth + 1);
    if (f.last) els = els.slice(-1);
    return els;
  }
  return { all, norm, accName, visible };
})();
`;

async function inject(page) {
  await page.evaluate(FINDER);
}

async function find(page, f, { timeout = TIMEOUT, desc } = {}) {
  return until(async () => {
    await inject(page);
    const h = await page.evaluateHandle((ff) => window.__e2e.all(ff)[0] || null, f);
    const el = h.asElement();
    return el || null;
  }, { timeout, desc: desc || `element ${JSON.stringify(f)}` });
}

async function count(page, f) {
  await inject(page);
  return page.evaluate((ff) => window.__e2e.all(ff).length, f);
}

async function texts(page, f) {
  await inject(page);
  return page.evaluate((ff) => window.__e2e.all(ff).map((e) => e.textContent || ''), f);
}

async function click(page, f, opts) {
  const el = await find(page, f, opts);
  await until(async () => page.evaluate((e) => !e.disabled && e.getAttribute('aria-disabled') !== 'true', el), { desc: `${JSON.stringify(f)} enabled` });
  // Dialogs/sheets animate in: click only once the box has stopped moving,
  // or the click lands where the element was a frame ago.
  await until(async () => {
    const a = await el.boundingBox();
    await sleep(80);
    const b = await el.boundingBox();
    return !a || !b || (a.x === b.x && a.y === b.y && a.width === b.width && a.height === b.height);
  }, { timeout: 3000, desc: 'element to stop moving' }).catch(() => {});
  try {
    await el.click();
  } catch (e) {
    // Text nodes inside a card / zero-box elements: dispatch the click on
    // the element itself (what a user's click on its visible box does).
    if (!/not clickable|not an Element|no bounding box/i.test(String(e))) throw e;
    await page.evaluate((x) => x.scrollIntoView({ block: 'center' }), el);
    await sleep(150);
    try {
      await el.click();
    } catch {
      // Still no box (e.g. a text node in a card): the full pointer sequence,
      // so components that act on pointerup (Radix Select items) see it.
      await page.evaluate((x) => {
        for (const type of ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click']) {
          const Ctor = type.startsWith('pointer') ? PointerEvent : MouseEvent;
          x.dispatchEvent(new Ctor(type, { bubbles: true, cancelable: true, pointerType: 'mouse', button: 0 }));
        }
      }, el);
    }
  }
}

async function fill(s, page, field) {
  if (field.click) { await click(page, field.find); return; }
  const el = await find(page, field.find);
  if (field.secret) { addSecret(field.value); s.secretFields.push(field.find); }
  await el.focus();
  // React controlled inputs: set through the native setter + an input event
  // (fast for long values like a key file, and replaces what was there).
  await page.evaluate((e, v) => {
    const proto = e.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(e, v);
    e.dispatchEvent(new Event('input', { bubbles: true }));
    e.dispatchEvent(new Event('change', { bubbles: true }));
  }, el, String(field.value));
}

// Radix select: open the trigger, pick the option.
async function choose(page, trigger, option, exact = false) {
  await click(page, trigger);
  await click(page, { role: 'option', name: option, exact });
}

async function waitText(page, text, { exact = true, timeout = TIMEOUT, gone = false } = {}) {
  return until(async () => {
    const n = await count(page, { text, exact });
    return gone ? n === 0 : n > 0;
  }, { timeout, desc: `${gone ? 'no ' : ''}text ${JSON.stringify(text)}` });
}

async function waitUrl(page, re, timeout = 30_000) {
  const rx = new RegExp(re);
  return until(async () => rx.test(page.url()) && page.url(), { timeout, desc: `URL ~ ${re}` });
}

async function authSettled(s) {
  await sleep(150); // let a just-mounted page start its refresh
  await until(async () => s.authInflight === 0, { timeout: 15_000, desc: 'in-flight auth requests to finish' }).catch(() => {});
}

// ------------------------------------------------------------------ ops
const COUNT_RE = /^\s*([\d,]+)\s+events?\s*$/i;

const OPS = {
  async secrets({ values }) { (values || []).forEach(addSecret); return true; },

  async open({ sid, out, name }) {
    const b = await ensureBrowser();
    const ctx = await b.createBrowserContext();
    const page = await ctx.newPage();
    await page.setViewport(VIEWPORT);
    await page.emulateTimezone('UTC');
    page.setDefaultTimeout(TIMEOUT);
    const s = {
      ctx, page, out, name, console: [], network: [], secretFields: [], bodies: [],
      responseBodies: new Set(), authInflight: 0,
    };
    // In-flight /api/auth/* requests: a navigation must not abort a token
    // refresh (the rotated refresh cookie would be lost, and the next page's
    // refresh presents a spent token -> logged out).
    const isAuth = (r) => { try { return new URL(r.url()).pathname.startsWith('/api/auth/'); } catch { return false; } };
    page.on('request', (r) => { if (isAuth(r)) s.authInflight += 1; });
    const done = (r) => { if (isAuth(r)) s.authInflight = Math.max(0, s.authInflight - 1); };
    page.on('requestfinished', done);
    page.on('requestfailed', done);
    if (BASE) await ctx.overridePermissions(BASE, ['clipboard-read', 'clipboard-write', 'clipboard-sanitized-write']);
    // beforeunload guards and native confirms (e.g. "leave without copying the
    // token?") are accepted; each is recorded in the console log.
    page.on('dialog', async (d) => {
      s.console.push({ type: 'dialog', text: `${d.type()}: ${d.message()}` });
      await d.accept().catch(() => {});
    });
    // API response bodies (JSON, bounded), to assert a secret never comes back
    // from the API outside the response that issued it.
    page.on('response', (r) => {
      const pending = (async () => {
        try {
          const u = new URL(r.url());
          if (!u.pathname.startsWith('/api/')) return;
          if (!(r.headers()['content-type'] || '').includes('json')) return;
          const body = await r.text();
          const method = r.request().method();
          // API keys are reveal-once values rendered by the page, not typed by
          // the harness. Learn them at the response boundary so a failure at
          // any later assertion cannot write the raw key into an artifact.
          if (method === 'POST' && u.pathname === '/api/api-keys') {
            try { addSecret(JSON.parse(body).key); } catch { /* malformed error response */ }
          }
          if (body.length < 512 * 1024) s.bodies.push({ t: Date.now(), method, path: u.pathname, body });
        } catch { /* navigation tore it down */ }
      })();
      s.responseBodies.add(pending);
      void pending.finally(() => s.responseBodies.delete(pending));
    });
    page.on('console', (m) => s.console.push({ type: m.type(), text: m.text().slice(0, 4000) }));
    page.on('pageerror', (e) => s.console.push({ type: 'pageerror', text: String(e).slice(0, 4000) }));
    page.on('requestfinished', (r) => {
      const resp = r.response();
      s.network.push({ t: Date.now(), method: r.method(), url: r.url(), status: resp ? resp.status() : 0 });
    });
    page.on('requestfailed', (r) => s.network.push({ t: Date.now(), method: r.method(), url: r.url(), failed: r.failure()?.errorText }));
    sessions.set(sid, s);
    return true;
  },

  async close({ sid, failed }) {
    const s = sess(sid);
    await Promise.allSettled([...s.responseBodies]);
    fs.mkdirSync(s.out, { recursive: true });
    const lines = s.console.map((c) => JSON.stringify(c));
    fs.writeFileSync(path.join(s.out, 'console.log'), scrub(lines.join('\n') + (lines.length ? '\n' : '')));
    if (failed) {
      try {
        // Never photograph a secret: blank every field a secret was typed into,
        // mask every node that DISPLAYS a known secret (issued / rotated
        // tokens the page rendered itself), then re-check the rendered page;
        // if a secret is still there the screenshot is skipped.
        await inject(s.page);
        await s.page.evaluate((fields) => {
          for (const f of fields) for (const e of window.__e2e.all({ ...f, visible: false })) if ('value' in e) e.value = '';
        }, s.secretFields);
        const left = await maskSecrets(s.page);
        if (left === 0) await s.page.screenshot({ path: path.join(s.out, 'failure.png'), fullPage: true });
        else fs.writeFileSync(path.join(s.out, 'failure.png.skipped.txt'), `screenshot skipped: ${left} rendered secret(s) could not be masked\n`);
        fs.writeFileSync(path.join(s.out, 'page.html'), scrub(await s.page.content()));
      } catch (e) {
        fs.writeFileSync(path.join(s.out, 'capture-error.txt'), scrub(String(e)));
      }
      fs.writeFileSync(path.join(s.out, 'network.jsonl'), scrub(s.network.map((n) => JSON.stringify(n)).join('\n') + '\n'));
    }
    await s.ctx.close().catch(() => {});
    sessions.delete(sid);
    return true;
  },

  async goto({ sid, path: p }) {
    const s = sess(sid);
    await authSettled(s);
    await s.page.goto(BASE + p, { waitUntil: 'domcontentloaded' });
    return s.page.url();
  },
  async url({ sid }) { return sess(sid).page.url(); },
  async reload({ sid }) {
    const s = sess(sid);
    await authSettled(s);
    await s.page.reload({ waitUntil: 'domcontentloaded' });
    return s.page.url();
  },
  async wait_url({ sid, re, timeout }) { return waitUrl(sess(sid).page, re, timeout); },
  async click({ sid, find: f, timeout }) { await click(sess(sid).page, f, { timeout }); return true; },
  async count({ sid, find: f }) { return count(sess(sid).page, f); },
  async texts({ sid, find: f }) { return texts(sess(sid).page, f); },
  async wait_text({ sid, text, exact = true, timeout, gone = false }) { return waitText(sess(sid).page, text, { exact, timeout, gone }); },
  async wait_for({ sid, find: f, timeout, gone = false }) {
    const { page } = sess(sid);
    if (gone) return until(async () => (await count(page, f)) === 0, { timeout, desc: `${JSON.stringify(f)} gone` });
    await find(page, f, { timeout });
    return true;
  },
  async fill({ sid, fields }) { const s = sess(sid); for (const f of fields) await fill(s, s.page, f); return true; },
  async choose({ sid, trigger, option, exact = false }) { await choose(sess(sid).page, trigger, option, exact); return true; },
  async select_native({ sid, find: f, value }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    await page.evaluate((e, v) => { e.value = v; e.dispatchEvent(new Event('change', { bubbles: true })); }, el, value);
    return true;
  },

  async clipboard({ sid }) {
    const { page } = sess(sid);
    await page.bringToFront();
    const text = await page.evaluate(() => navigator.clipboard.readText());
    return text;
  },
  // Click a download control; returns {name, text} of the file it produced.
  // The page's `<a download>` click is captured in the page (blob/data URL
  // read back there), so the result does not depend on the browser's download
  // manager; the file is also written to <scenario out>/downloads.
  async download({ sid, find: f, timeout = 30_000 }) {
    const s = sess(sid);
    await s.page.evaluate(() => {
      window.__e2eDownloads = [];
      if (window.__e2eDownloadHook) return;
      window.__e2eDownloadHook = true;
      // Pages revoke the blob URL right after the click: keep the Blob itself.
      const blobs = new Map();
      const create = URL.createObjectURL.bind(URL);
      URL.createObjectURL = (obj) => { const u = create(obj); blobs.set(u, obj); return u; };
      const orig = HTMLAnchorElement.prototype.click;
      HTMLAnchorElement.prototype.click = function click() {
        if (this.hasAttribute('download')) {
          const name = this.getAttribute('download') || 'download';
          const blob = blobs.get(this.href);
          const text = blob ? blob.text() : fetch(this.href).then((r) => r.text());
          window.__e2eDownloads.push(text.then((t) => ({ name, text: t })));
          return undefined;
        }
        return orig.call(this);
      };
    });
    await click(s.page, f, {});
    const got = await until(async () => s.page.evaluate(async () => (window.__e2eDownloads.length ? window.__e2eDownloads[0] : null)), {
      timeout,
      desc: 'a download to be produced',
    });
    const dir = path.join(s.out, 'downloads');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, path.basename(got.name)), scrub(got.text));
    return { name: got.name, text: scrub(got.text) };
  },
  // Capture an explicit acceptance screenshot in the scenario artifact dir.
  // The same secret masking guard as failure screenshots runs first.
  async screenshot({ sid, name, full_page = true }) {
    const s = sess(sid);
    if (typeof name !== 'string' || !/^[a-z0-9][a-z0-9._-]*\.png$/i.test(name) || path.basename(name) !== name) {
      throw new Error(`invalid screenshot name ${JSON.stringify(name)}`);
    }
    await Promise.allSettled([...s.responseBodies]);
    await inject(s.page);
    const left = await maskSecrets(s.page);
    if (left !== 0) throw new Error(`screenshot blocked: ${left} rendered secret(s) could not be masked`);
    fs.mkdirSync(s.out, { recursive: true });
    const target = path.join(s.out, name);
    await s.page.screenshot({ path: target, fullPage: full_page });
    return target;
  },
  async attr({ sid, find: f, name }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    return page.evaluate((e, n) => e.getAttribute(n), el, name);
  },
  // Layout box of an element plus the viewport (NAN-4970: a flyout is pinned
  // to the right edge, a centered dialog is not).
  async rect({ sid, find: f }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    return page.evaluate((e) => {
      const r = e.getBoundingClientRect();
      return { left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height,
        viewport_width: window.innerWidth, viewport_height: window.innerHeight };
    }, el);
  },
  async value({ sid, find: f }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    return page.evaluate((e) => e.value, el);
  },
  // Replace a CodeMirror document through its normal keyboard path.  Unlike
  // form inputs, CodeMirror is contenteditable and has no native value setter.
  async editor_fill({ sid, find: f, value }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    await el.click();
    const modifier = process.platform === 'darwin' ? 'Meta' : 'Control';
    await page.keyboard.down(modifier);
    await page.keyboard.press('KeyA');
    await page.keyboard.up(modifier);
    await page.keyboard.type(String(value));
    return true;
  },
  async wait_attr({ sid, find: f, name, value: want, timeout }) {
    const { page } = sess(sid);
    return until(async () => {
      await inject(page);
      return page.evaluate((ff, n, w) => {
        const e = window.__e2e.all(ff)[0];
        return !!e && e.getAttribute(n) === w;
      }, f, name, want);
    }, { timeout: timeout || TIMEOUT, desc: `${JSON.stringify(f)} [${name}=${want}]` });
  },
  // Booleans only: the page's HTML never crosses the protocol.
  async page_contains({ sid, text }) {
    return (await sess(sid).page.content()).includes(text);
  },
  // API responses (after `since` ms epoch, excluding `except_path` regex)
  // whose body contains `text`: returned as method+path only.
  async responses_containing({ sid, text, since = 0, except_path }) {
    const rx = except_path ? new RegExp(except_path) : null;
    return sess(sid).bodies
      .filter((b) => b.t >= since && b.body.includes(text) && !(rx && rx.test(`${b.method} ${b.path}`)))
      .map((b) => `${b.method} ${b.path}`);
  },
  // Every request URL (any host, any status) since `since` that contains
  // `text`, scrubbed: proves a value never left the page in a URL.
  async requests_containing({ sid, text, since = 0 }) {
    const enc = [text, encodeURIComponent(text)];
    return sess(sid).network.filter((n) => n.t >= since && enc.some((t) => n.url.includes(t))).map((n) => scrub(`${n.method} ${n.url}`));
  },
  // Set a file on an <input type=file> (hidden inputs included).
  async upload({ sid, find: f, path: file }) {
    const el = await find(sess(sid).page, { ...f, visible: false });
    await el.uploadFile(file);
    return true;
  },
  // Uncaught page errors (and React error boundaries' console errors) so far.
  async page_errors({ sid }) {
    return sess(sid).console.filter((c) => c.type === 'pageerror').map((c) => scrub(c.text).slice(0, 500));
  },
  // Visible text of <main> (or body), whitespace-normalized and bounded.
  async main_text({ sid }) {
    const { page } = sess(sid);
    const t = await page.evaluate(() => {
      const m = document.querySelector('main') || document.body;
      return (m.innerText || '').replace(/\s+/g, ' ').trim();
    });
    return scrub(t).slice(0, 4000);
  },
  // Mask every rendered known secret now (the same pass close() runs before a
  // failure screenshot); returns how many remain.
  async mask_secrets({ sid }) {
    const s = sess(sid);
    await Promise.allSettled([...s.responseBodies]);
    await inject(s.page);
    return maskSecrets(s.page);
  },
  async press_key({ sid, find: f, key }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    await el.focus();
    await page.keyboard.press(key);
    return true;
  },
  async now() { return Date.now(); },

  // A table row (the first containing `contains`) as {lowercased header: cell}.
  async row_cells({ sid, within, contains, timeout }) {
    const { page } = sess(sid);
    return until(async () => {
      await inject(page);
      return page.evaluate((w, c) => {
        const root = w ? window.__e2e.all(w)[0] : document;
        if (!root) return null;
        for (const t of root.querySelectorAll('table')) {
          const heads = [...t.querySelectorAll('thead th')].map((h) => window.__e2e.norm(h.textContent).toLowerCase());
          for (const r of t.querySelectorAll('tbody tr')) {
            if (!(r.textContent || '').includes(c)) continue;
            const cells = [...r.querySelectorAll('td')].map((d) => window.__e2e.norm(d.textContent));
            return Object.fromEntries(heads.map((h, i) => [h, cells[i] ?? '']));
          }
        }
        return null;
      }, within || null, contains);
    }, { timeout: timeout || TIMEOUT, desc: `table row containing ${contains}` });
  },

  // ---------------------------------------------------------------- auth
  async login({ sid, email, password }) {
    const s = sess(sid); const { page } = s;
    addSecret(password);
    await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' });
    const first = await find(page, { css: 'form input:not([disabled])' });
    await first.click(); await first.type(email);
    await page.keyboard.press('Enter');
    const pw = await find(page, { css: 'form input[autocomplete="current-password"]:not([disabled])' });
    await pw.click(); await pw.type(password);
    await page.keyboard.press('Enter');
    if (s.wantFail) return true;
    await until(async () => !page.url().includes('/login'), { timeout: 30_000, desc: 'leaving /login' });
    return page.url();
  },
  async login_attempt({ sid, email, password }) {
    const s = sess(sid); s.wantFail = true;
    try { await OPS.login({ sid, email, password }); } finally { s.wantFail = false; }
    return true;
  },
  async first_run_setup({ sid, name, email, password, setupToken = '' }) {
    const { page } = sess(sid);
    addSecret(password);
    if (setupToken) addSecret(setupToken);
    await page.goto(`${BASE}/setup`, { waitUntil: 'domcontentloaded' });
    await find(page, { css: '#name' });
    // NAN-5237: the token field is shown only when the API requires it.
    const fields = [['#name', name], ['#email', email], ['#password', password], ['#confirmPassword', password]];
    if (setupToken && (await page.$('#setupToken'))) fields.unshift(['#setupToken', setupToken]);
    for (const [id, v] of fields) {
      const el = await find(page, { css: id }); await el.click(); await el.type(v);
    }
    await click(page, { role: 'button', name: 'Create Admin Account' });
    await waitText(page, 'Setup Complete!');
    await waitUrl(page, '/login');
    return true;
  },

  // ---------------------------------------------------------------- search
  async search({ sid, query, extra = '' }) {
    const { page } = sess(sid);
    await page.goto(`${BASE}/search?q=${encodeURIComponent(query)}&run=true${extra}`, { waitUntil: 'domcontentloaded' });
    await waitText(page, 'Query complete', { exact: false, timeout: 60_000 });
    return page.url();
  },
  async results_count({ sid }) {
    const { page } = sess(sid);
    await inject(page);
    const t = await page.evaluate(() => {
      const label = [...document.querySelectorAll('span')].find((e) => window.__e2e.norm(e.textContent) === 'Results');
      if (!label) return null;
      const spans = [...label.parentElement.querySelectorAll('span')].map((e) => e.textContent || '');
      return spans.reverse().find((x) => /^\s*[\d,]+\s+events?\s*$/i.test(x)) || null;
    });
    const m = t && COUNT_RE.exec(t);
    if (!m) throw new Error(`no event count in the Results header (${t})`);
    return parseInt(m[1].replace(/,/g, ''), 10);
  },
  async result_rows({ sid }) {
    // The results list is virtualized: scroll through it, collecting every
    // row by its data-index, then scroll back.
    const { page } = sess(sid);
    return page.evaluate(async () => {
      const seen = new Map();
      const grab = () => document.querySelectorAll('main div[data-index]').forEach((e) => seen.set(e.getAttribute('data-index'), e.textContent || ''));
      const scrollers = [document.scrollingElement, ...document.querySelectorAll('main *')].filter(
        (el) => el && el.scrollHeight > el.clientHeight + 20 && getComputedStyle(el).overflowY !== 'visible');
      grab();
      for (const sc of scrollers) {
        const start = sc.scrollTop;
        for (let y = 0; y <= sc.scrollHeight; y += Math.max(200, sc.clientHeight / 2)) {
          sc.scrollTop = y;
          await new Promise((r) => setTimeout(r, 30));
          grab();
        }
        sc.scrollTop = start;
      }
      return [...seen.entries()].sort((a, b) => +a[0] - +b[0]).map((x) => x[1]);
    });
  },
  async table({ sid }) {
    const { page } = sess(sid);
    await find(page, { css: 'main table' });
    return page.$eval('main table', (t) => ({
      header: [...t.querySelectorAll('thead th,[role=columnheader]')].map((c) => (c.textContent || '').trim()),
      rows: [...t.querySelectorAll('tbody tr')].map((r) => [...r.querySelectorAll('td,[role=cell]')].map((c) => (c.textContent || '').trim())),
    }));
  },
  async tail({ sid, interval }) {
    const { page } = sess(sid);
    await click(page, { role: 'button', name: 'Tail interval' });
    await click(page, { role: 'menuitem', name: interval, exact: true });
    await find(page, { role: 'button', name: { re: `tail -f\\s*${interval}` } });
    return true;
  },
  async sidebar_group({ sid, label }) {
    await click(sess(sid).page, { role: 'button', name: { re: `^${label}\\b` } });
    return true;
  },
  async sidebar_field({ sid, field, click: doClick = true }) {
    const { page } = sess(sid);
    // The field list re-renders when field stats arrive, so the row is found
    // afresh on every poll (a held handle goes stale), and a click that landed
    // on a row being replaced is retried.
    const rowOf = (f) => {
      const span = [...document.querySelectorAll('span')].find((e) => window.__e2e.norm(e.textContent) === f);
      return span ? span.closest('div.cursor-pointer') : null;
    };
    let lastClick = 0;
    return until(async () => {
      await inject(page);
      const h = await page.evaluateHandle(new Function('f', `return (${rowOf.toString()})(f)`), field);
      const row = h.asElement();
      if (!row) return null;
      const got = await page.evaluate((r) => {
        const block = r.nextElementSibling;
        if (!block || !/unique/.test(block.textContent || '')) return { open: false };
        const head = (block.querySelector('div')?.textContent || '');
        const m = /([\d,]+)\+?\s+unique\s+·\s+([\d,]+)\+?\s+events/.exec(head);
        if (!m) return { open: true };
        const percent = {};
        for (const g of block.querySelectorAll('div.grid')) {
          const v = g.querySelector('span[title]')?.getAttribute('title') || '';
          const p = (g.querySelector('span.tabular-nums')?.textContent || '').trim().replace('%', '');
          percent[v] = parseFloat(p);
        }
        return { open: true, value: { unique: +m[1].replace(/,/g, ''), events: +m[2].replace(/,/g, ''), percent } };
      }, row);
      if (got.value) return got.value;
      if (!got.open && doClick && Date.now() - lastClick > 4000) {
        lastClick = Date.now();
        await row.click().catch(() => {});
      }
      return null;
    }, { desc: `values under ${field}` });
  },

  // ---------------------------------------------------------------- ingestion
  async ingestion_layout({ sid }) {
    const { page } = sess(sid);
    await page.goto(`${BASE}/ingestion/log-sources/cloud-pull`, { waitUntil: 'domcontentloaded' });
    try { await find(page, { testid: 'cloud-pull-sources' }, { timeout: 10_000 }); return 'nan4941'; } catch { return 'legacy'; }
  },
};

// In-process use (ui/playbooks/*): the same ops and DOM helpers, no stdin loop.
export { OPS, sess, find, count, texts, click, waitText, waitUrl, until, sleep, inject, addSecret, scrub, maskSecrets, chromePath };
export async function closeBrowser() {
  for (const { ctx } of sessions.values()) await ctx.close().catch(() => {});
  sessions.clear();
  if (browser) await browser.close().catch(() => {});
  browser = undefined;
}

const IS_MAIN = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (IS_MAIN) runProtocol();

// ------------------------------------------------------------------ loop
function runProtocol() {
const rl = readline.createInterface({ input: process.stdin });
const send = (o) => process.stdout.write(JSON.stringify(o) + '\n');
let chain = Promise.resolve();
let shuttingDown = false;

async function shutdown(code, drain = false) {
  if (shuttingDown) return;
  shuttingDown = true;
  try { rl.close(); } catch { /* already closed */ }
  if (drain) await chain.catch(() => {});
  for (const { ctx } of sessions.values()) await ctx.close().catch(() => {});
  sessions.clear();
  if (browser) await browser.close().catch(() => {});
  process.exit(code);
}

rl.on('line', (line) => {
  chain = chain.then(async () => {
    let req;
    try { req = JSON.parse(line); } catch { return; }
    const fn = OPS[req.op];
    if (!fn) return send({ id: req.id, ok: false, error: `unknown op ${req.op}` });
    try {
      send({ id: req.id, ok: true, result: await fn(req.args || {}) });
    } catch (e) {
      send({ id: req.id, ok: false, error: scrub(e && e.stack ? e.stack : String(e)).slice(0, 4000) });
    }
  });
});
rl.on('close', () => { void shutdown(0, true); });
process.once('SIGINT', () => { void shutdown(130); });
process.once('SIGTERM', () => { void shutdown(143); });
process.once('SIGHUP', () => { void shutdown(129); });
process.once('uncaughtException', (error) => {
  process.stderr.write(`${scrub(error?.stack || error)}\n`);
  void shutdown(1);
});
process.once('unhandledRejection', (error) => {
  process.stderr.write(`${scrub(error?.stack || error)}\n`);
  void shutdown(1);
});
}
