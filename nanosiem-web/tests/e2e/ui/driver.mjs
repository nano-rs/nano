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
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';
import {
  SECRET_REVEAL, clearMarks, layoutScan, layoutSignature, loadAllowlist, pageMayShowSecret, redactTokens, showMarks,
} from './layout.mjs';

// Mutable so an in-process importer (ui/playbooks/*) can point it at a stack.
let BASE = (process.env.E2E_UI_BASE || '').replace(/\/$/, '');
export function setBase(url) { BASE = String(url || '').replace(/\/$/, ''); }
const TIMEOUT = 20_000;
const VIEWPORT = { width: 1600, height: 2400 }; // tall: result lists are virtualized
// NAN-5762 layout invariants: `off` skips the scan; `enforce` / `report` are the
// Python wrapper's business (the driver records either way).
const LAYOUT_MODE = (process.env.NANO_E2E_LAYOUT || 'enforce').toLowerCase();
let LAYOUT_ALLOW = [];
try {
  LAYOUT_ALLOW = loadAllowlist(process.env.E2E_LAYOUT_ALLOWLIST || '');
} catch (e) {
  process.stderr.write(`layout allowlist unreadable: ${e}\n`);
  throw e;
}

// Inline WCAG 2.0/2.1 A/AA accessibility hook (mirrors NAN-5762 layout hook).
// Default is `off` so existing e2e runs are unaffected unless opted in.
// One strict parser, the same as ui.py a11y_mode(): off, report or enforce in
// any case, surrounding spaces ignored, unset or empty = off. Any other value
// is an error, so a typo never silently turns the scan on or off.
const A11Y_MODES = new Set(['off', 'report', 'enforce']);
export function parseA11yMode(raw) {
  const mode = String(raw ?? '').trim().toLowerCase() || 'off';
  if (!A11Y_MODES.has(mode)) {
    throw new Error(`NANO_E2E_A11Y=${JSON.stringify(String(raw))}: expected enforce, report or off`);
  }
  return mode;
}
const A11Y_MODE = parseA11yMode(process.env.NANO_E2E_A11Y);
const A11Y_WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
const A11Y_BLOCKING_IMPACTS = new Set(['critical', 'serious']);
const A11Y_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const A11Y_RULE_RE = /^[a-z][a-z0-9-]*$/;
const A11Y_ISSUE_RE = /^NAN-\d+$/;
const _AXE_CACHE = new Map();

// Why an allowlist selector or within is too broad, or null when it is
// specific. Mirrors ui.py a11y_selector_problem() exactly: CSS escapes,
// quoted strings, [attribute] bodies and (...) arguments are blanked first;
// then a universal "*" or a selector list is refused, and the last compound
// (the element the rule applies to) needs a non-empty id, class or
// attribute. So *, html, body, :root, div, ".", "div, *", "body *" and
// :not(.x) are all refused. Nor may the last part be the document root
// (html[lang], body.dark, :root:not(.x), html > body), whatever its
// qualifiers: as a within every element is inside it.
export function a11ySelectorProblem(sel) {
  let s = String(sel).replace(/\\./g, '_');
  s = s.replace(/"[^"]*"|'[^']*'/g, '"x"');
  s = s.replace(/\[([^\]]*)\]/g, (_, inner) => (inner.trim() ? '[a]' : '[]'));
  for (let prev = ''; prev !== s;) { prev = s; s = s.replace(/\([^()]*\)/g, '()'); }
  if (s.includes('*')) return 'uses the universal "*" selector';
  if (s.includes(',')) return 'is a selector list; use one selector per entry';
  const parts = s.trim().split(/\s*[>+~]\s*|\s+/).filter(Boolean);
  const subject = parts.length ? parts[parts.length - 1] : '';
  if (!/#[A-Za-z0-9_-]|\.[A-Za-z0-9_-]|\[a\]/.test(subject)) {
    return 'is too broad; its last part needs an id (#x), a class (.x) or an attribute ([x=y])';
  }
  if (/^(?:html|body)(?![A-Za-z0-9_-])/i.test(subject) || /:root(?![A-Za-z0-9_-])/i.test(subject)) {
    return 'is the whole page; every element is inside html, body or :root';
  }
  return null;
}

// ui-surfaces.json key -> regex source; the same as ui.py _a11y_route_regex().
export function a11yRouteRegex(route) {
  const esc = route.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/:[A-Za-z_][A-Za-z0-9_]*/g, '[^/]+');
  return `^${esc}/?$`;
}

// In-page allowlist matcher (self-contained: puppeteer serializes it). For
// each item returns the first matching entry id or null. An entry matches when
// the rule is the same, a surface (if any) matches the path or path+query, the
// element matches "selector" (if set) and has an ancestor-or-self matching
// "within" (if set). ui.py match_a11y_allowlist() applies the same rules to
// selector strings; e2e/selftest/fixtures/a11y-allowlist-parity.json pins them.
export function a11yMatchAll({ allow, items }) {
  const route = location.pathname;
  const full = route + location.search;
  const errors = [];
  const safe = (fn, sel) => {
    try { return fn(); } catch (err) { errors.push(`${sel}: ${err.message}`); return false; }
  };
  const ids = items.map(({ rule, target }) => {
    let el = null;
    if (typeof target === 'string' && target) {
      try { el = document.querySelector(target); } catch { el = null; }
    }
    if (!el) return null;
    for (const a of allow) {
      if (a.rule !== rule) continue;
      if (a.routes.length && !a.routes.some((rx) => new RegExp(rx).test(route) || new RegExp(rx).test(full))) continue;
      if (a.selector && !safe(() => el.matches(a.selector), a.selector)) continue;
      if (a.within && !safe(() => Boolean(el.closest(a.within)), a.within)) continue;
      return a.id;
    }
    return null;
  });
  return { ids, errors };
}

// A page URL safe to log: no user:password, no #fragment, and query values
// dropped (the keys stay, so ?tab= is still readable).
export function a11ySafeUrl(raw) {
  try {
    const u = new URL(String(raw));
    const keys = [...new Set([...u.searchParams.keys()])];
    return `${u.origin}${u.pathname}${keys.length ? `?${keys.map((k) => `${encodeURIComponent(k)}=`).join('&')}` : ''}`;
  } catch {
    return '';
  }
}

export function loadA11yAllowlist(file) {
  if (!file || !fs.existsSync(file)) return [];
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.entries)) {
    throw new Error('a11y allowlist must be a JSON object with an "entries" array');
  }
  const seen = new Set();
  const out = [];
  for (let i = 0; i < doc.entries.length; i += 1) {
    const e = doc.entries[i];
    const where = `a11y allowlist entry ${i}`;
    if (!e || typeof e !== 'object') throw new Error(`${where}: must be an object`);
    if (typeof e.id !== 'string' || !A11Y_ID_RE.test(e.id)) {
      throw new Error(`${where}: requires "id" matching [A-Za-z0-9][A-Za-z0-9._-]*`);
    }
    if (seen.has(e.id)) throw new Error(`${where}: duplicate id ${JSON.stringify(e.id)}`);
    seen.add(e.id);
    if (typeof e.rule !== 'string' || !A11Y_RULE_RE.test(e.rule) || e.rule === 'any' || e.rule === 'all') {
      throw new Error(`${where} (${e.id}): requires exact axe rule id in "rule" (wildcards forbidden)`);
    }
    const selector = typeof e.selector === 'string' && e.selector.trim() ? e.selector.trim() : null;
    const within = typeof e.within === 'string' && e.within.trim() ? e.within.trim() : null;
    if (!selector && !within) {
      throw new Error(`${where} (${e.id}): requires at least one of "selector" or "within"`);
    }
    for (const [name, value] of [['selector', selector], ['within', within]]) {
      const problem = value ? a11ySelectorProblem(value) : null;
      if (problem) throw new Error(`${where} (${e.id}): "${name}" ${JSON.stringify(value)} ${problem}`);
    }
    if (typeof e.reason !== 'string' || !e.reason.trim()) {
      throw new Error(`${where} (${e.id}): requires a non-empty "reason"`);
    }
    const surfaces = e.surfaces === undefined ? [] : e.surfaces;
    if (
      !Array.isArray(surfaces)
      || surfaces.some((s) => typeof s !== 'string' || !s.trim() || s !== s.trim() || s.includes('*') || !s.startsWith('/'))
    ) {
      throw new Error(`${where} (${e.id}): "surfaces" must be an array of concrete "/..." ui-surfaces.json keys without wildcards`);
    }
    if (e.temporary !== undefined && typeof e.temporary !== 'boolean') {
      throw new Error(`${where} (${e.id}): "temporary" must be a boolean`);
    }
    if (e.issue !== undefined && e.issue !== null) {
      if (typeof e.issue !== 'string' || !A11Y_ISSUE_RE.test(e.issue)) {
        throw new Error(`${where} (${e.id}): "issue" must match NAN-<id>`);
      }
    }
    if (e.temporary === true && !(typeof e.issue === 'string' && A11Y_ISSUE_RE.test(e.issue))) {
      throw new Error(`${where} (${e.id}): temporary entry requires "issue": "NAN-<id>"`);
    }
    out.push({
      id: e.id,
      rule: e.rule,
      routes: surfaces.map(a11yRouteRegex),
      selector,
      within,
    });
  }
  return out;
}

export function resolveAxeSource(explicitPath = '') {
  const configured = String(explicitPath || process.env.NANO_E2E_AXE_PATH || '').trim();
  const candidates = [];
  if (configured) {
    if (!fs.existsSync(configured)) {
      return {
        available: false,
        reason: `axe-core path does not exist: ${configured}`,
      };
    }
    candidates.push(configured);
  } else {
    const resolvers = [createRequire(import.meta.url)];
    try {
      resolvers.push(createRequire(path.join(process.cwd(), 'package.json')));
    } catch { /* cwd has no package.json */ }
    for (const req of resolvers) {
      for (const spec of ['axe-core/axe.min.js', 'axe-core']) {
        try {
          const resolved = req.resolve(spec);
          if (resolved && fs.existsSync(resolved)) {
            const minSibling = path.join(path.dirname(resolved), 'axe.min.js');
            candidates.push(fs.existsSync(minSibling) ? minSibling : resolved);
          }
        } catch { /* try next resolver */ }
      }
    }
  }
  for (const cand of candidates) {
    if (_AXE_CACHE.has(cand)) return { available: true, path: cand, source: _AXE_CACHE.get(cand) };
    try {
      const source = fs.readFileSync(cand, 'utf8');
      if (source.trim()) {
        _AXE_CACHE.set(cand, source);
        return { available: true, path: cand, source };
      }
    } catch { /* try next candidate */ }
  }
  return {
    available: false,
    reason: 'axe-core not found (set NANO_E2E_AXE_PATH or install axe-core in node_modules)',
  };
}

let A11Y_ALLOW = [];
try {
  A11Y_ALLOW = loadA11yAllowlist(process.env.E2E_A11Y_ALLOWLIST || '');
} catch (e) {
  process.stderr.write(`a11y allowlist unreadable: ${e}\n`);
  throw e;
}

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
  // NAN-5884: tag the browser with the run's leak-guard token, so a guard
  // only counts its own run's browsers when lanes share a host. The token is
  // in the profile directory: Chrome passes --user-data-dir to every helper
  // (renderer, GPU, utility), so an orphaned helper is still attributable.
  // The name keeps Puppeteer's own prefix, which the guard looks for; a
  // profile we pass ourselves is ours to remove.
  const token = process.env.NANO_LEAK_GUARD_RUN || '';
  let userDataDir;
  if (/^[0-9a-f]{8,64}$/.test(token)) {
    userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), `puppeteer_dev_chrome_profile-nano-${token}-`));
    process.once('exit', () => {
      try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    });
  }
  browser = await puppeteer.launch({
    executablePath: exe,
    headless: process.env.E2E_UI_HEADED !== '1',
    args: ['--no-sandbox', '--disable-dev-shm-usage', `--window-size=${VIEWPORT.width},1000`],
    ...(userDataDir ? { userDataDir } : {}),
  });
  return browser;
}

// Wait for captured API bodies (secret learning happens there), bounded: a body
// still pending after 10 s is a stream the capture filter did not recognise,
// and waiting on it would wedge the driver for the rest of the run (NAN-5333).
async function settleBodies(s, ms = BODY_WAIT_MS) {
  let timer;
  await Promise.race([
    Promise.allSettled([...s.responseBodies]),
    new Promise((resolve) => { timer = setTimeout(resolve, ms); }),
  ]);
  clearTimeout(timer);
}

// NAN-5833: how long one captured body may stay pending. Each capture gives up
// on its own after this, so a body that never arrives (CDP reported neither
// loadingFinished nor loadingFailed) leaves `responseBodies` once. Without it
// the stuck promise stayed in the set for the whole session and every later
// layout check paid the full settleBodies wait: 20 s per page on the smoke walk.
const BODY_WAIT_MS = 10_000;

// NAN-5833: the API responses whose bodies the driver captures. Only the app's
// own origin: a third-party URL whose path starts with /api/ (the browser
// Sentry envelope POSTs, https://…ingest.sentry.io/api/<id>/envelope/) is not
// an app response, and a cross-origin keepalive body may never be delivered.
export function capturesBody(url, contentType, base = BASE) {
  if (!isAppApi(url, '/api/', base)) return false;
  const ctype = contentType || '';
  // Streams (NDJSON search/tail, SSE) never end while the page is open:
  // awaiting their body would hang every later op (NAN-5333).
  return ctype.includes('json') && !ctype.includes('ndjson') && !ctype.includes('event-stream');
}

// NAN-5833: `url` is the app's own API (same origin as BASE when set) under
// `prefix`. A third-party URL whose path happens to start with /api/ (the
// Sentry envelope POSTs) is not.
export function isAppApi(url, prefix = '/api/', base = BASE) {
  let u;
  try { u = new URL(url); } catch { return false; }
  if (base) {
    try { if (u.origin !== new URL(base).origin) return false; } catch { return false; }
  }
  return u.pathname.startsWith(prefix);
}

// `p` settled, or `undefined` after `ms` (the timer is cleared once `p` settles).
export function bounded(p, ms = BODY_WAIT_MS) {
  let timer;
  return Promise.race([
    Promise.resolve(p).finally(() => clearTimeout(timer)),
    new Promise((resolve) => { timer = setTimeout(resolve, ms); }),
  ]);
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

// NAN-5465: after picking a select option, wait for the listbox to close and
// its exit animation to settle. Since Radix Select 2.4 / Dialog 1.3 the next
// click, if it lands while the select is closing, is swallowed: a dialog's
// submit clicked right after picking an option sent no request and the dialog
// stayed open (bisected: 0 ms stuck, 300 ms created). A user never clicks
// that fast.
async function settleAfterOption(page) {
  await until(async () => page.evaluate(() => !document.querySelector('[role=listbox]')),
    { timeout: 5000, desc: 'select listbox to close' }).catch(() => {});
  await sleep(350);
}

async function click(page, f, opts) {
  // A list that re-renders between find and click detaches the handle
  // (dashboard panels, field rows): find it again and retry (NAN-5684).
  for (let attempt = 0; ; attempt += 1) {
    const el = await find(page, f, opts);
    const isOption = await page.evaluate((e) => e.getAttribute('role') === 'option', el).catch(() => false);
    try {
      await clickElement(page, el, f);
      return;
    } catch (e) {
      if (attempt >= 2 || !/detached/i.test(String(e))) throw e;
      await sleep(250);
    } finally {
      if (isOption) await settleAfterOption(page);
    }
  }
}

// NAN-5830: `el.click()` clicks the element's centre with no hit test, so
// whatever is painted over the target takes the click instead. Two transient
// layers do that:
//   * a Sonner toast: the bottom-right stack sits on the parser Test lab's
//     "Test" button, and the pointer then hovering the toaster paused Sonner's
//     timers, so the toast never left;
//   * a dialog still animating closed: Radix keeps the closing overlay
//     (fixed, data-state="closed") mounted until its exit animation ends, so a
//     click right after confirming one dialog ("Save changes") lands on the
//     fading overlay and the next button ("Publish") never opens its dialog.
// Do what a user does: move the pointer off the toaster and wait for the layer
// to go. One that outlives the wait is reported and the click proceeds.
const COVER_WAIT_MS = 15_000;

async function transientCover(page, el) {
  return page.evaluate((e) => {
    // A toast's own action (Undo, Retry) is not covered by its toast.
    if (e.closest('[data-sonner-toast]')) return '';
    const r = e.getBoundingClientRect();
    if (!r.width || !r.height) return '';
    const x = r.left + r.width / 2;
    const y = r.top + r.height / 2;
    // Still off-screen (e.g. inside a clipped scroller): the click scrolls it.
    if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) return '';
    const hit = document.elementFromPoint(x, y);
    // The target, its content, or an ancestor of it receives the click.
    if (!hit || e.contains(hit) || hit.contains(e)) return '';
    const toast = hit.closest('[data-sonner-toast]');
    if (toast) return `toast ${(toast.textContent || '').trim().slice(0, 80)}`;
    for (let n = hit; n && n !== document.body; n = n.parentElement) {
      if (n.getAttribute('data-state') === 'closed' && getComputedStyle(n).position === 'fixed') {
        return `closing ${n.getAttribute('role') || n.tagName.toLowerCase()}`;
      }
    }
    return '';
  }, el).catch(() => '');
}

async function waitForTransientCover(page, el) {
  // Hit-test where el.click() will click: bring an off-screen target into
  // view first (the click scrolls it there anyway, possibly under a layer).
  await page.evaluate((e) => {
    const r = e.getBoundingClientRect();
    const cx = r.left + r.width / 2;
    const cy = r.top + r.height / 2;
    if (cx < 0 || cy < 0 || cx >= window.innerWidth || cy >= window.innerHeight) {
      e.scrollIntoView({ block: 'center', inline: 'nearest' });
    }
  }, el).catch(() => {});
  let cover = await transientCover(page, el);
  if (!cover) return;
  // Move off the toaster as soon as a toast is the cover, including one a
  // closing overlay uncovers later: a hovered Sonner stack never times out.
  let movedOff = false;
  const check = async () => {
    cover = await transientCover(page, el);
    if (cover.startsWith('toast') && !movedOff) {
      movedOff = true;
      await page.mouse.move(1, 1);
    }
    return !cover;
  };
  try {
    await until(check, { timeout: COVER_WAIT_MS, interval: 100, desc: 'a transient layer to stop covering the click target' });
  } catch {
    process.stderr.write(`${scrub(`still covered by ${JSON.stringify(cover)} after ${COVER_WAIT_MS}ms; clicking anyway`)}\n`);
  }
}

async function clickElement(page, el, f) {
  await until(async () => page.evaluate((e) => !e.disabled && e.getAttribute('aria-disabled') !== 'true', el), { desc: `${JSON.stringify(f)} enabled` });
  // Dialogs/sheets animate in: click only once the box has stopped moving,
  // or the click lands where the element was a frame ago.
  await until(async () => {
    const a = await el.boundingBox();
    await sleep(80);
    const b = await el.boundingBox();
    return !a || !b || (a.x === b.x && a.y === b.y && a.width === b.width && a.height === b.height);
  }, { timeout: 3000, desc: 'element to stop moving' }).catch(() => {});
  await waitForTransientCover(page, el);
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
  await click(page, { role: 'option', name: option, exact }); // settles (see click)
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
    // NAN-5798: a Sentry-enabled e2e build tags browser events with the run
    // and the scenario (lib/error-tracking/sentry.ts reads this). Nothing is
    // injected unless the harness turned Sentry on.
    if (process.env.E2E_SENTRY_WEB === '1') {
      await page.evaluateOnNewDocument((runId, test) => {
        window.__NANO_E2E__ = { runId, test };
      }, process.env.E2E_RUN_ID || '', String(name || ''));
    }
    const s = {
      ctx, page, out, name, console: [], network: [], secretFields: [], bodies: [],
      responseBodies: new Set(), authInflight: 0,
    };
    // In-flight /api/auth/* requests: a navigation must not abort a token
    // refresh (the rotated refresh cookie would be lost, and the next page's
    // refresh presents a spent token -> logged out).
    const isAuth = (r) => isAppApi(r.url(), '/api/auth/');
    page.on('request', (r) => {
      if (isAuth(r)) s.authInflight += 1;
      // NAN-5586: the session's bearer, kept for end_session (a secret: scrubbed).
      const h = r.headers().authorization || '';
      if (h.startsWith('Bearer ')) { const b = h.slice(7); if (b !== s.bearer) { s.bearer = b; addSecret(b); } }
    });
    const done = (r) => { if (isAuth(r)) s.authInflight = Math.max(0, s.authInflight - 1); };
    page.on('requestfinished', done);
    page.on('requestfailed', done);
    if (BASE) await ctx.overridePermissions(BASE, ['clipboard-read', 'clipboard-write', 'clipboard-sanitized-write']);
    // beforeunload guards and native confirms (e.g. "leave without copying the
    // token?") are accepted; each is recorded in the console log.
    page.on('dialog', async (d) => {
      s.console.push({ t: Date.now(), type: 'dialog', text: `${d.type()}: ${d.message()}` });
      await d.accept().catch(() => {});
    });
    // API response bodies (JSON, bounded), to assert a secret never comes back
    // from the API outside the response that issued it.
    page.on('response', (r) => {
      const pending = (async () => {
        try {
          if (!capturesBody(r.url(), r.headers()['content-type'])) return;
          const u = new URL(r.url());
          const body = await bounded(r.text());
          if (body === undefined) return; // never arrived (NAN-5833)
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
    page.on('console', (m) => s.console.push({ t: Date.now(), type: m.type(), text: m.text().slice(0, 4000) }));
    page.on('pageerror', (e) => s.console.push({ t: Date.now(), type: 'pageerror', text: String(e).slice(0, 4000) }));
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
    await settleBodies(s);
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
    await settleBodies(s);
    await inject(s.page);
    const left = await maskSecrets(s.page);
    if (left !== 0) throw new Error(`screenshot blocked: ${left} rendered secret(s) could not be masked`);
    fs.mkdirSync(s.out, { recursive: true });
    const target = path.join(s.out, name);
    await s.page.screenshot({ path: target, fullPage: full_page });
    return target;
  },
  // NAN-5561: switch the app theme (`light` | `dark`) in place for paired
  // acceptance screenshots: the same storage key and root class the app's
  // ThemeProvider uses, then a frame for styles to apply.
  async theme({ sid, mode }) {
    const s = sess(sid);
    if (mode !== 'light' && mode !== 'dark') throw new Error(`invalid theme ${JSON.stringify(mode)}`);
    await s.page.evaluate((m) => {
      try { localStorage.setItem('nanosiem-theme', m); } catch { /* storage may be blocked */ }
      const root = document.documentElement;
      root.classList.remove('light', 'dark');
      root.classList.add(m);
      root.style.colorScheme = m;
    }, mode);
    await s.page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
    return mode;
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
    await page.evaluate((e) => e.scrollIntoView({ block: 'center' }), el);
    try {
      await el.click();
    } catch (e) {
      // An editor inside an animating sheet has no clickable box for a few
      // frames: focus its contenteditable directly (NAN-5684).
      if (!/not clickable|not an Element|no bounding box/i.test(String(e))) throw e;
      await page.evaluate((x) => x.focus(), el);
    }
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
    await settleBodies(s);
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

  // ---------------------------------------------------------------- page health (NAN-5586)
  // Resize the viewport (`height` defaults to the harness's tall one).
  async viewport({ sid, width, height }) {
    const s = sess(sid);
    await s.page.setViewport({ width: Number(width) || VIEWPORT.width, height: Number(height) || VIEWPORT.height });
    await s.page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
    await sleep(250); // ResizeObserver-driven layouts settle
    return true;
  },
  // Horizontal overflow at the current viewport: whether the document (or the
  // app's main scroller) scrolls sideways, and the outermost elements that
  // stick out past the right edge without a scrolling ancestor to clip them.
  async overflow({ sid }) {
    const { page } = sess(sid);
    return page.evaluate(() => {
      const vw = document.documentElement.clientWidth;
      const doc = Math.max(document.documentElement.scrollWidth, document.body ? document.body.scrollWidth : 0);
      const main = document.querySelector('main');
      const mainOver = main ? main.scrollWidth - main.clientWidth : 0;
      const clipped = (el) => {
        for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
          const ox = getComputedStyle(p).overflowX;
          if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') {
            const pr = p.getBoundingClientRect();
            if (pr.right <= vw + 1) return true;
          }
        }
        return false;
      };
      const describe = (el) => {
        const id = el.getAttribute('data-testid');
        const cls = (el.getAttribute('class') || '').split(/\s+/).slice(0, 4).join('.');
        const txt = (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 60);
        return `${el.tagName.toLowerCase()}${id ? `[data-testid=${id}]` : ''}${cls ? `.${cls}` : ''} right=${Math.round(el.getBoundingClientRect().right)} "${txt}"`;
      };
      const offenders = [];
      for (const el of document.querySelectorAll('body *')) {
        const r = el.getBoundingClientRect();
        if (!r.width || r.right <= vw + 1 || getComputedStyle(el).position === 'fixed') continue;
        if (clipped(el)) continue;
        if (el.parentElement && el.parentElement.getBoundingClientRect().right > vw + 1 && !clipped(el.parentElement)) continue;
        offenders.push(describe(el));
        if (offenders.length >= 5) break;
      }
      return { viewport: vw, document: doc - vw, main: mainOver, offenders };
    });
  },
  // NAN-5762: the layout invariants (layout.mjs) on whatever the page shows
  // now. Runs the scan only when the page's fingerprint changed since the last
  // check (route, viewport, open panels, DOM size bucket, busy state) unless
  // `force`. A violation must persist across a short re-check (an animating
  // sheet is not a bug) and is reported once per session; each new batch gets
  // a screenshot with the offenders outlined and lines in layout.jsonl.
  async layout_check({ sid, force = false, after = '' }) {
    const s = sess(sid);
    if (LAYOUT_MODE === 'off') return { violations: [], allowed: [] };
    const { page } = s;
    s.layoutSeen = s.layoutSeen || new Set();
    try {
      const sig = await page.evaluate(layoutSignature);
      if (!force && sig === s.layoutSig) return { violations: [], allowed: [] };
      // Fail closed on secrets: learn every pending API body first, then treat
      // the page as secret-bearing if it may show one (layout.mjs).
      await settleBodies(s);
      await inject(page);
      const sensitive = await page.evaluate(pageMayShowSecret, { vals: [...SECRETS], fields: s.secretFields, reveal: SECRET_REVEAL });
      const scanOnce = async () => {
        await page.evaluate(clearMarks);
        return page.evaluate(layoutScan, { allow: LAYOUT_ALLOW, noText: sensitive });
      };
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      let first = await scanOnce();
      if (first.errors.length) throw new Error(`layout allowlist selector error: ${first.errors.join('; ')}`);
      const fresh = (r) => r.violations.filter((v) => !s.layoutSeen.has(v.key));
      // Persisting only: re-measure unallowed new violations after animations
      // settle. What both scans see is real on the page as it is now, so it is
      // never dropped (even if the page changed meanwhile).
      if (fresh(first).some((v) => !v.allowed)) {
        await sleep(450);
        const again = await scanOnce();
        const before = new Set(first.violations.map((v) => v.key));
        first = { ...again, violations: again.violations.filter((v) => v.allowed || before.has(v.key)) };
      }
      s.layoutSig = await page.evaluate(layoutSignature);
      // Element text leaves the page only scrubbed of registered secrets and of
      // token-shaped strings (paths and URLs below are harness-owned).
      const clean = (t) => (t == null ? t : redactTokens(scrub(t)));
      const found = fresh(first).map((v) => ({
        ...v, element: clean(v.element), container: clean(v.container), detail: JSON.parse(clean(JSON.stringify(v.detail ?? null))),
      }));
      for (const v of found) s.layoutSeen.add(v.key);
      const bad = found.filter((v) => !v.allowed);
      const allowed = found.filter((v) => v.allowed);
      let shot = null;
      if (found.length) {
        fs.mkdirSync(s.out, { recursive: true });
        if (bad.length) {
          s.layoutShots = (s.layoutShots || 0) + 1;
          const target = path.join(s.out, `layout-${s.layoutShots}.png`);
          // Re-check right before the capture (a reveal can open during the scan).
          const risky = sensitive || await page.evaluate(pageMayShowSecret, { vals: [...SECRETS], fields: s.secretFields, reveal: SECRET_REVEAL });
          if (risky) {
            fs.writeFileSync(`${target}.skipped.txt`, 'screenshot skipped: the page may show a secret (password field, reveal-once value or a registered secret)\n');
          } else {
            await page.evaluate(showMarks);
            await page.screenshot({ path: target, fullPage: false });
            shot = target;
          }
        }
        const lines = found.map((v) => JSON.stringify({ t: Date.now(), test: s.name, after, url: page.url(), screenshot: shot, ...v }));
        fs.appendFileSync(path.join(s.out, 'layout.jsonl'), scrub(lines.join('\n')) + '\n');
      }
      await page.evaluate(clearMarks);
      return JSON.parse(scrub(JSON.stringify({ violations: bad, allowed, screenshot: shot, stats: first.stats })));
    } catch (e) {
      // A navigation tore the context down mid-scan: the next op re-measures.
      if (/Execution context was destroyed|Cannot find context|Target closed|detached/i.test(String(e))) {
        return { violations: [], allowed: [] };
      }
      throw e;
    }
  },
  // WCAG 2.0/2.1 A/AA accessibility scan via axe-core (mirrors layout_check).
  // Resolves axe-core cleanly from NANO_E2E_AXE_PATH or node_modules; if
  // absent, returns a structured unavailable result without crashing Chrome.
  async a11y_scan({ sid, force = false, after = '', tags = A11Y_WCAG_TAGS, axe_path: axePath = '', mode = '' }) {
    const s = sess(sid);
    // The page's own mode (UiPage.a11y) wins over the driver's start-up env, so
    // a page that opts in works on the session-scoped driver.
    const effectiveMode = mode ? parseA11yMode(mode) : A11Y_MODE;
    if (effectiveMode === 'off' && !force) {
      return {
        available: true,
        skipped: true,
        reason: 'NANO_E2E_A11Y=off',
        route: '',
        theme: '',
        blocking: [],
        warnings: [],
        allowed: [],
        violations: [],
        incomplete_count: 0,
        passes_count: 0,
      };
    }
    const { page } = s;
    s.a11ySeen = s.a11ySeen || new Set();
    try {
      const sig = await page.evaluate(layoutSignature);
      if (!force && sig === s.a11ySig) {
        return {
          available: true,
          skipped: true,
          reason: 'unchanged',
          route: '',
          theme: '',
          blocking: [],
          warnings: [],
          allowed: [],
          violations: [],
          incomplete_count: 0,
          passes_count: 0,
        };
      }
      const axeResolved = resolveAxeSource(axePath);
      if (!axeResolved.available) {
        const meta = await page.evaluate(() => ({
          route: location.pathname,
          theme: document.documentElement.classList.contains('dark') ? 'dark' : 'light',
        })).catch(() => ({ route: '', theme: '' }));
        return JSON.parse(scrub(JSON.stringify({
          available: false,
          reason: axeResolved.reason,
          route: redactTokens(scrub(meta.route)),
          theme: meta.theme,
          blocking: [],
          warnings: [],
          allowed: [],
          violations: [],
          incomplete_count: 0,
          passes_count: 0,
        })));
      }
      await settleBodies(s);
      await inject(page);
      const sensitive = await page.evaluate(pageMayShowSecret, {
        vals: [...SECRETS],
        fields: s.secretFields,
        reveal: SECRET_REVEAL,
      });
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      const hasAxe = await page.evaluate(() => Boolean(window.axe && typeof window.axe.run === 'function'));
      if (!hasAxe) {
        await page.evaluate(axeResolved.source);
      }
      const runTags = Array.isArray(tags) && tags.length ? tags : A11Y_WCAG_TAGS;
      const scan = await page.evaluate(async ({ evalTags, allow, noText }) => {
        const route = location.pathname;
        const root = document.documentElement;
        let theme = 'light';
        try {
          const stored = localStorage.getItem('nanosiem-theme');
          if (stored === 'dark' || stored === 'light') theme = stored;
          else if (root.classList.contains('dark')) theme = 'dark';
        } catch {
          if (root.classList.contains('dark')) theme = 'dark';
        }
        if (!window.axe || typeof window.axe.run !== 'function') {
          return { missingAxe: true, route, theme, findings: [], allowErrors: [], incomplete_count: 0, passes_count: 0 };
        }
        const res = await window.axe.run(document, {
          runOnly: { type: 'tag', values: evalTags },
        });
        const findings = [];
        for (const v of (res.violations || [])) {
          const impact = String(v.impact || 'minor').toLowerCase();
          for (const node of (v.nodes || [])) {
            const targets = Array.isArray(node.target) ? node.target : [];
            const selector = targets.map((t) => (Array.isArray(t) ? t.join(' >> ') : String(t))).join(', ');
            const target = targets.length === 1 && typeof targets[0] === 'string' ? targets[0] : '';
            findings.push({
              target,
              key: `${v.id}|${impact}|${route}|${theme}|${selector}`,
              rule: v.id,
              impact,
              route,
              theme,
              selector,
              help: v.help || '',
              description: v.description || '',
              help_url: v.helpUrl || '',
              tags: Array.isArray(v.tags) ? v.tags : [],
              html: noText ? '' : String(node.html || '').slice(0, 400),
              failure_summary: noText ? '' : String(node.failureSummary || '').slice(0, 400),
            });
          }
        }
        return {
          missingAxe: false,
          route,
          theme,
          findings,
          incomplete_count: (res.incomplete || []).length,
          passes_count: (res.passes || []).length,
        };
      }, { evalTags: runTags, noText: sensitive });
      if (scan.missingAxe) {
        return JSON.parse(scrub(JSON.stringify({
          available: false,
          reason: 'axe-core script loaded without exposing window.axe.run()',
          route: redactTokens(scrub(scan.route)),
          theme: scan.theme,
          blocking: [],
          warnings: [],
          allowed: [],
          violations: [],
          incomplete_count: 0,
          passes_count: 0,
        })));
      }
      const matched = await page.evaluate(a11yMatchAll, {
        allow: A11Y_ALLOW,
        items: scan.findings.map((f) => ({ rule: f.rule, target: f.target })),
      });
      if (matched.errors.length) {
        throw new Error(`a11y allowlist selector error: ${matched.errors.join('; ')}`);
      }
      scan.findings.forEach((f, i) => { f.allowed = matched.ids[i]; });
      s.a11ySig = await page.evaluate(layoutSignature);
      // Every text field leaves through the same scrub (registered secrets +
      // token shapes); ui.py then runs nano_e2e.redact over the whole result.
      const clean = (t) => (t == null ? t : redactTokens(scrub(t)));
      const fresh = scan.findings
        .filter((f) => !s.a11ySeen.has(f.key))
        .map(({ target, ...f }) => ({
          ...f,
          key: clean(f.key),
          route: clean(f.route),
          selector: clean(f.selector),
          help: clean(f.help),
          description: clean(f.description),
          help_url: clean(f.help_url),
          html: clean(f.html),
          failure_summary: clean(f.failure_summary),
          severity: A11Y_BLOCKING_IMPACTS.has(f.impact) ? 'blocking' : 'warning',
        }));
      for (const f of scan.findings) s.a11ySeen.add(f.key);
      const allowed = fresh.filter((f) => Boolean(f.allowed));
      const blocking = fresh.filter((f) => !f.allowed && f.severity === 'blocking');
      const warnings = fresh.filter((f) => !f.allowed && f.severity !== 'blocking');
      // a11y.jsonl lines; ui.py redacts and writes them (one redaction path).
      const url = clean(a11ySafeUrl(page.url()));
      const records = fresh.map((f) => ({ t: Date.now(), test: s.name, after, url, ...f }));
      return JSON.parse(scrub(JSON.stringify({
        available: true,
        records,
        route: clean(scan.route),
        theme: scan.theme,
        blocking,
        warnings,
        allowed,
        violations: [...blocking, ...warnings],
        incomplete_count: scan.incomplete_count,
        passes_count: scan.passes_count,
      })));
    } catch (e) {
      if (/Execution context was destroyed|Cannot find context|Target closed|detached/i.test(String(e))) {
        return {
          available: true,
          skipped: true,
          reason: 'navigation_context_destroyed',
          route: '',
          theme: '',
          blocking: [],
          warnings: [],
          allowed: [],
          violations: [],
          incomplete_count: 0,
          passes_count: 0,
        };
      }
      throw e;
    }
  },
  // NAN-5758: horizontal scroll INSIDE one container (a flyout, a panel): its
  // own scrollWidth vs clientWidth, plus every descendant scroller that can
  // scroll sideways, and descendants whose box sticks out past its right edge.
  async scroll_extent({ sid, find: f }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    return page.evaluate((root) => {
      const describe = (e) => {
        const id = e.getAttribute('data-testid');
        const cls = (e.getAttribute('class') || '').split(/\s+/).slice(0, 4).join('.');
        const txt = (e.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 60);
        return `${e.tagName.toLowerCase()}${id ? `[data-testid=${id}]` : ''}${cls ? `.${cls}` : ''} "${txt}"`;
      };
      const rr = root.getBoundingClientRect();
      const scrollers = [];
      const past = [];
      for (const e of [root, ...root.querySelectorAll('*')]) {
        const ox = getComputedStyle(e).overflowX;
        if ((ox === 'auto' || ox === 'scroll') && e.scrollWidth > e.clientWidth + 1) {
          scrollers.push({ el: describe(e), scroll_width: e.scrollWidth, client_width: e.clientWidth });
        }
        if (e !== root && past.length < 5) {
          const r = e.getBoundingClientRect();
          if (r.width && r.right > rr.right + 1) past.push(`${describe(e)} right=${Math.round(r.right)} > ${Math.round(rr.right)}`);
        }
      }
      return { scroll_width: root.scrollWidth, client_width: root.clientWidth, scrollers, past_right_edge: past };
    }, el);
  },
  // NAN-5758: whether each match is actually visible as painted, three ways:
  // - hit tests: elementFromPoint at its centre and at four corners (inset
  //   1px) must land on the element or a descendant (anything painted OVER it);
  // - overlaps: other text in its enclosing row whose box intersects it. The
  //   row is found from the PARENT (`closest` tests the element itself first,
  //   so a match carrying its own data-testid would scope to itself and see
  //   nothing). This catches sibling text painted across a transparent label,
  //   which a hit test cannot (the later sibling wins the hit test);
  // - opacity down the ancestor chain, and its size.
  async occlusion({ sid, find: f }) {
    const { page } = sess(sid);
    await inject(page);
    return page.evaluate((ff) => window.__e2e.all(ff).map((e) => {
      e.scrollIntoView({ block: 'center' });
      const r = e.getBoundingClientRect();
      const label = (el) => (el ? `${el.tagName.toLowerCase()}.${(el.getAttribute('class') || '').split(/\s+/).slice(0, 3).join('.')}` : null);
      const inset = Math.min(1, r.width / 4, r.height / 4);
      const points = [
        ['center', r.left + r.width / 2, r.top + r.height / 2],
        ['top-left', r.left + inset, r.top + inset],
        ['top-right', r.right - inset, r.top + inset],
        ['bottom-left', r.left + inset, r.bottom - inset],
        ['bottom-right', r.right - inset, r.bottom - inset],
      ];
      const covered = [];
      let inside = true;
      for (const [where, x, y] of points) {
        if (x < 0 || y < 0 || x > window.innerWidth || y > window.innerHeight) { inside = false; continue; }
        const hit = document.elementFromPoint(x, y);
        if (!hit || !(hit === e || e.contains(hit))) covered.push(`${where}: ${label(hit)}`);
      }
      let opacity = 1;
      for (let p = e; p; p = p.parentElement) opacity *= Number(getComputedStyle(p).opacity || 1);
      const scope = (e.parentElement && e.parentElement.closest('[data-testid]')) || e.parentElement || document.body;
      const overlaps = [];
      for (const o of scope.querySelectorAll('*')) {
        if (o === e || o.contains(e) || e.contains(o)) continue;
        if (![...o.childNodes].some((c) => c.nodeType === 3 && c.textContent.trim())) continue;
        const q = o.getBoundingClientRect();
        if (q.width && q.height && q.left < r.right - 0.5 && q.right > r.left + 0.5 && q.top < r.bottom - 0.5 && q.bottom > r.top + 0.5) {
          overlaps.push((o.textContent || '').trim().slice(0, 40));
        }
      }
      const sid2 = scope.getAttribute && scope.getAttribute('data-testid');
      return {
        text: (e.textContent || '').trim().slice(0, 60),
        scope: label(scope) + (sid2 ? `[data-testid=${sid2}]` : ''),
        overlaps,
        covered,
        on_top: covered.length === 0,
        in_viewport: inside,
        opacity,
        width: r.width,
        height: r.height,
      };
    }), f);
  },
  // An /api request AS the logged-in browser user (the bearer the page sent),
  // for state only that user owns (its pivt notebooks). JSON in, JSON out.
  async session_fetch({ sid, method = 'GET', path: p, body }) {
    const s = sess(sid);
    if (typeof p !== 'string' || !p.startsWith('/api/')) throw new Error(`session_fetch: not an /api path: ${p}`);
    if (!s.bearer) throw new Error('session_fetch: the page has not sent a bearer yet');
    const out = await s.page.evaluate(async (m, u, b, auth) => {
      const r = await fetch(u, { method: m, headers: { Authorization: auth, ...(b == null ? {} : { 'Content-Type': 'application/json' }) },
        body: b == null ? undefined : JSON.stringify(b) });
      const text = await r.text();
      let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
      return { status: r.status, json };
    }, method, BASE + p, body ?? null, `Bearer ${s.bearer}`);
    return JSON.parse(scrub(JSON.stringify(out)));
  },
  // End THIS context's own server session, never the logout route (it ends
  // every session of the user, NAN-5573). `is_current` from /api/sessions/me
  // when the server sets it; otherwise the session this context's login
  // created (the first one created at or after it). The bearer never leaves
  // the driver.
  async end_session({ sid }) {
    const s = sess(sid);
    if (!s.bearer) return { status: 0, reason: 'no bearer seen' };
    return s.page.evaluate(async (base, loginAt, auth) => {
      const h = { Authorization: auth };
      const me = await fetch(`${base}/api/sessions/me`, { headers: h });
      if (!me.ok) return { status: me.status, reason: 'could not list own sessions' };
      const list = (await me.json()).sessions || [];
      let pick = list.find((x) => x.is_current);
      if (!pick && loginAt) {
        pick = list
          .filter((x) => Date.parse(x.created_at) >= loginAt - 2000)
          .sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at))[0];
      }
      if (!pick) return { status: 0, reason: 'no session matches this login' };
      const r = await fetch(`${base}/api/sessions/${encodeURIComponent(pick.id)}`, { method: 'DELETE', headers: h });
      return { status: r.status, session: pick.id, via: pick.is_current ? 'is_current' : 'login time' };
    }, BASE, s.loginAt || 0, `Bearer ${s.bearer}`).catch((e) => ({ status: 0, reason: String(e).slice(0, 200) }));
  },

  // ---------------------------------------------------------------- exploration (NAN-5291)
  // Console errors and failed network requests (status >= 400 or no
  // response) since `since` (ms epoch), scrubbed: what a step broke.
  async events_since({ sid, since = 0 }) {
    const s = sess(sid);
    const bad = new Set(['error', 'pageerror', 'assert']);
    return {
      console: s.console.filter((c) => (c.t || 0) >= since && bad.has(c.type))
        .map((c) => ({ t: c.t, type: c.type, text: scrub(c.text).slice(0, 1000) })),
      network: s.network.filter((n) => n.t >= since && (n.failed || (n.status || 0) >= 400))
        .map((n) => ({ t: n.t, method: n.method, url: scrub(n.url), status: n.status || 0, failed: n.failed || null })),
    };
  },
  // Every completed /api response since `since` (any status): what a page
  // fetched, e.g. data loaded before a permission gate rendered (NAN-5686).
  async api_responses_since({ sid, since = 0 }) {
    const s = sess(sid);
    return s.network.filter((n) => n.t >= since && !n.failed && isAppApi(n.url))
      .map((n) => ({ t: n.t, method: n.method, url: scrub(n.url), status: n.status || 0 }));
  },
  // Real keystrokes into an element (fill() uses the value setter instead).
  async type_text({ sid, find: f, text, clear = false }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    await el.click();
    if (clear) {
      const modifier = process.platform === 'darwin' ? 'Meta' : 'Control';
      await page.keyboard.down(modifier); await page.keyboard.press('KeyA'); await page.keyboard.up(modifier);
      await page.keyboard.press('Backspace');
    }
    await page.keyboard.type(String(text));
    return true;
  },
  // Replace a CodeMirror document with `text`, open completion (Ctrl-Space)
  // and return the offered options {label, detail}. [] when none open.
  async autocomplete({ sid, find: f, text, timeout = 5000 }) {
    const { page } = sess(sid);
    await OPS.editor_fill({ sid, find: f, value: text });
    await page.keyboard.down('Control'); await page.keyboard.press('Space'); await page.keyboard.up('Control');
    const sel = '.cm-tooltip-autocomplete li';
    try { await page.waitForSelector(sel, { timeout }); } catch { return []; }
    await sleep(300); // async sources (schema / usage) fill in after the first paint
    return page.$$eval(sel, (lis) => lis.map((li) => ({
      label: (li.querySelector('.cm-completionLabel')?.textContent || li.textContent || '').trim(),
      detail: (li.querySelector('.cm-completionDetail')?.textContent || '').trim(),
    })));
  },
  // Every field name listed in the search results sidebar (collapsed groups
  // such as Extended / Unmapped are opened first).
  async sidebar_fields({ sid }) {
    const { page } = sess(sid);
    await page.evaluate(() => {
      for (const b of document.querySelectorAll('button[aria-expanded="false"]')) {
        if (/^(extended|unmapped)\b/i.test((b.textContent || '').trim())) b.click();
      }
    });
    await sleep(500);
    return page.evaluate(() => {
      const out = [];
      for (const row of document.querySelectorAll('div.cursor-pointer')) {
        const spans = row.querySelectorAll(':scope > span');
        if (spans.length >= 2 && (spans[0].textContent || '').trim() === '›') {
          const name = (spans[1].textContent || '').trim();
          if (name && !out.includes(name)) out.push(name);
        }
      }
      return out;
    });
  },
  // Field-name hints rendered as placeholders ("e.g., process.name") on
  // visible inputs: hints a user copies verbatim.
  async field_hints({ sid }) {
    const { page } = sess(sid);
    return page.evaluate(() => [...document.querySelectorAll('input[placeholder],textarea[placeholder]')]
      .filter((e) => e.offsetWidth || e.offsetHeight)
      .map((e) => /^e\.g\.,?\s*([A-Za-z_][\w.]*)\s*$/.exec(e.getAttribute('placeholder') || ''))
      .filter(Boolean).map((m) => m[1]));
  },

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
    s.loginAt = Date.now(); // NAN-5586: end_session finds the session this login created
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
    // NAN-5235: a search link from outside the app loads its query and waits
    // for an explicit Run, unless this tab already ran the same query (then it
    // runs). Handle both: click Run when the prompt shows (NAN-5333).
    const prompt = { testid: 'linked-query-run-prompt' };
    const done = { text: 'Query complete', exact: false };
    const first = await until(async () => {
      if ((await count(page, done)) > 0) return 'done';
      if ((await count(page, prompt)) > 0) return 'prompt';
      return null;
    }, { timeout: 60_000, desc: 'the linked-query Run prompt or a completed query' });
    if (first === 'prompt') {
      await click(page, { role: 'button', name: 'Run', exact: true, within: prompt }, { timeout: 15_000 });
      await waitText(page, 'Query complete', { exact: false, timeout: 60_000 });
    }
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

  // ---------------------------------------------------------------- deep workflows (NAN-5684)
  // Real mouse drag across an element, from/to given as fractions of its box
  // (a chart's drag-to-zoom, a grid panel's move, a resize handle).
  async drag({ sid, find: f, from = [0.2, 0.5], to = [0.6, 0.5], steps = 12, hover = false }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    await page.evaluate((e) => e.scrollIntoView({ block: 'center' }), el);
    await sleep(150);
    const box = await el.boundingBox();
    if (!box) throw new Error(`no box to drag on ${JSON.stringify(f)}`);
    const at = ([fx, fy]) => [box.x + box.width * fx, box.y + box.height * fy];
    const [x1, y1] = at(from);
    const [x2, y2] = at(to);
    if (hover) { await page.mouse.move(x1 - 5, y1 - 5); await sleep(150); }
    await page.mouse.move(x1, y1);
    await page.mouse.down();
    for (let i = 1; i <= steps; i += 1) {
      await page.mouse.move(x1 + ((x2 - x1) * i) / steps, y1 + ((y2 - y1) * i) / steps);
      await sleep(16);
    }
    await page.mouse.up();
    return { x1, y1, x2, y2 };
  },
  // Clear this context's localStorage + sessionStorage for the current origin
  // (UI preferences a previous scenario left; auth is a cookie, NAN-5684).
  async storage_clear({ sid }) {
    const { page } = sess(sid);
    await page.evaluate(() => { try { localStorage.clear(); sessionStorage.clear(); } catch { /* opaque origin */ } });
    return true;
  },
  // Write page.html and network.jsonl (scrubbed) under `name`, for a
  // scenario failing on a page that stays open (a module-shared persona).
  async dump({ sid, name }) {
    const s = sess(sid);
    if (!/^[a-z0-9][a-z0-9._-]*$/i.test(String(name || ''))) throw new Error(`bad dump name ${name}`);
    await settleBodies(s);
    await inject(s.page);
    if ((await maskSecrets(s.page)) > 0) throw new Error('a secret is still rendered; not dumping');
    fs.mkdirSync(s.out, { recursive: true });
    fs.writeFileSync(path.join(s.out, `${name}.html`), scrub(await s.page.content()));
    fs.writeFileSync(path.join(s.out, `${name}.network.jsonl`), scrub(s.network.map((n) => JSON.stringify(n)).join('\n') + '\n'));
    return true;
  },
  // A keyboard chord on the focused page, e.g. ['Meta', 'k'] (command palette).
  async chord({ sid, keys }) {
    const { page } = sess(sid);
    const mods = keys.slice(0, -1);
    for (const m of mods) await page.keyboard.down(m);
    await page.keyboard.press(keys[keys.length - 1]);
    for (const m of mods.reverse()) await page.keyboard.up(m);
    return true;
  },
  // NAN-5864: answer one app API call with a canned JSON body, for states a
  // throwaway stack cannot reach on its own (a stale backup, a full disk, an
  // update on offer, a license in grace). Keyed by method and path, with the
  // query string when `path` has one. `body: null` with `clear: true` removes
  // the stub; requests the session never stubbed go to the server unchanged.
  // Returns how many requests the stub answered so far.
  async stub_api({ sid, method = 'GET', path: p, status = 200, body = null, clear = false }) {
    const s = sess(sid);
    if (typeof p !== 'string' || !p.startsWith('/api/')) throw new Error(`stub_api: path must start with /api/: ${p}`);
    const key = `${String(method).toUpperCase()} ${p}`;
    if (!s.stubs) {
      s.stubs = new Map();
      await s.page.setRequestInterception(true);
      s.page.on('request', (r) => {
        if (r.isInterceptResolutionHandled()) return;
        let stub;
        if (isAppApi(r.url(), '/api/', BASE)) {
          const u = new URL(r.url());
          const m = r.method().toUpperCase();
          stub = s.stubs.get(`${m} ${u.pathname}${u.search}`) || s.stubs.get(`${m} ${u.pathname}`);
        }
        if (!stub) { void r.continue().catch(() => {}); return; }
        stub.hits += 1;
        void r.respond({ status: stub.status, contentType: 'application/json', body: JSON.stringify(stub.body) }).catch(() => {});
      });
    }
    if (clear) {
      const had = s.stubs.get(key);
      s.stubs.delete(key);
      return had ? had.hits : 0;
    }
    const prev = s.stubs.get(key);
    s.stubs.set(key, { status, body, hits: prev ? prev.hits : 0 });
    return prev ? prev.hits : 0;
  },
  // Move the pointer over an element (reveals hover-only controls).
  async hover({ sid, find: f }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    await el.hover();
    return true;
  },
  // Scroll the app's scrolling container (and the document) to the bottom,
  // the way a person scrolls a long result list. Returns the scrollTop reached.
  async scroll_bottom({ sid }) {
    const { page } = sess(sid);
    return page.evaluate(() => {
      const els = [document.scrollingElement, ...document.querySelectorAll('div')]
        .filter((el) => el && el.scrollHeight > el.clientHeight + 20 && /(auto|scroll)/.test(getComputedStyle(el).overflowY));
      let top = 0;
      for (const el of els) { el.scrollTop = el.scrollHeight; top = Math.max(top, el.scrollTop); el.dispatchEvent(new Event('scroll')); }
      window.dispatchEvent(new Event('scroll'));
      return top;
    });
  },
  // Record window.open() calls instead of opening tabs ("Open in Search" from
  // a dashboard panel opens a new tab); `opened` returns the recorded URLs.
  async capture_window_open({ sid }) {
    const { page } = sess(sid);
    await page.evaluate(() => {
      window.__e2eOpened = [];
      window.open = (url) => { window.__e2eOpened.push(String(url)); return null; };
    });
    return true;
  },
  async opened({ sid }) {
    const { page } = sess(sid);
    return page.evaluate(() => window.__e2eOpened || []);
  },
  // The value of the attribute `name` on EVERY match (data-* hooks on lists).
  async attrs({ sid, find: f, name }) {
    const { page } = sess(sid);
    await inject(page);
    return page.evaluate((ff, n) => window.__e2e.all(ff).map((e) => e.getAttribute(n)), f, name);
  },
  // Bounding boxes of every match, with a chosen attribute (grid layout checks).
  async boxes({ sid, find: f, name }) {
    const { page } = sess(sid);
    await inject(page);
    return page.evaluate((ff, n) => window.__e2e.all(ff).map((e) => {
      const r = e.getBoundingClientRect();
      return { key: n ? e.getAttribute(n) : null, left: r.left, top: r.top, width: r.width, height: r.height };
    }), f, name);
  },
  // Text of the CodeMirror document inside `find` (the editor's model, not the
  // rendered lines, so long queries are not cut by virtualisation).
  async editor_text({ sid, find: f }) {
    const { page } = sess(sid);
    const el = await find(page, f);
    return page.evaluate((e) => {
      const host = e.closest('.cm-editor') || e.querySelector('.cm-editor') || e;
      const content = host.querySelector('.cm-content') || host;
      const view = content.cmView?.view || host.cmView?.view;
      if (view?.state) return view.state.doc.toString();
      return [...content.querySelectorAll('.cm-line')].map((l) => l.textContent).join('\n');
    }, el);
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
