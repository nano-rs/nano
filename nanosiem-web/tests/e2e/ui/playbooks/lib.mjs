// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared machinery for UI playbooks (NAN-5085): sessions on top of
// ../driver.mjs, an API client per user, the per-page check (NotFound /
// denied / crash / console / network), the dead-button probe, the
// denied-source leak scanner, and the JSON + Markdown report.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as D from '../driver.mjs';
import { KNOWN_ISSUES, splitKnown } from './known-issues.mjs';

const { OPS } = D;
export const sleep = D.sleep;
export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const WEB_ROOT = path.resolve(HERE, '../../../..');

export const BASE = (process.env.BASE_URL || '').replace(/\/$/, '');
if (!BASE) throw new Error('BASE_URL is required (the e2e stack edge, e.g. http://127.0.0.1:<edge port>)');
for (const p of [':3000', ':3002', ':5173', ':8123']) {
  if (BASE.endsWith(p)) throw new Error(`refusing BASE_URL ${BASE}: that is a dev-stack port`);
}
D.setBase(BASE);
export const OUT = path.resolve(process.env.PLAYBOOK_OUT || 'security-update-out');
fs.mkdirSync(OUT, { recursive: true });

// ------------------------------------------------------------------ API client
export class Api {
  constructor(label) { this.label = label; this.jwt = null; this.log = []; }
  async login(email, password) {
    D.addSecret(password);
    const r = await this.req('POST', '/api/auth/login', { email, password }, { auth: false });
    if (r.status !== 200 || !r.body?.tokens?.access_token) throw new Error(`${this.label}: login ${r.status} ${JSON.stringify(r.body?.status || r.body).slice(0, 300)}`);
    this.jwt = r.body.tokens.access_token;
    D.addSecret(this.jwt);
    this.user = r.body.user;
    return r.body;
  }
  async req(method, p, body, { auth = true, headers = {}, raw = false, timeout = 120_000 } = {}) {
    const h = { ...headers };
    if (auth && this.jwt) h.Authorization = `Bearer ${this.jwt}`;
    if (body !== undefined && !(body instanceof Uint8Array)) h['Content-Type'] = 'application/json';
    const t0 = Date.now();
    let status = 0; let text = '';
    try {
      const resp = await fetch(BASE + p, {
        method, headers: h, body: body === undefined ? undefined : (body instanceof Uint8Array ? body : JSON.stringify(body)),
        signal: AbortSignal.timeout(timeout),
      });
      status = resp.status;
      text = raw ? '' : await resp.text();
      if (raw) return { status, resp };
    } catch (e) { text = String(e); }
    let parsed = text;
    try { parsed = text ? JSON.parse(text) : null; } catch { /* not json */ }
    this.log.push({ t: t0, ms: Date.now() - t0, method, path: p, status });
    return { status, body: parsed, text };
  }
  get(p, o) { return this.req('GET', p, undefined, o); }
  post(p, b, o) { return this.req('POST', p, b === undefined ? {} : b, o); }
  put(p, b, o) { return this.req('PUT', p, b, o); }
  patch(p, b, o) { return this.req('PATCH', p, b, o); }
  del(p, o) { return this.req('DELETE', p, undefined, o); }
}

export function timeRange(minutesBack = 120, minutesAhead = 10) {
  const now = Date.now();
  return { start: new Date(now - minutesBack * 60_000).toISOString(), end: new Date(now + minutesAhead * 60_000).toISOString() };
}

export async function until(fn, { timeout = 60_000, interval = 1000, desc = 'condition' } = {}) {
  const end = Date.now() + timeout; let last;
  for (;;) {
    try { const v = await fn(); if (v) return v; last = v; } catch (e) { last = String(e); }
    if (Date.now() > end) throw new Error(`timed out (${timeout}ms) waiting for ${desc}; last: ${D.scrub(JSON.stringify(last) || '').slice(0, 300)}`);
    await sleep(interval);
  }
}

// ------------------------------------------------------------------ results
export class Results {
  constructor(meta) { this.meta = meta; this.checks = []; this.leaks = []; this.denials = []; this.knownHits = {}; this.started = Date.now(); }
  add(rec) {
    const r = { status: 'pass', problems: [], ...rec };
    const { known, rest } = splitKnown(r.problems);
    if (known.length) {
      r.problems = rest; r.known = known.map((k) => k.id);
      for (const k of known) (this.knownHits[k.id] ||= new Set()).add(`${r.role} ${r.kind} ${r.id}`);
      if (!rest.length && r.status === 'pass') r.status = 'warn';
    }
    if (r.problems.length && r.status === 'pass') r.status = 'fail';
    this.checks.push(r);
    if (this.checks.length % 10 === 0) { try { this.write(); } catch { /* best effort */ } }
    const tag = r.status === 'pass' ? '\x1b[32mPASS\x1b[0m' : r.status === 'skip' ? '\x1b[33mSKIP\x1b[0m' : r.status === 'warn' ? '\x1b[33mWARN\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
    process.stderr.write(`  [${tag}] ${r.role.padEnd(9)} ${r.kind.padEnd(5)} ${r.id}${r.problems.length ? '  — ' + r.problems.slice(0, 3).join(' | ').slice(0, 220) : ''}\n`);
    return r;
  }
  write() {
    const summary = { pass: 0, fail: 0, warn: 0, skip: 0 };
    for (const c of this.checks) summary[c.status] = (summary[c.status] || 0) + 1;
    const known = KNOWN_ISSUES.filter((k) => this.knownHits[k.id]).map((k) => ({ id: k.id, issue: k.issue, note: k.note, hits: [...this.knownHits[k.id]] }));
    const report = { ...this.meta, known, finished: new Date().toISOString(), seconds: Math.round((Date.now() - this.started) / 1000), summary, checks: this.checks, leaks: this.leaks, observed_denials: this.denials };
    fs.writeFileSync(path.join(OUT, 'report.json'), D.scrub(JSON.stringify(report, null, 2)));
    fs.writeFileSync(path.join(OUT, 'report.md'), D.scrub(renderMarkdown(report)));
    return report;
  }
}

function renderMarkdown(r) {
  const L = [];
  L.push(`# Security-update UI playbook — ${r.label} (${r.edition})`, '');
  L.push(`- commit: \`${r.sha}\`  base: ${r.base}  finished: ${r.finished} (${r.seconds}s)`);
  L.push(`- result: **${r.summary.fail} fail**, ${r.summary.warn} warn, ${r.summary.pass} pass, ${r.summary.skip} skip`, '');
  const roles = [...new Set(r.checks.map((c) => c.role))];
  const routes = r.checks.filter((c) => c.kind === 'route');
  L.push('## Coverage (routes × roles)', '', `| role | routes visited | rendered | denied (expected) | fail |`, `|---|---|---|---|---|`);
  for (const role of roles) {
    const rs = routes.filter((c) => c.role === role);
    L.push(`| ${role} | ${rs.length} | ${rs.filter((c) => c.state === 'rendered').length} | ${rs.filter((c) => c.state === 'denied' && c.status === 'pass').length} | ${rs.filter((c) => c.status === 'fail').length} |`);
  }
  L.push('', `Flows: ${r.checks.filter((c) => c.kind === 'flow').length} steps across ${roles.length} roles.`, '');
  const fails = r.checks.filter((c) => c.status === 'fail');
  L.push(`## Failures (${fails.length})`, '');
  for (const c of fails) {
    L.push(`### ${c.role} · ${c.kind} · ${c.id}`);
    if (c.url) L.push(`- url: ${c.url}`);
    for (const p of c.problems) L.push(`- ${p}`);
    if (c.screenshot) L.push(`- screenshot: ${c.screenshot}`);
    L.push('');
  }
  const warns = r.checks.filter((c) => c.status === 'warn');
  if (warns.length) {
    L.push(`## Warnings (${warns.length})`, '');
    for (const c of warns) L.push(`- ${c.role} · ${c.kind} · ${c.id}: ${c.problems.join(' | ') || c.note || ''}`);
    L.push('');
  }
  if (r.known?.length) {
    L.push(`## Known pre-existing issues (${r.known.length}) — downgraded to warnings`, '');
    for (const k of r.known) L.push(`- **${k.id}** (${k.issue}): ${k.note} — seen on ${k.hits.length} check(s), e.g. ${k.hits.slice(0, 3).join('; ')}`);
    L.push('');
  }
  L.push(`## Denied-source leak scan (${r.leaks.length} leak(s))`, '');
  for (const l of r.leaks) L.push(`- **${l.role}** ${l.where}: ${l.detail}`);
  if (!r.leaks.length) L.push('- none found');
  L.push('', '## Observed 403/404 per role (expected unless listed under Failures)', '');
  const byRole = {};
  for (const d of r.observed_denials) (byRole[d.role] ||= new Set()).add(`${d.status} ${d.method} ${d.path}`);
  for (const [role, set] of Object.entries(byRole)) L.push(`- ${role}: ${[...set].sort().join(', ')}`);
  L.push('');
  return L.join('\n');
}

// ------------------------------------------------------------------ browser sessions
let sidSeq = 0;
export class Session {
  constructor(role, results) { this.role = role; this.results = results; this.sid = `${role}-${++sidSeq}`; this.extraBodies = []; }
  get s() { return D.sess(this.sid); }
  get page() { return this.s.page; }
  async open() {
    await OPS.open({ sid: this.sid, out: path.join(OUT, 'sessions', this.role), name: this.role });
    const page = this.page;
    this.inflight = 0;
    page.on('request', () => { this.inflight += 1; });
    const done = () => { this.inflight = Math.max(0, this.inflight - 1); };
    page.on('requestfinished', done); page.on('requestfailed', done);
    // Every /api response body (any content type, SSE included), bounded, for
    // the denied-source scan. The driver only keeps JSON.
    page.on('response', (r) => {
      (async () => {
        try {
          const u = new URL(r.url());
          if (!u.pathname.startsWith('/api/')) return;
          const body = await r.text();
          this.extraBodies.push({ t: Date.now(), method: r.request().method(), path: u.pathname + u.search, status: r.status(), req: (r.request().postData() || '').slice(0, 100_000), body: body.slice(0, 2_000_000) });
        } catch { /* torn down */ }
      })();
    });
    return this;
  }
  async login(email, password) { return OPS.login({ sid: this.sid, email, password }); }
  async close() {
    // An open stream (SSE) never finishes its body read, which the driver's
    // close awaits: bound it and force the context closed.
    const s = this.s;
    await withTimeout(OPS.close({ sid: this.sid, failed: false }), 15_000, 'session close').catch(async () => {
      await s.ctx.close().catch(() => {});
    });
  }
  async settle({ quiet = 500, timeout = 20_000 } = {}) {
    const end = Date.now() + timeout; let quietSince = Date.now(); let lastN = this.s.network.length;
    while (Date.now() < end) {
      await sleep(150);
      const n = this.s.network.length;
      if (n !== lastN || this.inflight > 0) { lastN = n; quietSince = Date.now(); continue; }
      if (Date.now() - quietSince >= quiet) return true;
    }
    return false;
  }
  marks() { return { c: this.s.console.length, n: this.s.network.length, b: this.extraBodies.length, t: Date.now() }; }
  since(m) {
    return {
      console: this.s.console.slice(m.c),
      network: this.s.network.slice(m.n),
      bodies: this.extraBodies.slice(m.b),
    };
  }
  async screenshot(name) {
    const file = `${name.replace(/[^a-z0-9._-]+/gi, '_').slice(0, 120)}.png`;
    try {
      fs.mkdirSync(path.join(OUT, 'screenshots'), { recursive: true });
      await D.inject(this.page);
      const left = await D.maskSecrets(this.page);
      if (left) return null;
      const p = path.join(OUT, 'screenshots', file);
      await this.page.screenshot({ path: p, fullPage: true });
      return path.relative(OUT, p);
    } catch { return null; }
  }
  async state() {
    return this.page.evaluate(() => {
      const main = document.querySelector('main') || document.body;
      const txt = (main.innerText || '').replace(/\s+/g, ' ').trim();
      const h = [...document.querySelectorAll('h1,h2')].map((e) => e.textContent.trim()).filter(Boolean);
      return {
        url: location.pathname + location.search,
        notFound: !!document.querySelector('[data-testid="not-found-404"]'),
        denied: /Access Denied/.test(document.body.innerText) && /permission to access this page/.test(document.body.innerText),
        licensed: !!document.querySelector('[data-testid="licensed-feature-unavailable"]'),
        login: location.pathname.startsWith('/login'),
        mfa: location.pathname.startsWith('/mfa-setup'),
        blank: txt.length < 15,
        spinnerOnly: txt.length < 40 && !!document.querySelector('.animate-spin'),
        headings: h.slice(0, 4),
        breadcrumb: !!document.querySelector('nav[aria-label*="readcrumb" i], [data-testid*="breadcrumb" i]'),
        textLen: txt.length,
      };
    });
  }
}

// Console noise that is not an app defect (browser/network chatter).
const CONSOLE_IGNORE = [
  /Failed to load resource: the server responded with a status of \d{3}/, // every failed request is judged (and attributed) by the network check
  /Download the React DevTools/,
  /\[vite\]/,
  /ResizeObserver loop/,
  /favicon/,
];
export function consoleProblems(entries) {
  return entries
    .filter((c) => c.type === 'error' || c.type === 'pageerror')
    .filter((c) => !CONSOLE_IGNORE.some((rx) => rx.test(c.text)))
    .map((c) => `${c.type}: ${c.text.replace(/\s+/g, ' ').slice(0, 240)}`);
}

// ------------------------------------------------------------------ denials
// `expected` entries: {re: RegExp on "METHOD /path", status: [..], why}
export function networkProblems(role, network, expected, results) {
  const out = [];
  for (const n of network) {
    let u; try { u = new URL(n.url); } catch { continue; }
    if (!u.pathname.startsWith('/api/')) continue;
    if (n.failed) { if (!/ERR_ABORTED/.test(n.failed)) out.push(`network ${n.method} ${u.pathname} failed: ${n.failed}`); continue; }
    if (!n.status || n.status < 400) continue;
    const key = `${n.method} ${u.pathname}`;
    if (n.status === 403 || n.status === 404 || n.status === 401) results.denials.push({ role, status: n.status, method: n.method, path: normPath(u.pathname) });
    const ok = expected.find((e) => e.re.test(key) && (!e.status || e.status.includes(n.status)));
    if (!ok) out.push(`HTTP ${n.status} ${key}`);
  }
  return [...new Set(out)];
}
export function normPath(p) {
  return p.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f-]{27,}/gi, '/:id').replace(/\/[a-z]+_[0-9a-z]{26}\b/g, '/:id').replace(/\/\d{2,}\b/g, '/:n');
}

// ------------------------------------------------------------------ dead buttons
const DESTRUCTIVE = /delete|remove|revoke|disable|deactivate|reset|rotate|purge|drop|log ?out|sign ?out|uninstall|disconnect|archive|merge|deploy|publish|regenerate|clear|discard|restore|unlink|suspend|kill|stop|cancel run|terminate|approve|reject|close case|resolve|wipe|forget|leave|restart|reboot|reload|rollback|apply|require|mfa|enable|toggle|sync|reindex|rebuild|backfill|import file|upload|browse|choose file/i;

export async function probeButtons(sess, { max = 6, route }) {
  const page = sess.page;
  const labels = await page.evaluate((destr) => {
    const rx = new RegExp(destr, 'i');
    const vis = (e) => !!(e.offsetWidth || e.offsetHeight) && getComputedStyle(e).visibility !== 'hidden';
    const main = document.querySelector('main') || document.body;
    const seen = new Set(); const out = [];
    for (const b of main.querySelectorAll('button,[role=button]')) {
      if (!vis(b) || b.disabled || b.getAttribute('aria-disabled') === 'true') continue;
      if (b.closest('[role=dialog],[role=menu],[role=listbox],table tbody,[data-index]')) continue;
      if (b.getAttribute('role') === 'switch' || b.hasAttribute('aria-checked') || b.getAttribute('aria-pressed') === 'true' || b.getAttribute('aria-selected') === 'true' || /^(on|active|checked|open)$/.test(b.getAttribute('data-state') || '')) continue;
      const name = (b.getAttribute('aria-label') || b.textContent || b.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
      if (!name || name.length > 60 || rx.test(name) || seen.has(name)) continue;
      seen.add(name); out.push(name);
    }
    return out;
  }, DESTRUCTIVE.source);
  const dead = []; const clicked = []; const errors = [];
  for (const name of labels.slice(0, max)) {
    const before = page.url();
    const nBefore = sess.s.network.length;
    await page.evaluate(() => {
      window.__mut = 0;
      window.__mo?.disconnect();
      window.__mo = new MutationObserver((m) => { window.__mut += m.length; });
      window.__mo.observe(document.body, { subtree: true, childList: true, attributes: true, characterData: true });
    });
    let err = null;
    try {
      const h = await page.evaluateHandle((n) => {
        const main = document.querySelector('main') || document.body;
        return [...main.querySelectorAll('button,[role=button]')].find((b) => (b.getAttribute('aria-label') || b.textContent || b.getAttribute('title') || '').replace(/\s+/g, ' ').trim() === n) || null;
      }, name);
      const el = h.asElement();
      if (!el) continue;
      // Effects caused by hovering (tooltips) must not count as a click effect.
      await el.hover().catch(() => {});
      await sleep(250);
      await page.evaluate(() => { window.__mut = 0; });
      await el.click();
    } catch (e) { err = String(e).slice(0, 120); }
    await sleep(850);
    const effect = await page.evaluate(() => {
      const r = { mut: window.__mut, dialog: !!document.querySelector('[role=dialog],[role=alertdialog],[role=menu],[role=listbox]') };
      window.__mo?.disconnect();
      return r;
    }).catch(() => ({ mut: 1 }));
    const moved = page.url() !== before;
    const net = sess.s.network.length > nBefore;
    for (const n of sess.s.network.slice(nBefore)) {
      let pth; try { pth = new URL(n.url).pathname; } catch { continue; }
      if (pth.startsWith('/api/') && n.status >= 400 && ![401, 403, 429].includes(n.status)) /* 429: deliberate throttle */ errors.push(`click "${name}" -> HTTP ${n.status} ${n.method} ${normPath(pth)}`);
    }
    clicked.push(name);
    if (!err && !moved && !net && !effect.dialog && !effect.mut) dead.push(name);
    await page.keyboard.press('Escape').catch(() => {});
    await sleep(150);
    if (moved) {
      await OPS.goto({ sid: sess.sid, path: route }).catch(() => {});
      await sess.settle({ timeout: 10_000 });
    }
  }
  return { clicked, dead, errors: [...new Set(errors)] };
}

// ------------------------------------------------------------------ route table
// Routes + their guard, read from App.tsx (the same source check-dead-links uses).
export function routeTable() {
  const src = fs.readFileSync(path.join(WEB_ROOT, 'src/App.tsx'), 'utf8');
  const parts = src.split(/<Route\s+path="/).slice(1);
  const seen = new Map();
  for (const part of parts) {
    const p = part.slice(0, part.indexOf('"'));
    if (p === '*' || p === '/*' || seen.has(p)) continue;
    const body = part.slice(0, 1200);
    const perm = /permission="([^"]+)"/.exec(body)?.[1] || null;
    const any = /anyPermission=\{\[([^\]]+)\]\}/.exec(body)?.[1]?.match(/'([^']+)'/g)?.map((x) => x.slice(1, -1)) || null;
    const cap = /capability="([^"]+)"/.exec(body)?.[1] || null;
    const redirect = /^\s*element=\{\s*<Navigate/.test(body.slice(p.length + 1, 200));
    seen.set(p, { path: p, permission: perm, anyPermission: any, capability: cap, redirect });
  }
  return [...seen.values()];
}

// The route-table entry a concrete pathname lands on (most specific first:
// literal segments beat params).
export function matchRoute(table, pathname) {
  const segs = pathname.replace(/\/+$/, '').split('/');
  const hits = table.filter((r) => {
    const rs = r.path.replace(/\/+$/, '').split('/');
    return rs.length === segs.length && rs.every((x, i) => x.startsWith(':') || x === segs[i]);
  });
  hits.sort((a, b) => (a.path.match(/:/g) || []).length - (b.path.match(/:/g) || []).length);
  return hits[0] || null;
}

export function withTimeout(promise, ms, what) {
  let t;
  return Promise.race([promise, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`HUNG: ${what} did not finish within ${ms / 1000}s`)), ms); })]).finally(() => clearTimeout(t));
}

export function hasAccess(route, perms) {
  const has = (p) => perms.includes(p) || perms.includes('*') || perms.includes(p.split(':')[0] + ':*');
  if (route.permission && !has(route.permission)) return false;
  if (route.anyPermission && !route.anyPermission.some(has)) return false;
  return true;
}

export { D, OPS };
