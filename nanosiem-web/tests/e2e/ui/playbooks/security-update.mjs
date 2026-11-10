#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Security-update UI playbook (NAN-5085). Walks the whole web UI as four users
// and drives the primary flows, so a branch carrying security fixes
// can be compared against main: anything that works on main and breaks on the
// branch is a regression.
//
// Normally started by run-security-update.sh (throwaway e2e stack). Directly:
//   BASE_URL=http://127.0.0.1:<edge> NANO_ADMIN_EMAIL=… NANO_ADMIN_PASSWORD=… \
//   NANOSIEM_HEC_URL=http://127.0.0.1:<hec> PLAYBOOK_OUT=dir node security-update.mjs
// Optional: PLAYBOOK_ONLY=<regex on check id>, PLAYBOOK_ROLES=admin,analyst,
// PLAYBOOK_BUTTONS=0 (skip dead-button probing), HEADLESS via E2E_UI_HEADED=1.
//
// Users (created through the API as the admin):
//   admin    the bootstrap admin
//   analyst  a low-privilege analyst role (search, alerts, cases, notebooks, …)
//   helpdesk users:view + users:edit only (manages accounts, nothing else)
//   scoped   the analyst permissions, but its group is NOT granted the
//            restricted source; it must never see that source's events.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  Api, BASE, OUT, OPS, D, Results, Session, consoleProblems, networkProblems, probeButtons,
  routeTable, hasAccess, matchRoute, withTimeout, timeRange, until, sleep,
} from './lib.mjs';
import { FLOWS, typeidToUuid } from './flows.mjs';
import { splitKnown } from './known-issues.mjs';

const EDITION = process.env.PLAYBOOK_EDITION || process.env.E2E_EDITION || 'enterprise';
const ONLY = process.env.PLAYBOOK_ONLY ? new RegExp(process.env.PLAYBOOK_ONLY) : null;
const ROLES = (process.env.PLAYBOOK_ROLES || 'admin,analyst,helpdesk,scoped').split(',');
const PROBE_BUTTONS = process.env.PLAYBOOK_BUTTONS !== '0';
const PROBE_ALL = process.env.PLAYBOOK_BUTTONS === 'all'; // also probe as the analyst (slow)
const HEC = (process.env.NANOSIEM_HEC_URL || '').replace(/\/$/, '');
if (/:(3000|3002|5173|8123)$/.test(HEC)) throw new Error(`refusing NANOSIEM_HEC_URL ${HEC}: that is a dev-stack port`);
const ADMIN_EMAIL = process.env.NANO_ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.NANO_ADMIN_PASSWORD;
if (!ADMIN_EMAIL || !ADMIN_PASSWORD) throw new Error('NANO_ADMIN_EMAIL / NANO_ADMIN_PASSWORD are required');
D.addSecret(ADMIN_PASSWORD);

const TAG = `secu${crypto.randomBytes(3).toString('hex')}`;
const results = new Results({
  label: process.env.PLAYBOOK_LABEL || 'local', sha: process.env.PLAYBOOK_SHA || '', edition: EDITION, base: BASE, tag: TAG,
  started: new Date().toISOString(),
});

// ------------------------------------------------------------------ roles
const ANALYST_PERMS = [
  'search:view', 'search:execute', 'search:save', 'dashboards:view', 'dashboards:create', 'dashboards:edit',
  'alerts:view', 'alerts:acknowledge', 'alerts:close', 'alerts:assign', 'cases:view', 'cases:create', 'cases:comment',
  'cases:edit', 'notebooks:view', 'notebooks:create', 'notebooks:edit', 'detections:view', 'mitre:view',
  'prevalence:view', 'risk:view', 'lookup:view', 'enrichments:view', 'notifications:view', 'artifacts:view',
  'hunts:view', 'hunts:run', 'hunts:report', 'hunts:profile_write', 'log_sources:view',
];
const HELPDESK_PERMS = ['users:view', 'users:edit'];

// Expected denials per role: the page/API is outside the role's permissions,
// so a 403 (or a 404 for an existence-hiding endpoint) is correct behaviour.
// Anything not listed here is reported. Keep each entry justified.
const EXPECTED = {
  common: [
    { re: /^GET \/api\/auth\/refresh/, status: [401], why: 'no refresh cookie before first login' },
    { re: /^POST \/api\/auth\/refresh/, status: [401], why: 'no refresh cookie before first login' },
    { re: /^GET \/api\/auth\/me$/, status: [401], why: 'probe before login' },
  ],
  admin: [],
  analyst: [],
  helpdesk: [],
  scoped: [],
};
// Low-privilege users: any 403 is a permission boundary working; it is
// RECORDED (observed_denials in the report) and a 403 is only a failure on a
// page the role is entitled to render AND the request is the page's primary
// data (judged per route below), so gate on route access, not raw 403s.
const LOWPRIV = new Set(['analyst', 'helpdesk', 'scoped']);

// ------------------------------------------------------------------ helpers
async function step(role, id, fn, extra = {}) {
  if (ONLY && !ONLY.test(id)) return null;
  const rec = { role, kind: 'flow', id, problems: [], ...extra };
  const t0 = Date.now();
  try {
    const r = await fn(rec);
    if (r && typeof r === 'object' && r.skip) { rec.status = 'skip'; rec.note = r.skip; }
  } catch (e) {
    rec.problems.push(D.scrub(String(e && e.message ? e.message : e)).slice(0, 600));
  }
  rec.ms = Date.now() - t0;
  if (rec.problems.length && rec.sess) rec.screenshot = await rec.sess.screenshot(`${role}-${id}`);
  delete rec.sess;
  return results.add(rec);
}
const must = (cond, msg) => { if (!cond) throw new Error(msg); };
const ok2xx = (r, what) => { must(r.status >= 200 && r.status < 300, `${what} -> HTTP ${r.status} ${typeof r.body === 'string' ? r.body.slice(0, 200) : JSON.stringify(r.body).slice(0, 300)}`); return r.body; };

async function hec(token, event, sourcetype) {
  const r = await fetch(`${HEC}/services/collector/event`, {
    method: 'POST',
    headers: { Authorization: `Splunk ${token}`, 'X-Splunk-Request-Channel': crypto.randomUUID(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ event, ...(sourcetype ? { sourcetype } : {}) }),
  });
  return r.status;
}

async function searchApi(api, query, extra = {}) {
  return api.post('/api/search', {
    query, time_range: timeRange(180), limit: 200, skip_histogram: true, skip_field_stats: true, use_cache: false,
    request_id: `pb-${crypto.randomBytes(5).toString('hex')}`, ...extra,
  }, { headers: { 'x-nano-cache-bypass': '1' } });
}

// ------------------------------------------------------------------ setup (admin, API)
async function setup(admin) {
  const ctx = { TAG, EDITION, users: {}, ids: {} };
  ctx.caps = (await admin.get('/api/capabilities')).body?.capabilities || {};
  // Two routed sources: one open, one restricted to the full analyst's group.
  for (const kind of ['open', 'secret']) {
    const rk = `${TAG}_${kind}`;
    const src = ok2xx(await admin.post('/api/log-sources', {
      name: rk, description: 'security-update playbook (NAN-5085)', source_type: 'routed', parser_vrl: '',
      match_values: [rk], lifecycle_status: 'draft',
    }), `create ${kind} source`);
    const tok = ok2xx(await admin.post('/api/ingest-tokens', { name: `${rk}-tok`, source_id: src.id }), `issue ${kind} token`);
    D.addSecret(tok.token);
    ctx.ids[`${kind}Source`] = src.id; ctx[`${kind}Route`] = rk; ctx[`${kind}Token`] = tok.token; ctx.ids[`${kind}Cred`] = tok.credential?.credential_id;
  }
  ctx.openMark = `${TAG}openmark`; ctx.secretMark = `${TAG}secretmark`;
  // Vector re-reads the hashed tokens file every ~2s: wait for acceptance.
  for (const kind of ['open', 'secret']) {
    let streak = 0;
    await until(async () => { streak = (await hec(ctx[`${kind}Token`], { message: `warmup ${kind}` })) === 200 ? streak + 1 : 0; return streak >= 4; },
      { timeout: 120_000, interval: 1000, desc: `Vector accepting the ${kind} token` });
  }
  const users = ['alice', 'bob', 'carol', 'dave'];
  for (let i = 0; i < 30; i++) {
    const u = users[i % 4];
    await hec(ctx.openToken, { message: `${ctx.openMark} user=${u} action=login status=${i % 5 ? 'success' : 'failure'} src_ip=10.0.0.${i % 7} bytes=${100 + i * 13}`, user: u, src_ip: `10.0.0.${i % 7}`, bytes: 100 + i * 13 });
    await hec(ctx.secretToken, { message: `${ctx.secretMark} user=${u} action=exfil dest=203.0.113.${i % 5} bytes=${900 + i}`, user: u, bytes: 900 + i });
  }
  await until(async () => {
    const a = await searchApi(admin, `"${ctx.openMark}"`); const b = await searchApi(admin, `"${ctx.secretMark}"`);
    return (a.body?.results || []).length >= 25 && (b.body?.results || []).length >= 25;
  }, { timeout: 180_000, interval: 3000, desc: 'seed events searchable' });

  // Roles -> groups -> users.
  // Only grant what this edition's Admin holds (open core has no hunts:*, …).
  const held = new Set(admin.user?.permissions || []);
  const mkUser = async (label, wanted, { grantSecret }) => {
    const perms = held.size ? wanted.filter((p) => held.has(p)) : wanted;
    const name = `${TAG}-${label}`;
    const role = ok2xx(await admin.post('/api/roles', { name, description: 'security-update playbook (NAN-5085)', permissions: perms }), `role ${label}`);
    const group = ok2xx(await admin.post('/api/groups', { name, description: 'security-update playbook (NAN-5085)', role_ids: [role.id] }), `group ${label}`);
    const password = `Pb-${crypto.randomBytes(12).toString('hex')}!`;
    D.addSecret(password);
    const email = `${name}@e2e.nano.local`;
    const user = ok2xx(await admin.post('/api/users', { email, name, password, group_ids: [group.id] }), `user ${label}`);
    ctx.users[label] = { email, password, id: user.id, role: role.id, group: group.id, perms };
    return ctx.users[label];
  };
  ctx.users.admin = { email: ADMIN_EMAIL, password: ADMIN_PASSWORD, perms: ['*'] };
  await mkUser('analyst', ANALYST_PERMS, { grantSecret: true });
  await mkUser('helpdesk', HELPDESK_PERMS, { grantSecret: false });
  await mkUser('scoped', ANALYST_PERMS, { grantSecret: false });
  // A throwaway account for the user-management flows (reset/MFA/disable).
  await mkUser('target', ['search:view'], { grantSecret: false });

  // Restrict the secret source; grant it to the full analyst's group only.
  ok2xx(await admin.post('/api/source-scopes/restricted', { source_type: ctx.secretRoute, description: 'playbook restricted source' }), 'restrict secret source');
  ok2xx(await admin.post('/api/source-scopes/grants', { source_type: ctx.secretRoute, group_id: typeidToUuid(ctx.users.analyst.group) }), 'grant secret source to analyst group');
  return ctx;
}

// ------------------------------------------------------------------ route walk
function concretePath(route, ctx) {
  const ids = ctx.ids;
  const map = {
    '/alerts/:id': ids.alert, '/cases/:id': ids.case, '/dashboards/:id': ids.dashboard, '/rules/:id': ids.rule,
    '/rules/:id/matches': ids.rule, '/rules/editor/:id': ids.rule, '/notebooks/:id': ids.notebook,
    '/ingestion/log-sources/:id': ids.openSource, '/settings/access-control/roles/:id': ctx.users.analyst?.role,
    '/settings/access-control/groups/:id': ctx.users.analyst?.group, '/settings/access-control/api-keys/:id': ids.apiKey,
    '/observability/:tab': 'overview', '/rules/lookup-tables/:name': ids.lookup, '/rules/tuning/:id': ids.tuningProposal,
  };
  if (!route.includes(':')) return route;
  const v = map[route];
  if (!v) return null;
  return route.replace(/:[a-zA-Z]+/, encodeURIComponent(v));
}

const SKIP_ROUTES = new Set(['/login', '/setup', '/mfa-setup', '/denied', '/demo', '/d/:token', '/auth/callback/:provider', '/trace/:traceId', '/docs']);

async function walk(sessRef, role, ctx, perms) {
  const table = routeTable();
  for (const r of table) {
    const sess = sessRef.current;
    if (SKIP_ROUTES.has(r.path)) continue;
    const p = concretePath(r.path, ctx);
    const id = r.path;
    if (ONLY && !ONLY.test(id)) continue;
    if (!p) { results.add({ role, kind: 'route', id, status: 'skip', note: 'no entity id for this route' }); continue; }
    const entitled = role === 'admin' || hasAccess(r, perms);
    const m = sess.marks();
    const rec = { role, kind: 'route', id, url: p, problems: [], entitled };
    try { await withTimeout((async () => {
      await OPS.goto({ sid: sess.sid, path: p });
      await sess.settle();
      await sleep(300);
      const st = await sess.state();
      rec.final = st.url; rec.headings = st.headings;
      rec.state = st.notFound ? 'notfound' : st.denied ? 'denied' : st.licensed ? 'licensed' : st.login ? 'login' : st.blank ? 'blank' : 'rendered';
      if (st.notFound) rec.problems.push('renders NotFound (404 page)');
      if (st.login) rec.problems.push('bounced to /login (session lost)');
      if (st.blank) rec.problems.push('page rendered nothing (blank main: crash or stuck loader)');
      // Judge on where the browser landed: redirects and in-page tab gates
      // carry their own permission (e.g. /rules/:id -> editor needs detections:edit).
      const landed = matchRoute(table, st.url.split('?')[0]);
      const entitledHere = role === 'admin' || (landed ? hasAccess(landed, perms) : entitled);
      rec.landed = landed?.path;
      if (st.denied && role === 'admin') rec.problems.push('Access Denied for the Admin');
      else if (st.denied && entitledHere) rec.deniedNote = `Access Denied although the App.tsx guard of ${landed?.path || p} allows it (in-page gate?)`;
      if (!entitled && rec.state === 'rendered' && r.permission) rec.problems.push(`rendered for a role without ${r.permission || r.anyPermission}`);
      const got = sess.since(m);
      rec.problems.push(...consoleProblems(got.console));
      const expected = [...EXPECTED.common, ...(EXPECTED[role] || [])];
      // Low-privilege users on a page they cannot open: denials are the point.
      if (LOWPRIV.has(role) && (!entitled || !entitledHere || st.denied)) expected.push({ re: /./, status: [401, 403, 404], why: 'route outside role permissions' });
      const net = networkProblems(role, got.network, expected, results);
      // An entitled low-priv page making a side request it may not make is
      // reported as a warning (the page still works), not a failure.
      const hard = net.filter((x) => !(LOWPRIV.has(role) && / 403 /.test(` ${x} `)));
      const soft = net.filter((x) => !hard.includes(x));
      rec.problems.push(...hard);
      if (soft.length) rec.warnings = soft;
      if (PROBE_BUTTONS && rec.state === 'rendered' && (role === 'admin' || (PROBE_ALL && role === 'analyst'))) {
        const pr = await probeButtons(sess, { route: p });
        rec.buttons = pr.clicked.length;
        if (pr.dead.length) rec.dead = pr.dead;
        rec.problems.push(...pr.errors);
        const after = sess.since(m);
        rec.problems.push(...consoleProblems(after.console).filter((x) => !rec.problems.includes(x)));
      }
      if (role === 'scoped') scanLeaks(sess, ctx, `route ${p}`, m);
    })(), 120_000, `route ${p}`); } catch (e) {
      rec.problems.push(`${/HUNG/.test(String(e)) ? '' : 'navigation error: '}${String(e.message || e).slice(0, 300)}`);
      if (/HUNG|detached Frame|Target closed|Session closed|Execution context was destroyed/.test(String(e))) {
        // The renderer is wedged: a fresh browser context and sign-in, then carry on.
        rec.screenshot = null;
        await sessRef.reopen().catch(() => {});
        results.add(rec);
        continue;
      }
    }
    if (!rec.problems.length && (rec.dead?.length || rec.warnings?.length || rec.deniedNote)) {
      rec.status = 'warn';
      rec.problems = [];
      rec.note = [rec.deniedNote || '', rec.dead?.length ? `no visible effect on click: ${rec.dead.join(', ')}` : '', rec.warnings?.length ? `side requests denied: ${rec.warnings.join(', ')}` : ''].filter(Boolean).join(' | ');
    } else if (rec.dead?.length) {
      rec.note = `no visible effect on click: ${rec.dead.join(', ')}`;
    }
    if (splitKnown(rec.problems).rest.length) rec.screenshot = await sess.screenshot(`${role}-route-${p}`);
    const added = results.add(rec);
    if (added.status === 'warn') process.stderr.write(`           ${rec.note}\n`);
  }
}

// ------------------------------------------------------------------ denied-source leak scan
export function scanLeaks(sess, ctx, where, mark) {
  const needles = [ctx.secretMark, ctx.secretRoute];
  const got = sess.since(mark || { c: 0, n: 0, b: 0 });
  for (const b of got.bodies) {
    // The log-source/ingest config surfaces legitimately name the source to a
    // log_sources:view holder; events, SQL, cases, notebooks, reports, recon must not.
    if (/^\/api\/(log-sources|ingest-tokens|source-scopes|vector|sources)/.test(b.path)) continue;
    // Rule definitions name the source in their query text (config the
    // analyst may read); only event content counts as a leak there.
    const ns = /^\/api\/rules/.test(b.path) ? [ctx.secretMark] : needles;
    // The mixed case (open + restricted alert) is visible by design (a case is
    // visible when at least one linked alert is); report it, don't call it a leak.
    if ([ctx.ids.case, ctx.ids.notebook].some((id) => id && b.path.includes(id))) {
      if (needles.some((n) => b.body.includes(n))) ctx.ids.mixedCaseExposure = (ctx.ids.mixedCaseExposure || new Set()).add(b.path.split('?')[0].replace(/[a-z]+_[0-9a-z]{26}/g, ':id'));
      continue;
    }
    for (const n of ns) {
      // A response that echoes the caller's own request (query text, history) is not a leak.
      if (b.body.includes(n) && !(b.req || '').includes(n) && !/^\/api\/search\/history/.test(b.path)) {
        const leak = { role: sess.role, where: `${where} :: ${b.method} ${b.path.split('?')[0]}`, detail: `response contains ${n === ctx.secretMark ? 'a denied-source event marker' : 'the denied source_type'}` };
        if (!results.leaks.some((l) => l.where === leak.where && l.detail === leak.detail)) results.leaks.push(leak);
      }
    }
  }
}

// ------------------------------------------------------------------ main
async function main() {
  const admin = new Api('admin');
  await admin.login(ADMIN_EMAIL, ADMIN_PASSWORD);
  let ctx;
  try {
    ctx = await setup(admin);
    results.add({ role: 'admin', kind: 'flow', id: 'setup/seed+users+scope', note: `sources ${ctx.openRoute}, ${ctx.secretRoute}` });
  } catch (e) {
    results.add({ role: 'admin', kind: 'flow', id: 'setup/seed+users+scope', problems: [D.scrub(String(e.message || e))] });
    results.write();
    process.exitCode = 1;
    return;
  }
  ctx.adminApi = admin;
  ctx.step = step; ctx.must = must; ctx.ok2xx = ok2xx; ctx.searchApi = searchApi; ctx.hec = hec; ctx.results = results; ctx.scanLeaks = scanLeaks;

  const runRole = async (role) => {
    const u = ctx.users[role];
    const api = new Api(role);
    await api.login(u.email, u.password);
    let sess = await new Session(role, results).open();
    const sessRef = {
      get current() { return sess; },
      async reopen() {
        await withTimeout(sess.close(), 15_000, 'close hung session').catch(() => {});
        sess = await new Session(role, results).open();
        await sess.login(u.email, u.password);
      },
    };
    try {
      await step(role, 'login/ui', async (rec) => { rec.sess = sess; const url = await sess.login(u.email, u.password); must(!/\/login|\/mfa-setup/.test(url), `after login at ${url}`); });
      const perms = role === 'admin' ? ['*'] : (api.user?.permissions || u.perms);
      for (const f of FLOWS) {
        if (f.roles && !f.roles.includes(role)) continue;
        if (f.edition && f.edition !== EDITION) continue;
        try {
          await withTimeout(f.run({ ...ctx, role, api, sess, perms }), 20 * 60_000, `flow ${f.name}`);
        } catch (e) {
          results.add({ role, kind: 'flow', id: `${f.name}/watchdog`, problems: [String(e.message || e).slice(0, 300)] });
          await sessRef.reopen().catch(() => {});
          sess = sessRef.current;
        }
      }
      if (process.env.PLAYBOOK_WALK !== '0') await walk(sessRef, role, ctx, perms);
      sess = sessRef.current;
      if (role === 'scoped') {
        scanLeaks(sess, ctx, 'whole session', { c: 0, n: 0, b: 0 });
        if (ctx.ids.mixedCaseExposure?.size) results.add({ role, kind: 'flow', id: 'scope/mixed-case-exposure', status: 'warn', note: `a case linking an open AND a restricted alert is visible by design; these responses carry restricted-source content: ${[...ctx.ids.mixedCaseExposure].join(', ')}` });
      }
    } finally {
      await sess.close();
    }
  };
  // Admin first (its flows create the alert / case / notebook / dashboard /
  // report the other users then open), then the three others in parallel.
  if (ROLES.includes('admin')) await runRole('admin');
  // Whatever the admin walk touched, the other users must still be able to sign in.
  // Fresh token: the run's first one may have expired during a long walk.
  await admin.login(ADMIN_EMAIL, ADMIN_PASSWORD).catch(() => {});
  const mfa = await admin.put('/api/settings/mfa-required', { required: false });
  if (mfa.status >= 300) results.add({ role: 'admin', kind: 'flow', id: 'setup/mfa-required-off', problems: [`could not turn global MFA off: ${mfa.status}`] });
  await Promise.all(ROLES.filter((r) => r !== 'admin').map((r) => runRole(r).catch((e) => {
    results.add({ role: r, kind: 'flow', id: 'session', problems: [D.scrub(String(e.message || e))] });
  })));
  // Admin-only post flows (cleanup of the real-time rule etc.) run inside FLOWS.
}

// Interrupted (Ctrl-C, CI timeout): keep what was checked so far.
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.once(sig, () => { try { results.add({ role: 'admin', kind: 'flow', id: 'interrupted', problems: [`run interrupted by ${sig}`] }); results.write(); } catch { /* */ } process.exit(130); });
}

main()
  .catch((e) => { results.add({ role: 'admin', kind: 'flow', id: 'fatal', problems: [D.scrub(String(e.stack || e))] }); })
  .finally(async () => {
    const rep = results.write();
    await D.closeBrowser();
    process.stderr.write(`\nreport: ${path.join(OUT, 'report.md')}  (${rep.summary.fail} fail, ${rep.summary.warn} warn, ${rep.summary.pass} pass, leaks ${rep.leaks.length})\n`);
    process.exit(rep.summary.fail || rep.leaks.length ? 1 : 0);
  });
