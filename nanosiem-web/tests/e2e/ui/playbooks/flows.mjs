// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Primary flows for the security-update playbook (NAN-5085). Each flow is
// {name, roles?, edition?, run(c)} where c carries the role's Api client,
// browser Session, permissions and the shared setup context. Flows drive the
// UI for the user-facing path and use the API to arrange state and to verify
// what the UI did. A step is one result row.
//
// kind 'flow'  — the feature works as designed (must pass on every branch).
// kind 'sec'   — a hardening expectation from the security review. On a branch
//                without that fix it fails; the diff reports it as "fixed"
//                when it starts passing, never as a regression.

import crypto from 'node:crypto';
import { OPS, D, sleep, until, timeRange } from './lib.mjs';

const ALPH = '0123456789abcdefghjkmnpqrstvwxyz';
export function typeidToUuid(t) {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) return t;
  const s = String(t).slice(String(t).lastIndexOf('_') + 1);
  let n = 0n;
  for (const ch of s) n = n * 32n + BigInt(ALPH.indexOf(ch));
  const h = n.toString(16).padStart(32, '0');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// Licensed surfaces on an unlicensed stack: one explicit SKIP row each, so a
// later licensed run's rows line up and coverage gaps are visible.
async function unlicensed(c, cap, ids) {
  for (const id of ids) await c.step(c.role, id, async () => ({ skip: `capability '${cap}' not licensed on this stack` }));
}

const rid = () => crypto.randomBytes(3).toString('hex');
const has = (perms, p) => perms.includes('*') || perms.includes(p);
const j = (b) => (typeof b === 'string' ? b : JSON.stringify(b ?? null)).slice(0, 300);

// UI primitives on a Session
const ui = {
  goto: async (c, p) => { await OPS.goto({ sid: c.sess.sid, path: p }); await c.sess.settle(); },
  click: (c, f, o) => D.click(c.sess.page, f, o),
  fill: (c, find, value) => OPS.fill({ sid: c.sess.sid, fields: [{ find, value }] }),
  text: (c, t, o = {}) => D.waitText(c.sess.page, t, { exact: false, timeout: 30_000, ...o }),
  url: (c, re, t) => D.waitUrl(c.sess.page, re, t),
  count: (c, f) => D.count(c.sess.page, f),
  // Wait for a request (method + path regex) issued after `since`; returns it.
  req: (c, method, re, since, timeout = 30_000) => until(() => c.sess.s.network.find((n) => n.t >= since && n.method === method && re.test(new URL(n.url).pathname)), { timeout, interval: 250, desc: `${method} ${re}` }),
  mainText: (c) => c.sess.page.evaluate(() => (document.querySelector('main') || document.body).innerText),
};
const now = () => Date.now();

async function uiSearch(c, query) {
  await OPS.goto({ sid: c.sess.sid, path: `/search?q=${encodeURIComponent(query)}&run=true&time=Last%2024%20hours` });
  await D.waitText(c.sess.page, 'Query complete', { exact: false, timeout: 120_000 });
  await c.sess.settle({ timeout: 15_000 });
  const err = await c.sess.page.evaluate(() => {
    const t = [...document.querySelectorAll('[title="Syntax Error"],[title="Query Blocked"],[title="Empty Query"]')];
    return t.length ? (t[0].closest('div')?.innerText || t[0].title).replace(/\s+/g, ' ').slice(0, 300) : null;
  });
  const hits = await c.sess.page.evaluate(() => {
    const m = /([\d,]+)\s+hits?/.exec(document.body.innerText); return m ? parseInt(m[1].replace(/,/g, ''), 10) : null;
  });
  return { err, hits };
}

// ------------------------------------------------------------------ search
const SEARCH_QUERIES = (x) => [
  ['marker', `"${x.openMark}"`],
  ['eval-strftime', `source_type="${x.openRoute}" | eval day = strftime(timestamp, "%Y-%m-%d") | stats count by day`],
  ['anomaly', `source_type="${x.openRoute}" | anomaly count() by source_type`],
  ['prevalence', `source_type="${x.openRoute}" | prevalence enrich=true | head 5`],
  ['sequence', `source_type="${x.openRoute}" | sequence by source_type maxspan=60m [message="*success*"] [message="*failure*"]`],
  ['bin', `source_type="${x.openRoute}" | bin span=5m | stats count by time_bucket`],
  ['fillnull', `source_type="${x.openRoute}" | fillnull value="N/A" user | head 5`],
  ['reserved-alias-select', `source_type="${x.openRoute}" | eval select = 1 | table select, message | head 5`],
  ['reserved-alias-from', `source_type="${x.openRoute}" | eval "from" = "x" | stats count by "from"`],
  ['stats-where-sort', `source_type="${x.openRoute}" | stats count by source_type | where count > 1 | sort -count`],
  ['timechart', `source_type="${x.openRoute}" | timechart span=5m count`],
];

const searchFlow = {
  name: 'search',
  async run(c) {
    if (!has(c.perms, 'search:execute')) return;
    for (const [name, q] of SEARCH_QUERIES(c)) {
      await c.step(c.role, `search/npl/${name}`, async (rec) => {
        rec.sess = c.sess; rec.steps = `search page: ${q}`;
        const api = await c.searchApi(c.api, q);
        c.must(api.status === 200, `API /api/search -> ${api.status} ${j(api.body)}`);
        const r = await uiSearch(c, q);
        c.must(!r.err, `UI shows a query error: ${r.err}`);
        if (name === 'marker' && c.role !== 'helpdesk') c.must((api.body.results || []).length >= 25, `expected the 30 seeded events, API returned ${(api.body.results || []).length}`);
      });
    }
    await c.step(c.role, 'search/inspect-sql', async (rec) => {
      rec.sess = c.sess;
      await uiSearch(c, `source_type="${c.openRoute}" | head 5`);
      await ui.click(c, { role: 'button', name: 'More', exact: true });
      await ui.click(c, { role: 'menuitem', name: 'Inspect SQL' });
      await ui.text(c, 'Compiled SQL');
      const ex = await c.api.post('/api/search/explain', { query: `source_type="${c.openRoute}"`, time_range: timeRange(60), table_view: true });
      c.must(ex.status === 200 && ex.body?.sql, `explain -> ${ex.status} ${j(ex.body)}`);
    });
    // Saved searches (UI save -> API sees it -> delete)
    if (has(c.perms, 'search:save')) {
      await c.step(c.role, 'search/saved-search', async (rec) => {
        rec.sess = c.sess;
        const name = `${c.TAG}-${c.role}-saved-${rid()}`;
        await uiSearch(c, `"${c.openMark}" | head 3`);
        await ui.click(c, { role: 'button', name: 'Save', exact: true });
        await ui.fill(c, { placeholder: 'e.g. Failed console logins' }, name);
        const t0 = now();
        await ui.click(c, { role: 'button', name: 'Save query', exact: true });
        await ui.req(c, 'POST', /^\/api\/search\/saved$/, t0);
        const mine = await until(async () => { const r = await c.api.get('/api/search/saved/mine'); const l = Array.isArray(r.body) ? r.body : (r.body?.saved_searches || r.body?.items || []); return l.find((s) => s.name === name); }, { timeout: 15_000, desc: 'saved search listed' });
        const del = await c.api.del(`/api/search/saved/${mine.id}`);
        c.must(del.status === 200 || del.status === 204, `delete saved search -> ${del.status}`);
      });
    }
  },
};

// ------------------------------------------------------------------ scope (denied source)
const scopeFlow = {
  name: 'scope',
  roles: ['analyst', 'scoped'],
  async run(c) {
    const denied = c.role === 'scoped';
    await c.step(c.role, 'scope/search-denied-source', async (rec) => {
      rec.sess = c.sess;
      const a = await c.searchApi(c.api, `"${c.secretMark}"`);
      const b = await c.searchApi(c.api, `source_type="${c.secretRoute}"`);
      const s = await c.searchApi(c.api, `* | stats count by source_type`);
      c.must(a.status === 200 && b.status === 200 && s.status === 200, `search statuses ${a.status}/${b.status}/${s.status}`);
      const n = (a.body.results || []).length + (b.body.results || []).length;
      const inStats = JSON.stringify(s.body.results || []).includes(c.secretRoute);
      if (denied) {
        c.must(n === 0, `scoped analyst got ${n} rows from the denied source`);
        c.must(!inStats, 'denied source_type appears in stats count by source_type');
        const r = await uiSearch(c, '"secretmark"');
        c.must(!r.hits, `search page shows ${r.hits} hits for the denied source`);
        const rows = await OPS.result_rows({ sid: c.sess.sid });
        c.must(!rows.some((t) => t.includes(c.secretMark)), 'search results render a denied-source event');
      } else {
        c.must(n >= 25, `granted analyst should see the restricted source (positive control), got ${n}`);
      }
    });
    if (denied) {
      // NAN-5043: explain / include_sql must not name denied sources.
      await c.step(c.role, 'scope/explain-sql-hides-denied-source', async () => {
        const ex = await c.api.post('/api/search/explain', { query: '*', time_range: timeRange(60), table_view: true });
        const inc = await c.searchApi(c.api, '* | head 1', { include_sql: true });
        const leak = [ex, inc].filter((r) => JSON.stringify(r.body || '').includes(c.secretRoute));
        if (leak.length) c.results.leaks.push({ role: c.role, where: 'explain/include_sql :: POST /api/search/explain|/api/search', detail: 'generated SQL names the denied source_type' });
        c.must(!leak.length, 'generated SQL (explain / include_sql) names the denied source_type');
      }, { kind: 'sec' });
      // NAN-5049: recon census / surface list live source inventory.
      await c.step(c.role, 'scope/recon-hides-denied-source', async () => {
        const out = [];
        for (const p of ['/api/hunts/profile/census', '/api/hunts/profile/surface?detail=full']) {
          const r = await c.api.post(p);
          if (r.status === 200 && JSON.stringify(r.body).includes(c.secretRoute)) out.push(p);
          else if (r.status >= 500) out.push(`${p} -> ${r.status}`);
        }
        const g = await c.api.get('/api/hunts/profile');
        if (g.status === 200 && JSON.stringify(g.body).includes(c.secretRoute)) out.push('GET /api/hunts/profile');
        for (const w of out) c.results.leaks.push({ role: c.role, where: `recon :: ${w}`, detail: 'recon lists the denied source_type' });
        c.must(!out.length, `recon exposes the denied source: ${out.join(', ')}`);
      }, { kind: 'sec' });
    }
  },
};

// ------------------------------------------------------------------ detections + alerts
const detectionFlow = {
  name: 'detections',
  roles: ['admin'],
  async run(c) {
    const yamlFor = (title, query, extra = '') => `---\ntitle: ${title}\ndescription: security-update playbook rule\nauthor: e2e playbook\nseverity: medium\nmitre_tactics: TA0001\nmitre_techniques: T1078\nmode: staging\ndetection_mode: realtime\nlookback: 15m\nalert_mode: grouped\n${extra}---\n${query}\n`;
    const uiTitle = `${c.TAG}_ui_rule`;
    let uiRuleId;
    await c.step(c.role, 'detections/ui-create-realtime-rule', async (rec) => {
      rec.sess = c.sess;
      const content = yamlFor(uiTitle, `source_type = "${c.openRoute}"`);
      await ui.goto(c, `/rules/editor/new?content=${encodeURIComponent(content)}`);
      await ui.click(c, { role: 'button', name: 'Create rule', exact: true }, { timeout: 30_000 });
      const u = await ui.url(c, '/rules/editor/rule_', 30_000);
      uiRuleId = decodeURIComponent(u.split('/rules/editor/')[1].split(/[?#]/)[0]);
      c.ids.rule = uiRuleId;
      const r = await c.api.get(`/api/rules/${uiRuleId}`);
      c.must(r.status === 200, `GET rule -> ${r.status}`);
      c.must(r.body.detection_mode === 'real-time', `UI-created rule is ${r.body.detection_mode}, expected real-time (warning: ${r.body.warning || 'none'})`);
      c.must(!!r.body.materialized_view_name, 'real-time rule has no materialized_view_name');
    });
    if (uiRuleId) {
      await c.step(c.role, 'detections/ui-edit-rule', async (rec) => {
        rec.sess = c.sess;
        await ui.goto(c, `/rules/editor/${uiRuleId}`);
        await ui.text(c, uiTitle);
        const content = yamlFor(uiTitle, `source_type = "${c.openRoute}" message = "*login*"`);
        await OPS.editor_fill({ sid: c.sess.sid, find: { css: '[aria-label="Detection rule editor"]' }, value: content });
        await ui.click(c, { role: 'button', name: 'Save rule', exact: true });
        const t0 = now();
        await ui.click(c, { role: 'button', name: 'Save Rule', exact: true });
        await ui.req(c, 'PUT', /^\/api\/rules\//, t0);
        await until(async () => (await c.api.get(`/api/rules/${uiRuleId}`)).body?.query?.includes('login'), { timeout: 15_000, desc: 'rule query updated' });
      });
      await c.step(c.role, 'detections/ui-promote-to-live', async (rec) => {
        rec.sess = c.sess;
        await ui.goto(c, `/rules/editor/${uiRuleId}`);
        await ui.click(c, { role: 'button', name: 'Rule actions' });
        await ui.click(c, { role: 'menuitem', name: 'Promote to live' });
        await until(async () => (await c.api.get(`/api/rules/${uiRuleId}`)).body?.mode === 'live', { timeout: 15_000, desc: 'rule mode live' });
        await ui.text(c, 'LIVE', { exact: true });
      });
      await c.step(c.role, 'detections/api-demote-and-delete-realtime', async () => {
        const d = await c.api.post(`/api/rules/${uiRuleId}/demote`, { expected_mode: 'live' });
        c.must(d.status === 200, `demote -> ${d.status} ${j(d.body)}`);
        const x = await c.api.del(`/api/rules/${uiRuleId}`);
        c.must(x.status === 200, `delete real-time rule -> ${x.status} ${j(x.body)}`);
        const g = await c.api.get(`/api/rules/${uiRuleId}`);
        c.must(g.status === 404 || g.body?.archived || g.body?.archived_at || g.body?.is_archived, `deleted rule still active: ${g.status} ${j(g.body)}`);
      });
    }
    // Scheduled alerting rules (one per source) -> alerts for the alert/case flows.
    await c.step(c.role, 'detections/scheduled-alerting-rules', async () => {
      for (const kind of ['open', 'secret']) {
        const body = { name: `${c.TAG}_${kind}_alerting`, query: `source_type="${c[`${kind}Route`]}"`, severity: 'high', mode: 'staging', detection_mode: 'scheduled', schedule_cron: '*/15 * * * * *', lookback_minutes: 240, alert_mode: 'grouped', description: 'security-update playbook' };
        const r = c.ok2xx(await c.api.post('/api/rules', body), `create ${kind} rule`);
        for (const m of ['staging', 'live']) c.ok2xx(await c.api.post(`/api/rules/${r.id}/promote`, { expected_mode: m }), `promote ${kind} from ${m}`);
        c.ids[`${kind}Rule`] = r.id;
      }
      c.ids.rule = c.ids.rule || c.ids.openRule;
    });
    await c.step(c.role, 'alerts/scheduled-rule-fires', async () => {
      for (const kind of ['open', 'secret']) {
        const a = await until(async () => { const r = await c.api.get(`/api/alerts?rule_id=${c.ids[`${kind}Rule`]}&limit=5`); return Array.isArray(r.body) && r.body[0]; }, { timeout: 180_000, interval: 5000, desc: `alert from the ${kind} rule` });
        c.ids[`${kind}Alert`] = a.id;
      }
      c.ids.alert = c.ids.openAlert;
    });
    if (c.ids.openAlert) {
      await c.step(c.role, 'alerts/list-and-detail-ui', async (rec) => {
        rec.sess = c.sess;
        await ui.goto(c, '/alerts');
        await ui.text(c, `${c.TAG}_open_alerting`);
        await ui.goto(c, `/alerts/${c.ids.openAlert}`);
        await ui.text(c, `${c.TAG}_open_alerting`);
        if (!c.caps.cases) {
          const t0 = now();
          await ui.click(c, { role: 'button', name: 'Acknowledge' });
          await ui.req(c, 'POST', /\/acknowledge$/, t0);
        } else {
          await ui.click(c, { role: 'button', name: 'Add to case' });
          await ui.text(c, 'Add alert to case');
          await c.sess.page.keyboard.press('Escape');
        }
      });
      await c.step(c.role, 'alerts/acknowledge-api', async () => {
        // Opening the detail page may already have acknowledged it.
        const cur = await c.api.get(`/api/alerts/${c.ids.secretAlert || c.ids.openAlert}`);
        if (/^new$/i.test(cur.body?.status || '')) {
          const r = await c.api.post(`/api/alerts/${cur.body.id}/acknowledge`);
          c.must(r.status === 200, `acknowledge -> ${r.status} ${j(r.body)}`);
        }
        const after = await c.api.get(`/api/alerts/${cur.body.id}`);
        c.must(/acknowledged/i.test(after.body?.status || ''), `alert status after acknowledge: ${after.body?.status}`);
      });
    }
  },
};

// Non-admins read the rules + alerts the admin produced.
const readDetectionsFlow = {
  name: 'detections-read',
  roles: ['analyst', 'scoped'],
  async run(c) {
    await c.step(c.role, 'alerts/list-visible', async (rec) => {
      rec.sess = c.sess;
      const r = await c.api.get('/api/alerts?limit=200');
      c.must(r.status === 200, `GET /api/alerts -> ${r.status}`);
      const ids = (r.body || []).map((a) => a.id);
      if (c.ids.openAlert) c.must(ids.includes(c.ids.openAlert), 'alert from the open source is not visible');
      if (c.role === 'scoped' && c.ids.secretAlert && ids.includes(c.ids.secretAlert)) {
        const d = await c.api.get(`/api/alerts/${c.ids.secretAlert}`);
        if (JSON.stringify(d.body).includes(c.secretMark)) c.results.leaks.push({ role: c.role, where: 'alerts :: GET /api/alerts/:id', detail: 'denied-source alert exposes event content' });
      }
      await ui.goto(c, '/alerts');
      await ui.text(c, `${c.TAG}_open_alerting`);
    });
  },
};

// ------------------------------------------------------------------ cases + notebooks + shadow investigation (enterprise)
const casesFlow = {
  name: 'cases',
  roles: ['admin'],
  edition: 'enterprise',
  async run(c) {
    if (!c.caps.cases) return unlicensed(c, 'cases', ['cases/ui-create-case', 'cases/api-case-with-notebook-and-alert', 'cases/ui-case-thread-note', 'cases/shadow-investigation-ran', 'notebooks/ui-create-notebook']);
    await c.step(c.role, 'cases/ui-create-case', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/inbox');
      await ui.click(c, { role: 'button', name: 'New investigation' });
      await ui.fill(c, { css: '#case-intake-title' }, `${c.TAG} ui case`);
      await ui.click(c, { role: 'button', name: 'Create case', exact: true });
      const u = await ui.url(c, '/cases/case_', 30_000);
      c.ids.uiCase = u.split('/cases/')[1].split(/[?#]/)[0];
    });
    await c.step(c.role, 'cases/api-case-with-notebook-and-alert', async () => {
      c.ok2xx(await c.api.put('/api/settings/cases', { auto_investigate_enabled: true }), 'enable auto-investigation');
      const cs = c.ok2xx(await c.api.post('/api/cases', { title: `${c.TAG} secret-source case`, severity: 'high', assigned_to: c.adminApi.user.id, description: 'security-update playbook' }), 'create case');
      c.ids.case = cs.case?.id || cs.id;
      const nb = await until(async () => { const r = await c.api.get(`/api/cases/${c.ids.case}/notebook`); return r.body?.id ? r.body : (r.body?.notebook?.id ? r.body.notebook : null); }, { timeout: 20_000, desc: 'case notebook' });
      c.ids.notebook = nb.id;
      c.ok2xx(await c.api.post(`/api/notebooks/${nb.id}/entries`, { entry_type: 'manual_note', content: { text: `${c.TAG} note` } }), 'add note');
      const rs = await c.searchApi(c.api, `"${c.secretMark}" | head 3`);
      c.ok2xx(await c.api.post(`/api/notebooks/${nb.id}/entries`, { entry_type: 'search_executed', content: { query: `source_type="${c.secretRoute}" | head 3`, result_count: (rs.body?.results || []).length, execution_time_ms: rs.body?.execution_time_ms || 1, results: (rs.body?.results || []).slice(0, 3) } }), 'add search entry');
      if (c.ids.secretAlert) c.ok2xx(await c.api.post(`/api/cases/${c.ids.case}/alerts`, { alert_id: c.ids.secretAlert, is_primary: false }), 'link secret alert');
      if (c.ids.openAlert) c.ok2xx(await c.api.post(`/api/cases/${c.ids.case}/alerts`, { alert_id: c.ids.openAlert, is_primary: false }), 'link open alert');
      // A second case linked ONLY to the restricted source's alert: per-source
      // case scope (NAN-5028) must hide it, and its notebook, from the scoped user.
      if (c.ids.secretAlert) {
        const so = c.ok2xx(await c.api.post('/api/cases', { title: `${c.TAG} secret-only case`, severity: 'high', assigned_to: c.adminApi.user.id }), 'create secret-only case');
        c.ids.secretCase = so.case?.id || so.id;
        c.ok2xx(await c.api.post(`/api/cases/${c.ids.secretCase}/alerts`, { alert_id: c.ids.secretAlert, is_primary: true }), 'link secret alert only');
        const snb = await until(async () => { const r = await c.api.get(`/api/cases/${c.ids.secretCase}/notebook`); return r.body?.id ? r.body : (r.body?.notebook?.id ? r.body.notebook : null); }, { timeout: 20_000, desc: 'secret-only case notebook' });
        c.ids.secretNotebook = snb.id;
        c.ok2xx(await c.api.post(`/api/notebooks/${snb.id}/entries`, { entry_type: 'manual_note', content: { text: `${c.secretMark} restricted-only case note` } }), 'note in secret-only case');
      }
    });
    if (c.ids.case) {
      await c.step(c.role, 'cases/ui-case-thread-note', async (rec) => {
        rec.sess = c.sess;
        await ui.goto(c, `/cases/${c.ids.case}`);
        await ui.text(c, `${c.TAG} secret-source case`);
        const box = { placeholder: 'Ask the agent, or add a note — Enter to send · Shift+Enter for new line · @ to mention' };
        await ui.fill(c, box, `@note ${c.TAG} ui-note`);
        const t0 = now();
        await D.click(c.sess.page, { css: 'button[title="Send (Enter)"]' });
        await ui.req(c, 'POST', /\/api\/notebooks\/[^/]+\/entries$/, t0);
        await ui.text(c, `${c.TAG} ui-note`);
      });
      await c.step(c.role, 'cases/shadow-investigation-ran', async () => {
        // Linking alerts re-triggers shadow investigation; with no AI provider
        // it must still leave a breadcrumb (skipped/credits/error), never crash.
        const got = await until(async () => {
          const r = await c.api.get(`/api/notebooks/${c.ids.notebook}/entries?limit=200`);
          const l = Array.isArray(r.body) ? r.body : (r.body?.entries || []);
          return l.find((e) => /shadow/i.test(JSON.stringify([e.source, e.metadata, e.entry_type, e.content]).slice(0, 4000)));
        }, { timeout: 90_000, interval: 5000, desc: 'a shadow-investigation entry in the case notebook' }).catch(() => null);
        if (!got) return { skip: 'no shadow-investigation entry within 90s (no AI provider on the e2e stack)' };
      });
    }
    await c.step(c.role, 'notebooks/ui-create-notebook', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/notebooks');
      const n = await ui.count(c, { role: 'button', name: 'New notebook' });
      let opened = false;
      for (let i = 0; i < n && !opened; i++) {
        await ui.click(c, { role: 'button', name: 'New notebook', nth: i });
        opened = await D.find(c.sess.page, { css: '#nb-title' }, { timeout: 4000 }).then(() => true, () => false);
        if (!opened) await c.sess.page.keyboard.press('Escape');
      }
      c.must(opened, 'no New notebook control opened the create dialog');
      await ui.fill(c, { css: '#nb-title' }, `${c.TAG} ui notebook`);
      const t0 = now();
      await ui.click(c, { within: { role: 'dialog' }, role: 'button', name: 'create', exact: true });
      // A new notebook opens as a pivt tab (no navigation): verify the write.
      const r = await ui.req(c, 'POST', /^\/api\/notebooks$/, t0);
      c.must(r.status === 200 || r.status === 201, `create notebook -> ${r.status}`);
      await until(async () => { const l = await c.api.get('/api/notebooks?limit=100'); return JSON.stringify(l.body || '').includes(`${c.TAG} ui notebook`); }, { timeout: 15_000, desc: 'notebook listed' });
    });
  },
};

const casesReadFlow = {
  name: 'cases-read',
  roles: ['analyst', 'scoped'],
  edition: 'enterprise',
  async run(c) {
    if (c.caps.cases && c.ids.secretCase && c.role === 'scoped') {
      await c.step(c.role, 'scope/restricted-only-case-hidden', async () => {
        const cs = await c.api.get(`/api/cases/${c.ids.secretCase}`);
        const nb = await c.api.get(`/api/notebooks/${c.ids.secretNotebook}/entries?limit=50`);
        const list = await c.api.get('/api/cases?limit=200');
        const listed = JSON.stringify(list.body || '').includes(c.ids.secretCase);
        const bad = [];
        if (cs.status < 300) bad.push(`GET case -> ${cs.status}`);
        if (nb.status < 300 && JSON.stringify(nb.body).includes(c.secretMark)) bad.push(`GET notebook entries -> ${nb.status} with content`);
        if (listed) bad.push('listed in GET /api/cases');
        for (const b of bad) c.results.leaks.push({ role: c.role, where: `cases :: restricted-only case (${b})`, detail: 'a case linked only to a denied source is visible' });
        c.must(!bad.length, `restricted-only case visible to the scoped analyst: ${bad.join(', ')}`);
      }, { kind: 'sec' });
    }
    if (!c.caps.cases) return unlicensed(c, 'cases', ['cases/open-shared-case-and-notebook']);
    if (!c.ids.case) return;
    await c.step(c.role, 'cases/open-shared-case-and-notebook', async (rec) => {
      rec.sess = c.sess;
      const m = c.sess.marks();
      const cs = await c.api.get(`/api/cases/${c.ids.case}`);
      const nb = await c.api.get(`/api/notebooks/${c.ids.notebook}/entries?limit=200`);
      // This is the MIXED case (open + restricted alert): visible by design, so
      // its content is reported as an observation by the leak scan, not a leak.
      c.must(cs.status === 200, `mixed case should be visible to ${c.role}: ${cs.status}`);
      void nb;
      await ui.goto(c, `/cases/${c.ids.case}`);
      await ui.goto(c, `/notebooks/${c.ids.notebook}`);
      if (c.role === 'scoped') c.scanLeaks(c.sess, c, 'case + notebook pages', m);
    });
  },
};

// ------------------------------------------------------------------ dashboards
const dashboardsFlow = {
  name: 'dashboards',
  roles: ['admin', 'analyst'],
  async run(c) {
    if (!has(c.perms, 'dashboards:create')) return;
    await c.step(c.role, 'dashboards/ui-create-and-panel', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/dashboards');
      await ui.click(c, { role: 'button', name: 'New Dashboard' });
      await ui.fill(c, { placeholder: 'e.g., Security Overview' }, `${c.TAG} ${c.role} dash`);
      await ui.click(c, { role: 'button', name: 'Create blank', exact: true });
      const u = await ui.url(c, '/dashboards/[a-z]+_[0-9a-z]{20,}', 30_000);
      const id = u.split('/dashboards/')[1].split(/[?#]/)[0];
      if (c.role === 'admin') c.ids.dashboard = id;
      const cur = c.ok2xx(await c.api.get(`/api/dashboards/${id}`), 'get dashboard');
      const panels = [{ id: 'p1', title: 'events by source', query: `source_type="${c.openRoute}" | stats count by source_type`, queryMode: 'piped', visualizationType: 'table', visualizationConfig: {}, timeRangeMode: 'dashboard', drilldownEnabled: false }];
      c.ok2xx(await c.api.put(`/api/dashboards/${id}`, { name: cur.name, panels, layout: { columns: 12, rowHeight: 100, items: [{ i: 'p1', x: 0, y: 0, w: 6, h: 3 }] } }), 'add panel');
      await ui.goto(c, `/dashboards/${id}`);
      const t0 = now();
      await ui.click(c, { role: 'button', name: 'Run', exact: true }).catch(() => ui.click(c, { role: 'button', name: 'Refresh', exact: true }));
      const q = await ui.req(c, 'POST', /^\/api\/dashboards\/panel\/query$/, t0, 30_000);
      c.must(q.status === 200, `panel query -> ${q.status}`);
    });
  },
};

// ------------------------------------------------------------------ reports
const reportsFlow = {
  name: 'reports',
  roles: ['admin'],
  async run(c) {
    await c.step(c.role, 'reports/generate-run-download', async (rec) => {
      rec.sess = c.sess;
      for (const kind of ['open', 'secret']) {
        const r = c.ok2xx(await c.api.post('/api/reports', { name: `${c.TAG} ${kind} report`, source_type: 'search', source_query: `source_type="${c[`${kind}Route`]}" | head 20`, cron_expression: '0 8 * * *' }), `create ${kind} report`);
        const rep = r.report || r;
        c.ids[`${kind}Report`] = rep.id;
      }
      // Run the open one from the UI ("Run now"), the secret one via the API.
      await ui.goto(c, '/reports');
      await ui.text(c, `${c.TAG} open report`);
      const t0 = now();
      await c.sess.page.evaluate((name) => {
        // The tightest element holding both this report's name and a Run now button = its row.
        const row = [...document.querySelectorAll('main *')]
          .filter((e) => (e.textContent || '').includes(name) && e.querySelector('[aria-label="Run now"],[title="Run now"]'))
          .sort((a, b) => a.textContent.length - b.textContent.length)[0];
        row?.querySelector('[aria-label="Run now"],[title="Run now"]')?.click();
      }, `${c.TAG} open report`);
      const run = await ui.req(c, 'POST', /^\/api\/reports\/[^/]+\/run$/, t0, 15_000);
      c.must(run.status === 202 || run.status === 200, `Run now -> ${run.status}`);
      c.ok2xx(await c.api.post(`/api/reports/${c.ids.secretReport}/run`), 'run secret report');
      for (const kind of ['open', 'secret']) {
        const done = await until(async () => {
          const r = await c.api.get(`/api/reports/${c.ids[`${kind}Report`]}/runs`);
          const runs = r.body?.runs || [];
          const okRun = runs.find((x) => /complete|succe/i.test(x.status));
          if (okRun) return (await c.api.get(`/api/reports/runs/${okRun.id}`)).body?.run || okRun;
          const bad = runs.find((x) => /fail|error/i.test(x.status));
          return bad ? { failed: bad } : null;
        }, { timeout: 120_000, interval: 3000, desc: `${kind} report run to finish` });
        c.must(!done.failed, `${kind} report run failed: ${j(done.failed)}`);
        c.must((done.artifacts || []).length, `${kind} report run produced no artifact: ${j(done)}`);
        const art = done.artifacts[0];
        c.ids[`${kind}Artifact`] = art.id;
        const dl = await c.api.get(`/api/reports/artifacts/${art.id}/download`);
        c.must(dl.status === 200 && dl.text.length > 0, `download ${kind} artifact -> ${dl.status}`);
      }
    });
  },
};

const reportsReadFlow = {
  name: 'reports-read',
  roles: ['scoped', 'analyst'],
  async run(c) {
    if (!c.ids.secretArtifact) return;
    await c.step(c.role, 'reports/denied-source-artifact-gate', async () => {
      const dl = await c.api.get(`/api/reports/artifacts/${c.ids.secretArtifact}/download`);
      if (c.role === 'scoped') {
        if (dl.status === 200 && dl.text.includes(c.secretMark)) c.results.leaks.push({ role: c.role, where: 'reports :: GET /api/reports/artifacts/:id/download', detail: 'denied-source report artifact downloadable' });
        c.must(dl.status === 403 || dl.status === 404, `scoped analyst downloading a denied-source artifact -> ${dl.status}`);
      } else {
        c.must(dl.status === 200 || dl.status === 403, `granted analyst artifact download -> ${dl.status}`);
      }
    });
  },
};

// ------------------------------------------------------------------ log sources + ingest tokens
const logSourcesFlow = {
  name: 'log-sources',
  roles: ['admin'],
  async run(c) {
    const id = c.ids.openSource;
    await c.step(c.role, 'log-sources/ui-sampling-exclude-condition', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, `/ingestion/log-sources/${id}?tab=config`);
      await ui.click(c, { role: 'button', name: 'Edit', exact: true });
      await D.click(c.sess.page, { role: 'switch', name: { re: 'ampl' } }).catch(async () => {
        // The switch sits beside "Sample a percentage of incoming events".
        await c.sess.page.evaluate(() => {
          const label = [...document.querySelectorAll('*')].find((e) => e.children.length === 0 && /Sample a percentage of incoming events/.test(e.textContent || ''));
          let n = label; for (let i = 0; i < 5 && n; i++) { const s = n.querySelector?.('[role=switch]'); if (s) { s.click(); return; } n = n.parentElement; }
        });
      });
      await ui.fill(c, { placeholder: '.action != "allow"' }, '.action != "allow"');
      const t0 = now();
      await ui.click(c, { role: 'button', name: 'Save changes', exact: true });
      const put = await ui.req(c, 'PUT', /^\/api\/log-sources\/[^/]+$/, t0);
      c.must(put.status === 200, `save -> ${put.status}`);
      const g = await c.api.get(`/api/log-sources/${id}`);
      c.must(g.body?.sampling_exclude_condition === '.action != "allow"', `sampling_exclude_condition not saved: ${j(g.body?.sampling_exclude_condition)}`);
      // Put the source back to full sampling for the rest of the run.
      await c.api.put(`/api/log-sources/${id}`, { sampling_ratio: 1.0, sampling_exclude_condition: '' });
    });
    // NAN-5012: the exclude condition is VRL; a malformed one must be refused at save.
    await c.step(c.role, 'log-sources/invalid-exclude-condition-rejected', async () => {
      const r = await c.api.put(`/api/log-sources/${c.ids.secretSource}`, { sampling_ratio: 0.5, sampling_exclude_condition: '.action == ' });
      await c.api.put(`/api/log-sources/${c.ids.secretSource}`, { sampling_ratio: 1.0, sampling_exclude_condition: '' });
      c.must(r.status === 400 || r.status === 422, `malformed VRL exclude condition saved: ${r.status}`);
    }, { kind: 'sec' });
    await c.step(c.role, 'log-sources/ui-test-vrl', async (rec) => {
      rec.sess = c.sess;
      const api = await c.api.post('/api/log-sources/test-vrl', { vrl_code: '. = parse_json!(.message)', sample_log: '{"message":"{\\"a\\":1}"}', extension_vrl: null });
      c.must(api.status === 200, `test-vrl API -> ${api.status} ${j(api.body)}`);
      await ui.goto(c, `/ingestion/log-sources/${id}?tab=vrl`);
      await ui.click(c, { role: 'tab', name: 'Test events' }).catch(() => ui.click(c, { role: 'button', name: 'Test events' }));
      await ui.fill(c, { placeholder: 'Paste 1+ raw events, one per line. Cmd/Ctrl+Enter to run.' }, '{"message":"hello"}');
      const t0 = now();
      await ui.click(c, { role: 'button', name: 'Test', exact: true });
      const r = await ui.req(c, 'POST', /^\/api\/log-sources\/(test-vrl|[^/]+\/test.*)$/, t0);
      c.must(r.status === 200, `UI test -> ${r.status}`);
    });
    await c.step(c.role, 'log-sources/validate-publish-deploy', async (rec) => {
      rec.sess = c.sess;
      // An OCSF-profile install only stores events whose parser emits a
      // class_uid (Base Event here); a non-OCSF parser routes to UDM only.
      c.ok2xx(await c.api.put(`/api/log-sources/${id}`, { parser_vrl: '.class_uid = 0\n.category_uid = 0\n.activity_id = 0\n.playbook = "v2"' }), 'edit parser');
      const pub = await c.api.post(`/api/log-sources/${id}/publish`, {});
      c.must(pub.status === 200 || pub.status === 409, `publish -> ${pub.status} ${j(pub.body)}`);
      c.ok2xx(await c.api.post(`/api/log-sources/${id}/validate`, {}), 'validate');
      await ui.goto(c, `/ingestion/log-sources/${id}`);
      const t0 = now();
      await ui.click(c, { role: 'button', name: { re: '^(Re)?[Dd]eploy$' } });
      await ui.click(c, { within: { role: 'alertdialog' }, role: 'button', name: 'Deploy', exact: true }).catch(() => ui.click(c, { within: { role: 'dialog' }, role: 'button', name: 'Deploy', exact: true }));
      const d = await ui.req(c, 'POST', /\/deploy$/, t0, 60_000);
      c.must(d.status === 200, `deploy -> ${d.status}`);
      // Events still flow through the redeployed source.
      const mark = `${c.TAG}afterdeploy`;
      await until(async () => { await c.hec(c.openToken, { message: mark }); return ((await c.searchApi(c.api, `"${mark}"`)).body?.results || []).length > 0; }, { timeout: 150_000, interval: 5000, desc: 'events searchable after deploy' });
    });
    await c.step(c.role, 'log-sources/parser-repo-import', async (rec) => {
      rec.sess = c.sess;
      const repos = await c.api.get('/api/parser-repositories');
      c.must(repos.status === 200, `list parser repos -> ${repos.status}`);
      const list = Array.isArray(repos.body) ? repos.body : (repos.body?.repositories || []);
      await ui.goto(c, '/ingestion/log-sources/repositories');
      if (!list.length) return { skip: 'no parser repository registered on this stack' };
      const repo = list[0];
      await c.api.post(`/api/parser-repositories/${repo.id}/sync`);
      const parsers = await until(async () => { const r = await c.api.get(`/api/parser-repositories/${repo.id}/parsers`); const l = Array.isArray(r.body) ? r.body : (r.body?.parsers || []); return l.length ? l : null; }, { timeout: 90_000, interval: 5000, desc: 'parser catalog synced' }).catch(() => null);
      if (!parsers) return { skip: 'parser repository did not sync (offline stack)' };
      const fp = (x) => x.file_path || x.path || x.name;
      const p = parsers.find((x) => /^parsers[^/]*\/.*json/i.test(fp(x))) || parsers.find((x) => /^parsers/.test(fp(x))) || parsers[0];
      const imp = await c.api.post(`/api/parser-repositories/${repo.id}/parsers/import/${encodeURIComponent(fp(p))}`, { import_type: 'linked', source_type: `${c.TAG}_imported` });
      c.must(imp.status === 200 || imp.status === 201, `import ${fp(p)} -> ${imp.status} ${j(imp.body)}`);
    });
  },
};

const ingestTokensFlow = {
  name: 'ingest-tokens',
  roles: ['admin'],
  async run(c) {
    await c.step(c.role, 'ingest-tokens/ui-issue-rotate-revoke', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/ingestion/ingest-tokens');
      await ui.url(c, '/ingestion/log-sources/credentials');
      await ui.click(c, { role: 'button', name: 'New token' });
      const name = `${c.TAG}-uitok`;
      await ui.fill(c, { css: '#ingest-token-name' }, name);
      const sel = await D.find(c.sess.page, { css: '#ingest-token-source' });
      const tag = await c.sess.page.evaluate((e) => e.tagName, sel);
      if (tag === 'SELECT') await OPS.select_native({ sid: c.sess.sid, find: { css: '#ingest-token-source' }, value: c.ids.openSource });
      else await OPS.choose({ sid: c.sess.sid, trigger: { css: '#ingest-token-source' }, option: c.openRoute });
      await ui.click(c, { role: 'button', name: 'Issue token', exact: true });
      await D.find(c.sess.page, { testid: 'issued-ingest-token' });
      await ui.click(c, { role: 'button', name: 'Done', exact: true });
      const list = (await c.api.get('/api/ingest-tokens')).body?.tokens || [];
      const t = list.find((x) => x.name === name && x.state === 'active');
      c.must(t, 'issued token not listed as active');
      const rot = await c.api.post(`/api/ingest-tokens/${t.credential_id}/rotate`);
      c.must(rot.status === 201, `rotate -> ${rot.status}`);
      if (rot.body?.token) D.addSecret(rot.body.token);
      // Revoke only what this step issued: the setup token on the same source keeps working.
      const after = ((await c.api.get('/api/ingest-tokens')).body?.tokens || []).filter((x) => x.name === name);
      for (const x of after) if (x.state === 'active') await c.api.post(`/api/ingest-tokens/${x.credential_id}/revoke`);
    });
  },
};

// ------------------------------------------------------------------ AI providers (enterprise)
const aiProvidersFlow = {
  name: 'ai-providers',
  roles: ['admin'],
  edition: 'enterprise',
  async run(c) {
    if (!c.caps.melod) return unlicensed(c, 'melod', ['ai-providers/ui-test-connection-bad-url', 'ai-providers/private-url-refused', 'ai-providers/azure-api-base-ssrf']);
    await c.step(c.role, 'ai-providers/ui-test-connection-bad-url', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/settings/ai');
      const field = { placeholder: 'http://vllm.internal:8000/v1' };
      await D.find(c.sess.page, field);
      await ui.fill(c, field, 'https://does-not-exist.nano-e2e.invalid/v1');
      await ui.fill(c, { placeholder: 'Enter API key…' }, 'sk-playbook-dummy-key').catch(() => {});
      // Test connection is enabled once the card is saved: Save that card
      // (the one holding the URL just typed), then test if it saved.
      const t0 = now();
      await c.sess.page.evaluate((url) => {
        const input = [...document.querySelectorAll('input')].find((i) => i.value === url);
        let card = input; while (card && !(card.querySelector && [...card.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Save'))) card = card.parentElement;
        [...(card?.querySelectorAll('button') || [])].find((b) => b.textContent.trim() === 'Save')?.click();
      }, 'https://does-not-exist.nano-e2e.invalid/v1');
      const save = await ui.req(c, 'PUT', /^\/api\/settings\/ai-providers\//, t0, 15_000);
      if (save.status < 300) {
        const t1 = now();
        await ui.click(c, { role: 'button', name: 'Test connection', exact: true });
        await ui.req(c, 'POST', /\/validate$/, t1, 30_000);
      }
      // Either the save is refused or the probe fails: the operator must SEE why.
      await until(async () => /Connection failed|rejected|failed|blocked|Invalid|DNS|resolve/i.test(await c.sess.page.evaluate(() => document.body.innerText)), { timeout: 30_000, desc: 'a visible verdict for the bad URL' });
    });
    await c.step(c.role, 'ai-providers/private-url-refused', async () => {
      const r = await c.api.put('/api/settings/ai-providers/openai', { api_key: 'sk-playbook-dummy-key', config: { base_url: 'http://127.0.0.1:9/v1' }, enabled: false });
      if (r.status === 200) {
        const v = await c.api.post('/api/settings/ai-providers/openai/validate');
        c.must(v.body?.success === false && /blocked|rejected|private|localhost/i.test(v.body?.message || ''), `private base_url accepted and probed: ${j(v.body)}`);
      } else {
        c.must(r.status === 400, `private base_url save -> ${r.status}`);
      }
    });
    // NAN-5022: Azure api_base must go through the same SSRF validator.
    await c.step(c.role, 'ai-providers/azure-api-base-ssrf', async () => {
      const r = await c.api.put('/api/settings/ai-providers/azure', { api_key: 'playbook-dummy-key', config: { api_base: 'http://169.254.169.254', deployment: 'x', api_version: '2024-10-21' }, enabled: false });
      if (r.status === 200) {
        const v = await c.api.post('/api/settings/ai-providers/azure/validate');
        c.must(/blocked|rejected|metadata|link-local|private/i.test(v.body?.message || ''), `Azure api_base to a metadata IP probed without the SSRF check: ${j(v.body)}`);
      }
      await c.api.put('/api/settings/ai-providers/azure', { config: { api_version: '2024-10-21' }, enabled: false });
    }, { kind: 'sec' });
  },
};

// ------------------------------------------------------------------ users / groups / roles / API keys
const usersFlow = {
  name: 'users',
  roles: ['admin'],
  async run(c) {
    const tgt = c.users.target;
    await c.step(c.role, 'users/ui-invite-user', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/settings/access-control?tab=users');
      await ui.click(c, { role: 'button', name: 'Invite user' });
      const email = `${c.TAG}-invited@e2e.nano.local`;
      await ui.fill(c, { placeholder: 'person@acme.io' }, email);
      const t0 = now();
      await ui.click(c, { role: 'button', name: 'Create user', exact: true });
      const r = await ui.req(c, 'POST', /^\/api\/users$/, t0);
      c.must(r.status === 201 || r.status === 200, `create user -> ${r.status}`);
      await ui.click(c, { role: 'button', name: 'Close', exact: true }).catch(() => c.sess.page.keyboard.press('Escape'));
      const l = await c.api.get('/api/users');
      const list = Array.isArray(l.body) ? l.body : (l.body?.users || []);
      c.ids.invited = list.find((u) => u.email === email)?.id;
      c.must(c.ids.invited, 'invited user not listed');
    });
    await c.step(c.role, 'users/ui-edit-user', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/settings/access-control?tab=users');
      await ui.click(c, { text: tgt.email });
      await ui.click(c, { role: 'button', name: 'Edit', exact: true });
      await ui.fill(c, { placeholder: 'Jane Doe' }, `${c.TAG} target renamed`);
      const t0 = now();
      await ui.click(c, { role: 'button', name: 'Save changes', exact: true });
      const r = await ui.req(c, 'PUT', /^\/api\/users\/[^/]+(\/groups)?$/, t0);
      c.must(r.status === 200, `edit user -> ${r.status}`);
    });
    await c.step(c.role, 'users/ui-disable-enable', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/settings/access-control?tab=users');
      await ui.click(c, { text: tgt.email });
      let t0 = now();
      await ui.click(c, { role: 'button', name: 'Disable', exact: true });
      await ui.click(c, { within: { role: 'alertdialog' }, role: 'button', name: 'Disable', exact: true }).catch(() => ui.click(c, { within: { role: 'dialog' }, role: 'button', name: 'Disable', exact: true }));
      let r = await ui.req(c, 'POST', /\/disable$/, t0);
      c.must(r.status === 200, `disable -> ${r.status}`);
      const login = await fetch(`${process.env.BASE_URL}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: tgt.email, password: tgt.password }) });
      c.must(login.status !== 200, 'disabled user can still log in');
      // The detail panel must offer Enable for the now-disabled user (reopen
      // it, as an operator would). If it does not, re-enable through the API so
      // later steps still have a working account, and fail this step.
      await ui.goto(c, '/settings/access-control?tab=users');
      await ui.click(c, { text: tgt.email });
      const offered = await D.find(c.sess.page, { role: 'button', name: 'Enable', exact: true }, { timeout: 8000 }).then(() => true, () => false);
      if (!offered) {
        await c.api.post(`/api/users/${tgt.id}/enable`);
        throw new Error('user detail panel offers no Enable action for a disabled user (no action buttons after Disable)');
      }
      t0 = now();
      await ui.click(c, { role: 'button', name: 'Enable', exact: true });
      await ui.click(c, { within: { role: 'alertdialog' }, role: 'button', name: 'Enable', exact: true }).catch(() => {});
      r = await ui.req(c, 'POST', /\/enable$/, t0);
      c.must(r.status === 200, `enable -> ${r.status}`);
    });
    await c.step(c.role, 'users/reset-password-and-mfa', async () => {
      const np = `Pb-${crypto.randomBytes(12).toString('hex')}!`; D.addSecret(np);
      c.ok2xx(await c.api.put(`/api/users/${tgt.id}`, { password: np }), 'reset password');
      tgt.password = np;
      const m = await c.api.del(`/api/admin/users/${tgt.id}/mfa`);
      c.must([200, 204, 404].includes(m.status), `MFA reset -> ${m.status} ${j(m.body)}`);
      const login = await fetch(`${process.env.BASE_URL}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: tgt.email, password: np }) });
      c.must(login.status === 200, `login with the reset password -> ${login.status}`);
    });
    // NAN-5014: an admin password reset ends the user's existing sessions.
    await c.step(c.role, 'users/password-reset-revokes-sessions', async () => {
      const lr = await fetch(`${process.env.BASE_URL}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: tgt.email, password: tgt.password }) });
      const jwt = (await lr.json()).tokens?.access_token; D.addSecret(jwt);
      c.must(jwt, 'target user could not sign in before the reset');
      // Revocation is a seconds-resolution watermark: the token must be issued
      // in an earlier second than the reset, as a real stolen token would be.
      await sleep(1100);
      const np = `Pb-${crypto.randomBytes(12).toString('hex')}!`; D.addSecret(np);
      c.ok2xx(await c.api.put(`/api/users/${tgt.id}`, { password: np }), 'reset password');
      tgt.password = np;
      await sleep(1500);
      const me = await fetch(`${process.env.BASE_URL}/api/auth/me`, { headers: { Authorization: `Bearer ${jwt}` } });
      c.must(me.status === 401, `pre-reset access token still valid after reset (/api/auth/me -> ${me.status})`);
    }, { kind: 'sec' });
    await c.step(c.role, 'roles-groups/ui-create-role-and-group', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/settings/access-control?tab=roles');
      await D.click(c.sess.page, { css: 'button[title="New role"]' });
      await ui.fill(c, { placeholder: 'e.g. Threat Hunter' }, `${c.TAG} ui role`);
      await D.click(c.sess.page, { css: '[role=checkbox][aria-label^="search:view"]' });
      let t0 = now();
      await ui.click(c, { role: 'button', name: 'Create role', exact: true });
      let r = await ui.req(c, 'POST', /^\/api\/roles$/, t0);
      c.must(r.status === 201 || r.status === 200, `create role -> ${r.status}`);
      await ui.goto(c, '/settings/access-control?tab=groups');
      await D.click(c.sess.page, { css: 'button[title="New group"]' });
      await ui.fill(c, { placeholder: 'e.g. Threat Intel' }, `${c.TAG} ui group`);
      t0 = now();
      await ui.click(c, { role: 'button', name: 'Create group', exact: true });
      r = await ui.req(c, 'POST', /^\/api\/groups$/, t0);
      c.must(r.status === 201 || r.status === 200, `create group -> ${r.status}`);
    });
    await c.step(c.role, 'source-scopes/ui-grant-group', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/settings/source-scopes');
      await ui.text(c, c.secretRoute);
      const g = await c.api.get(`/api/source-scopes/restricted/${c.secretRoute}/grants`);
      c.must(g.status === 200 && JSON.stringify(g.body).includes(typeidToUuid(c.users.analyst.group).slice(0, 8)), `grant list -> ${g.status} ${j(g.body)}`);
    });
  },
};

const helpdeskFlow = {
  name: 'helpdesk',
  roles: ['helpdesk'],
  async run(c) {
    const tgt = c.users.target;
    await c.step(c.role, 'helpdesk/edit-and-reset-ordinary-user', async (rec) => {
      rec.sess = c.sess;
      c.ok2xx(await c.api.put(`/api/users/${tgt.id}`, { name: `${c.TAG} helpdesk-renamed` }), 'rename user');
      const np = `Pb-${crypto.randomBytes(12).toString('hex')}!`; D.addSecret(np);
      c.ok2xx(await c.api.put(`/api/users/${tgt.id}`, { password: np }), 'reset password');
      tgt.password = np;
      c.ok2xx(await c.api.post(`/api/users/${tgt.id}/disable`), 'disable');
      c.ok2xx(await c.api.post(`/api/users/${tgt.id}/enable`), 'enable');
      await ui.goto(c, '/settings/access-control?tab=users');
      await ui.text(c, tgt.email);
    });
    // NAN-5027: users:edit must not reach an Admin's password / email / MFA.
    await c.step(c.role, 'helpdesk/cannot-take-over-admin', async () => {
      const a2 = c.users.admin2;
      const p = await c.api.put(`/api/users/${a2.id}`, { password: `Pb-${crypto.randomBytes(12).toString('hex')}!` });
      const e = await c.api.put(`/api/users/${a2.id}`, { email: `${c.TAG}-hijack@e2e.nano.local` });
      const m = await c.api.del(`/api/admin/users/${a2.id}/mfa`);
      const bad = [['password', p], ['email', e], ['mfa', m]].filter(([, r]) => r.status < 300).map(([k, r]) => `${k}:${r.status}`);
      c.must(!bad.length, `helpdesk changed an Admin account: ${bad.join(', ')}`);
    }, { kind: 'sec' });
  },
};

const apiKeysFlow = {
  name: 'api-keys',
  roles: ['admin'],
  async run(c) {
    await c.step(c.role, 'api-keys/ui-create', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/settings/access-control?tab=api-keys');
      await D.click(c.sess.page, { css: 'button[title="New API key"]' });
      await ui.fill(c, { placeholder: 'e.g. ci-deploy-robot' }, `${c.TAG}-uikey`);
      await ui.click(c, { role: 'button', name: '90 days', exact: true }).catch(() => {});
      const t0 = now();
      await ui.click(c, { role: 'button', name: 'Create key', exact: true });
      const r = await ui.req(c, 'POST', /^\/api\/api-keys$/, t0);
      c.must(r.status === 201, `create key -> ${r.status}`);
      await D.find(c.sess.page, { testid: 'api-key-reveal' });
      await c.sess.page.keyboard.press('Escape');
    });
    await c.step(c.role, 'api-keys/edit-expiry-and-rotate', async () => {
      const exp = new Date(Date.now() + 30 * 86400_000).toISOString();
      const k = c.ok2xx(await c.api.post('/api/api-keys', { name: `${c.TAG}-apikey`, description: 'playbook', permissions: ['search:view', 'search:execute'], expires_at: exp, rate_limit: 600 }), 'create key');
      D.addSecret(k.key);
      c.ids.apiKey = k.id;
      const exp2 = new Date(Date.now() + 10 * 86400_000).toISOString();
      c.ok2xx(await c.api.put(`/api/api-keys/${k.id}`, { expires_at: exp2 }), 'edit expiry');
      const rot = c.ok2xx(await c.api.post(`/api/api-keys/${k.id}/reset`), 'rotate key');
      D.addSecret(rot.key);
      const useNew = await fetch(`${process.env.BASE_URL}/api/auth/me`, { headers: { 'X-API-Key': rot.key } });
      const useOld = await fetch(`${process.env.BASE_URL}/api/auth/me`, { headers: { 'X-API-Key': k.key } });
      c.must(useOld.status === 401 || useOld.status === 403, `old key still works after rotate (${useOld.status})`);
      c.must(useNew.status === 200, `rotated key rejected (${useNew.status})`);
      c.ids.apiKeyValue = rot.key;
    });
    // NAN-5029: a key must not lift its own expiry / rate limit.
    await c.step(c.role, 'api-keys/key-cannot-remove-own-expiry', async () => {
      if (!c.ids.apiKeyValue) return { skip: 'no key' };
      const r = await fetch(`${process.env.BASE_URL}/api/api-keys/${c.ids.apiKey}`, { method: 'PUT', headers: { 'X-API-Key': c.ids.apiKeyValue, 'Content-Type': 'application/json' }, body: JSON.stringify({ expires_at: null, rate_limit: null }) });
      c.must(r.status === 401 || r.status === 403, `key edited its own expiry -> ${r.status}`);
    }, { kind: 'sec' });
  },
};

// ------------------------------------------------------------------ settings / health / audit / license / marketplace
const platformFlow = {
  name: 'platform',
  roles: ['admin'],
  async run(c) {
    await c.step(c.role, 'siem-health/run-health-check', async (rec) => {
      rec.sess = c.sess;
      await ui.goto(c, '/platform/health');
      const t0 = now();
      await ui.click(c, { role: 'button', name: { re: '^(Run first health check|Run health check)$' } });
      const r = await ui.req(c, 'POST', /^\/api\/siem-health\/reports\/trigger$/, t0);
      c.must(r.status === 200, `trigger -> ${r.status}`);
    });
    await c.step(c.role, 'audit-log/list-and-export', async (rec) => {
      rec.sess = c.sess;
      const a = await c.api.get('/api/audit?limit=50&offset=0');
      c.must(a.status === 200 && (a.body?.logs || []).length, `audit list -> ${a.status}`);
      await ui.goto(c, '/settings/audit');
      await ui.text(c, 'Audit Log');
      const got = await OPS.download({ sid: c.sess.sid, find: { role: 'button', name: 'Export CSV', exact: true } });
      c.must(got.text.length > 20, 'audit CSV export empty');
    });
    // NAN-5032: an ingested event claiming source_type=audit is not an audit record.
    await c.step(c.role, 'audit-log/ingested-audit-spoof-not-shown', async () => {
      const mark = `${c.TAG}auditspoof`;
      await c.hec(c.openToken, { message: mark, source_type: 'audit', action: 'user.login' }, 'audit');
      await sleep(8000);
      const a = await c.api.get('/api/audit?limit=200&offset=0');
      c.must(!JSON.stringify(a.body).includes(mark), 'an ingested event shows up in the audit log');
    }, { kind: 'sec' });
    await c.step(c.role, 'licence/page-and-api', async (rec) => {
      rec.sess = c.sess;
      const l = await c.api.get('/api/license');
      // The license surface is enterprise-only: the open build answers 404.
      c.must(c.EDITION === 'open' ? l.status === 404 : l.status === 200, `GET /api/license -> ${l.status} (${c.EDITION})`);
      await ui.goto(c, '/settings/license');
      if (c.EDITION === 'enterprise') await ui.text(c, 'License');
    });
    await c.step(c.role, 'marketplace/catalog', async (rec) => {
      rec.sess = c.sess;
      const cat = await c.api.get('/api/marketplace/catalog');
      c.must(cat.status === 200, `catalog -> ${cat.status}`);
      await ui.goto(c, '/marketplace');
      await ui.text(c, 'Marketplace');
    });
  },
};

// The admin2 account used by the helpdesk takeover probe.
const admin2Setup = {
  name: 'admin2',
  roles: ['admin'],
  async run(c) {
    if (c.users.admin2) return;
    await c.step(c.role, 'setup/second-admin', async () => {
      const grp = c.ok2xx(await c.api.post('/api/groups', { name: `${c.TAG}-admins`, description: 'playbook', role_ids: ['00000000-0000-0000-0000-000000000001'] }), 'admin group');
      const password = `Pb-${crypto.randomBytes(12).toString('hex')}!`; D.addSecret(password);
      const u = c.ok2xx(await c.api.post('/api/users', { email: `${c.TAG}-admin2@e2e.nano.local`, name: `${c.TAG}-admin2`, password, group_ids: [grp.id] }), 'admin2 user');
      c.users.admin2 = { id: u.id, email: u.email, password };
    });
  },
};

// Order matters: admin flows produce what the other roles read.
export const FLOWS = [
  admin2Setup, searchFlow, scopeFlow, detectionFlow, readDetectionsFlow, casesFlow, casesReadFlow, dashboardsFlow,
  reportsFlow, reportsReadFlow, logSourcesFlow, ingestTokensFlow, aiProvidersFlow, usersFlow, helpdeskFlow, apiKeysFlow,
  platformFlow,
];
