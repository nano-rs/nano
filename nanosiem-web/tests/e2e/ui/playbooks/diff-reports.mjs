#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Diff two security-update playbook reports (NAN-5085).
//   node diff-reports.mjs <baseline/report.json> <candidate/report.json> [--json]
// Regression   = a check that passes on the baseline and fails on the candidate
//                (or a denied-source leak present only on the candidate).
// Pre-existing = fails on both.  Fixed = fails on baseline only.
// Checks are matched by role + kind + id. Exit 1 when there is a regression.

import fs from 'node:fs';

const [a, b] = process.argv.slice(2).filter((x) => !x.startsWith('--'));
if (!a || !b) { console.error('usage: diff-reports.mjs <baseline.json> <candidate.json> [--json]'); process.exit(2); }
const base = JSON.parse(fs.readFileSync(a, 'utf8'));
const cand = JSON.parse(fs.readFileSync(b, 'utf8'));
const key = (c) => `${c.role}|${c.kind}|${c.id}`;
const bmap = new Map(base.checks.map((c) => [key(c), c]));
const cmap = new Map(cand.checks.map((c) => [key(c), c]));
const bad = (c) => c && c.status === 'fail';
const regressions = []; const unstable = []; const preexisting = []; const fixed = []; const missing = []; const added = [];
for (const [k, c] of cmap) {
  const o = bmap.get(k);
  if (!o) { if (bad(c)) added.push(c); continue; }
  if (bad(c) && !bad(o)) regressions.push({ c, o });
  else if (bad(c) && bad(o)) {
    // Same check failing on both: still a regression if the candidate has NEW problems.
    // Entity ids and run tags differ per run: compare problems with them masked.
    const norm = (p) => p.replace(/\b[a-z]+_[0-9a-z]{26}\b/g, ':id').replace(/[0-9a-f]{8}-[0-9a-f-]{27}/gi, ':uuid').replace(/\bsecu[0-9a-f]{6}/g, ':tag');
    const seen = new Set(o.problems.map(norm));
    const fresh = c.problems.filter((p) => !seen.has(norm(p)));
    if (fresh.length) regressions.push({ c, o, fresh });
    preexisting.push(c);
  } else if (!bad(c) && bad(o)) fixed.push(c);
}
for (const [k, o] of bmap) if (!cmap.has(k) && o.status !== 'skip') missing.push(o);
// A check whose new problems are ALL the API-unavailability signature (502 at
// the edge, session lost) is the intermittent span panic (NAN-5102), which hits
// random routes on every branch: listed separately, never hidden.
const UNAVAILABLE = /HTTP 502 |status of 502|Bad Gateway|bounced to \/login/;
for (let i = regressions.length - 1; i >= 0; i--) {
  const { c, fresh } = regressions[i];
  if ((fresh || c.problems).every((p) => UNAVAILABLE.test(p))) unstable.push(...regressions.splice(i, 1));
}
// Heuristic signals (dead buttons, denied side requests) never fail a check;
// list the ones only the candidate shows so a reviewer can look.
const noteSet = (n) => new Set(String(n || '').split(/ \| |, /).map((x) => x.replace(/\bsecu[0-9a-f]{6}/g, ':tag').replace(/\b[a-z]+_[0-9a-z]{26}\b/g, ':id').trim()).filter(Boolean));
const newWarnings = [...cmap.values()].filter((c) => {
  if (c.status !== 'warn' || !c.note) return false;
  const before = noteSet(bmap.get(key(c))?.note);
  return [...noteSet(c.note)].some((x) => !before.has(x));
});
const leakKey = (l) => `${l.role}|${String(l.where).replace(/\b[a-z]+_[0-9a-z]{26}\b/g, ':id')}|${l.detail}`;
const bl = new Set((base.leaks || []).map(leakKey));
const newLeaks = (cand.leaks || []).filter((l) => !bl.has(leakKey(l)));
const cl = new Set((cand.leaks || []).map(leakKey));
const fixedLeaks = (base.leaks || []).filter((l) => !cl.has(leakKey(l)));

if (process.argv.includes('--json')) {
  console.log(JSON.stringify({ regressions, unstable, preexisting, fixed, missing, added, newLeaks, fixedLeaks, newWarnings }, null, 2));
} else {
  const L = [];
  L.push(`# Playbook diff: ${base.label} (${base.sha}) → ${cand.label} (${cand.sha}), ${cand.edition}`, '');
  L.push(`- regressions: **${regressions.length}**, new leaks: **${newLeaks.length}**, api-unavailable (NAN-5102): ${unstable.length}, pre-existing failures: ${preexisting.length}, fixed: ${fixed.length + fixedLeaks.length}, checks only in baseline: ${missing.length}, new failing checks only in candidate: ${added.length}`, '');
  L.push('## Regressions (pass on baseline, fail on candidate)', '');
  for (const { c, o, fresh } of regressions) {
    L.push(`### ${c.role} · ${c.kind} · ${c.id}${fresh ? ' (new problems on an already-failing check)' : ''}`);
    if (c.url) L.push(`- url: ${c.url}`);
    if (c.steps) L.push(`- steps: ${c.steps}`);
    for (const p of fresh || c.problems) L.push(`- ${p}`);
    if (c.screenshot) L.push(`- screenshot: ${c.screenshot}`);
    if (o.problems?.length && !fresh) L.push(`- baseline: ${o.status}`);
    L.push('');
  }
  for (const c of added) { L.push(`### ${c.role} · ${c.kind} · ${c.id} (no baseline counterpart)`); for (const p of c.problems) L.push(`- ${p}`); L.push(''); }
  if (unstable.length) {
    L.push(`## API-unavailability window on the candidate (${unstable.length}) — NAN-5102, not attributed to the branch`, '');
    for (const { c } of unstable) L.push(`- ${c.role} · ${c.kind} · ${c.id}`);
    L.push('');
  }
  L.push('## New denied-source leaks', '');
  for (const l of newLeaks) L.push(`- ${l.role} ${l.where}: ${l.detail}`);
  if (!newLeaks.length) L.push('- none');
  L.push('', '## Pre-existing (fail on both)', '');
  for (const c of preexisting) L.push(`- ${c.role} · ${c.kind} · ${c.id}: ${c.problems.slice(0, 3).join(' | ')}`);
  L.push('', '## Fixed on candidate', '');
  for (const c of fixed) L.push(`- ${c.role} · ${c.kind} · ${c.id}`);
  for (const l of fixedLeaks) L.push(`- leak gone: ${l.role} ${l.where}`);
  if (newWarnings.length) { L.push('', '## New warnings on candidate (heuristic, review)', ''); for (const c of newWarnings) L.push(`- ${c.role} · ${c.kind} · ${c.id}: ${c.note}`); }
  if (missing.length) { L.push('', '## Checks present only in the baseline run', ''); for (const c of missing) L.push(`- ${c.role} · ${c.kind} · ${c.id} (${c.status})`); }
  console.log(L.join('\n'));
}
process.exit(regressions.length || newLeaks.length || added.length ? 1 : 0);
