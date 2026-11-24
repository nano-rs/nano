// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: keeps glossary tooltips consistent. When a guarded glossary term
// (an entry with a `guard` pattern) appears in a component's JSX text, that
// component must render <Term id="..."> for it at least once.
//
// The check is per file: a component that shows "sweeps" in its JSX text
// wraps the first one. Text inside <Term>, <code>, <pre> and <kbd> is ignored.
// It reads JSX text only, so labels that come from string constants are not
// seen; wrap those by hand.
//
// Two lists can excuse a hit:
// - ALLOWLIST (below): a permanent exception, with a reason.
// - glossary-guard-baseline.json (core, and one under src/enterprise/lib/glossary):
//   known debt from before the guard. It only
//   shrinks. A baseline entry that no longer fails is an error too, so remove
//   it when you fix it. Regenerate after a fix with
//     UPDATE_GLOSSARY_BASELINE=1 npx vitest run src/lib/glossary/glossary-guard.test.ts
//   (that only ever removes entries unless you also add new violations).

import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

import { glossarySections } from './index';
import type { GlossaryEntry } from './types';

const SRC = join(__dirname, '..', '..');
// Two baselines so the open-core mirror (which strips src/enterprise) carries
// no enterprise file names or term ids.
const CORE_BASELINE = join(__dirname, 'glossary-guard-baseline.json');
const ENTERPRISE_BASELINE = join(SRC, 'enterprise', 'lib', 'glossary', 'glossary-guard-baseline.json');
const isEnterpriseRow = (row: string) => row.startsWith('enterprise/');

/** `path::termId` pairs that are fine without a Term, each with a reason. */
const ALLOWLIST: Record<string, string> = {};

const SKIP_DIRS = new Set(['__tests__', 'node_modules']);
const SKIP_PREFIXES = ['components/ui/', 'lib/glossary/'];
/** Elements that wrap a term: <Term> and the open-core slot <EnterpriseTerm>. */
const TERM_TAGS = new Set(['Term', 'EnterpriseTerm']);
const IGNORED_ELEMENTS = new Set([...TERM_TAGS, 'code', 'pre', 'kbd']);

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    if (name.isDirectory()) {
      if (!SKIP_DIRS.has(name.name)) walk(join(dir, name.name), out);
    } else if (name.name.endsWith('.tsx') && !/\.(test|spec|stories)\.tsx$/.test(name.name)) {
      out.push(join(dir, name.name));
    }
  }
  return out;
}

function tagName(node: ts.JsxOpeningLikeElement): string {
  return node.tagName.getText();
}

function insideIgnored(node: ts.Node): boolean {
  for (let p = node.parent; p; p = p.parent) {
    if (ts.isJsxElement(p) && IGNORED_ELEMENTS.has(tagName(p.openingElement))) return true;
  }
  return false;
}

/** The ids of every <Term id="..."> in a file. */
function termIds(sf: ts.SourceFile): Set<string> {
  const ids = new Set<string>();
  const visit = (n: ts.Node) => {
    if ((ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) && TERM_TAGS.has(tagName(n))) {
      for (const attr of n.attributes.properties) {
        if (!ts.isJsxAttribute(attr) || attr.name.getText() !== 'id' || !attr.initializer) continue;
        const init = attr.initializer;
        if (ts.isStringLiteral(init)) ids.add(init.text);
        else if (ts.isJsxExpression(init) && init.expression && ts.isStringLiteralLike(init.expression)) {
          ids.add(init.expression.text);
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return ids;
}

/** Visible JSX text outside <Term>, <code>, <pre> and <kbd>. */
function jsxTexts(sf: ts.SourceFile): string[] {
  const out: string[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isJsxText(n) && n.text.trim() && !insideIgnored(n)) out.push(n.text.replace(/\s+/g, ' ').trim());
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

/** Every entry with its effective guard scope (see GlossaryEntry.guardIn). */
function scopedGlossary(): Record<string, GlossaryEntry> {
  const out: Record<string, GlossaryEntry> = {};
  for (const [section, terms] of Object.entries(glossarySections())) {
    const fallback = section.startsWith('enterprise:') ? ['enterprise/'] : undefined;
    for (const [id, e] of Object.entries(terms)) out[id] = e.guardIn || !fallback ? e : { ...e, guardIn: fallback };
  }
  return out;
}

const inScope = (e: GlossaryEntry, rel: string) => !e.guardIn || e.guardIn.some((p) => rel.startsWith(p));

/** Guarded term ids a file shows in JSX text without a <Term> for them. */
function unwrappedTerms(source: string, glossary: Record<string, GlossaryEntry>, rel = 'x.tsx'): string[] {
  const sf = ts.createSourceFile(rel, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const wrapped = termIds(sf);
  const texts = jsxTexts(sf);
  const missing: string[] = [];
  for (const [id, entry] of Object.entries(glossary)) {
    if (!entry.guard || wrapped.has(id) || !inScope(entry, rel)) continue;
    const re = new RegExp(entry.guard.source, entry.guard.flags.replace('g', ''));
    if (texts.some((t) => re.test(t))) missing.push(id);
  }
  return missing;
}

let scanned: string[] | null = null;

/** Parses every component once per run; both app tests share the result. */
function scan(): string[] {
  if (scanned) return scanned;
  scanned = scanAll();
  return scanned;
}

function scanAll(): string[] {
  const glossary = scopedGlossary();
  const violations: string[] = [];
  for (const file of walk(SRC)) {
    const rel = relative(SRC, file).split('\\').join('/');
    if (SKIP_PREFIXES.some((p) => rel.startsWith(p))) continue;
    for (const id of unwrappedTerms(readFileSync(file, 'utf8'), glossary, rel)) {
      violations.push(`${rel}::${id}`);
    }
  }
  return violations.sort();
}

const readRows = (path: string): string[] =>
  existsSync(path) ? (JSON.parse(readFileSync(path, 'utf8')) as string[]) : [];

function readBaseline(): string[] {
  return [...readRows(CORE_BASELINE), ...readRows(ENTERPRISE_BASELINE)];
}

function writeBaseline(rows: string[]) {
  const write = (path: string, list: string[]) => writeFileSync(path, `${JSON.stringify(list, null, 2)}\n`);
  write(CORE_BASELINE, rows.filter((r) => !isEnterpriseRow(r)));
  if (existsSync(join(SRC, 'enterprise'))) write(ENTERPRISE_BASELINE, rows.filter(isEnterpriseRow));
}

describe('glossary guard: the checker', () => {
  const g: Record<string, GlossaryEntry> = {
    sweep: { term: 'Sweep', short: 'One run.', guard: /\bsweeps?\b/i },
    lead: { term: 'Lead', short: 'Needs a person.' },
  };

  it('flags a guarded term in JSX text with no Term', () => {
    expect(unwrappedTerms('const A = () => <p>Recent sweeps</p>;', g)).toEqual(['sweep']);
  });

  it('passes once the file wraps the term', () => {
    const src = 'const A = () => <div><h2><Term id="sweep">Sweeps</Term></h2><p>All sweeps ran.</p></div>;';
    expect(unwrappedTerms(src, g)).toEqual([]);
  });

  it('accepts id={"..."} and ignores code, pre and kbd', () => {
    expect(unwrappedTerms("const A = () => <Term id={'sweep'} />;", g)).toEqual([]);
    expect(unwrappedTerms('const A = () => <code>sweep_id</code>;', g)).toEqual([]);
  });

  it('ignores unguarded terms, attributes and identifiers', () => {
    expect(unwrappedTerms('const A = () => <p>lead</p>;', g)).toEqual([]);
    expect(unwrappedTerms('const sweeps = 1; const A = () => <p title="sweeps">{sweeps}</p>;', g)).toEqual([]);
  });

  it('applies a scoped guard only under its paths', () => {
    const scoped = { budget: { term: 'Budget', short: 'Most it may use.', guard: /\bbudget\b/i, guardIn: ['enterprise/pages/Hunts/'] } };
    const src = 'const A = () => <p>Error budget</p>;';
    expect(unwrappedTerms(src, scoped, 'pages/observability/SlosTab.tsx')).toEqual([]);
    expect(unwrappedTerms(src, scoped, 'enterprise/pages/Hunts/HuntDetailPage.tsx')).toEqual(['budget']);
  });

  it('counts the open-core <EnterpriseTerm> slot as a wrap', () => {
    expect(unwrappedTerms('const A = () => <p><EnterpriseTerm id="sweep">sweeps</EnterpriseTerm> ran</p>;', g)).toEqual([]);
  });

  it('does not count a Term for a different id', () => {
    expect(unwrappedTerms('const A = () => <p><Term id="lead" /> from sweeps</p>;', g)).toEqual(['sweep']);
  });
});

// Parsing every .tsx file takes a few seconds, more under a loaded full run.
describe('glossary guard: the app', { timeout: 60_000 }, () => {
  it('every guarded term is wrapped in every component that shows it', () => {
    const found = scan();
    const allowed = new Set(Object.keys(ALLOWLIST));
    const debt = found.filter((v) => !allowed.has(v));

    if (process.env.UPDATE_GLOSSARY_BASELINE) {
      writeBaseline(debt);
      return;
    }

    const baseline = new Set(readBaseline());
    const fresh = debt.filter((v) => !baseline.has(v));
    expect(fresh, 'wrap the first use of each term with <Term id=...> (src/components/ui/term.tsx)').toEqual([]);

    const fixed = [...baseline].filter((v) => !found.includes(v));
    expect(fixed, 'these are fixed: remove them from the glossary-guard-baseline.json files').toEqual([]);
  });

  it('allowlist entries are all still needed', () => {
    const found = new Set(scan());
    const unused = Object.keys(ALLOWLIST).filter((k) => !found.has(k));
    expect(unused, 'remove allowlist entries that no longer match').toEqual([]);
  });
});
