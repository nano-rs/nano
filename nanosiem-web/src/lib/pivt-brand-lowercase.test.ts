// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-3624: the AI assistant's name is always lowercase "pivt" — never
// "PIVT" or "Pivt", including at the start of a sentence. This guard scans
// every source file under src/ for the brand as a standalone word (string
// literals, JSX text, aria-labels, markdown, comments). Code identifiers that
// merely contain the letters — PIVT_ACCENT, PivtIcon, usePivtState,
// `pivt:open-*-wizard` — are allowed because they touch `_` or other word
// characters.
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = new URL('../', import.meta.url).pathname;
const SELF = 'lib/pivt-brand-lowercase.test.ts';

// Standalone "PIVT" / "Pivt": not preceded or followed by an identifier
// character. `$` counts so template-literal interpolations stay identifiers.
// A preceding `\n` escape (e.g. `'\nPIVT engine'`) is still prose.
const BRAND_MISCASE = /(?:(?<=\\n)|(?<![A-Za-z0-9_$]))(?:PIVT|Pivt)(?![A-Za-z0-9_$])/g;

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|js|jsx|mjs|css|md|mdx|json|html)$/.test(name)) out.push(p);
  }
  return out;
}

function findBrandMiscase(src: string): string[] {
  const hits: string[] = [];
  src.split('\n').forEach((line, i) => {
    BRAND_MISCASE.lastIndex = 0;
    if (BRAND_MISCASE.test(line)) hits.push(`${i + 1}: ${line.trim()}`);
  });
  return hits;
}

describe('pivt brand casing', () => {
  it('flags prose uses and allows identifiers', () => {
    expect(findBrandMiscase(`title="PIVT"`)).toHaveLength(1);
    expect(findBrandMiscase(`'Ask PIVT about this pipeline'`)).toHaveLength(1);
    expect(findBrandMiscase(`<span>Pivt suggests</span>`)).toHaveLength(1);
    expect(findBrandMiscase(`'Generated\\nPIVT engine'`)).toHaveLength(1);
    expect(findBrandMiscase(`const c = PIVT_ACCENT; <PivtIcon />; usePivtState();`)).toHaveLength(0);
    expect(findBrandMiscase(`dispatch('pivt:open-tuning-wizard'); 'pivt suggests'`)).toHaveLength(0);
  });

  it('never writes the assistant name as PIVT or Pivt in nanosiem-web/src', () => {
    const offenders: string[] = [];
    for (const file of walk(ROOT, [])) {
      const rel = relative(ROOT, file);
      if (rel === SELF) continue;
      for (const hit of findBrandMiscase(readFileSync(file, 'utf8'))) offenders.push(`${rel}:${hit}`);
    }
    expect(offenders, 'the assistant is always lowercase "pivt" (NAN-3624)').toEqual([]);
  });
});
