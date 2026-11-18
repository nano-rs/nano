// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />
//
// NAN-5541: the app does not use sparkle icons. An AI-driven control carries
// the pivt mark (`@/components/icons/PivtIcon`); a control that is not AI (a
// deterministic Format action, a statistical suggestion) gets a plain lucide
// icon that says what it does. This guard keeps the sparkle family — lucide
// `Sparkle`, `Sparkles`, `WandSparkles` and friends, icon-name strings that
// resolve to them, and the sparkles emoji — from coming back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('../', import.meta.url).pathname;

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|js|jsx)$/.test(name) && !/\.test\.[jt]sx?$/.test(name) && !/\.d\.ts$/.test(name)) out.push(p);
  }
  return out;
}

// Any lucide identifier in the sparkle family: Sparkle, Sparkles, WandSparkles,
// SparklesIcon, LucideSparkles, ...
const SPARKLE_IDENT = /\b\w*Sparkles?\w*\b/;
// Named imports and re-exports: `import { Sparkles as X }`, `export { Sparkles } from`.
const LUCIDE_IMPORT = /(?:import|export)\s*(?:type\s*)?\{([^}]*)\}\s*from\s*['"]lucide-react(?:\/[^'"]*)?['"]/g;
const LUCIDE_PATH_IMPORT = /from\s*['"]lucide-react\/dist\/esm\/icons\/[\w-]*sparkle[\w-]*['"]/gi;
// Namespace access: `Icons.Sparkles`, `icons.WandSparkles`.
const MEMBER_ACCESS = /\b\w+\.\w*Sparkles?\w*\b/g;
// Icon-name strings in config maps: `icon: 'Sparkles'`, `'wand-sparkles'`.
const ICON_NAME_STRING = /['"`][\w-]*sparkle[\w-]*['"`]/gi;
const SPARKLES_EMOJI = '✨';

test('no sparkle icons in nanosiem-web/src (AI = pivt mark)', () => {
  const offenders: string[] = [];
  for (const file of walk(ROOT, [])) {
    const rel = file.slice(ROOT.length);
    const src = readFileSync(file, 'utf8');
    const lineOf = (idx: number) => src.slice(0, idx).split('\n').length;

    for (const m of src.matchAll(LUCIDE_IMPORT)) {
      if (SPARKLE_IDENT.test(m[1])) offenders.push(`${rel}:${lineOf(m.index ?? 0)} imports a sparkle icon from lucide-react`);
    }
    for (const m of src.matchAll(LUCIDE_PATH_IMPORT)) {
      offenders.push(`${rel}:${lineOf(m.index ?? 0)} imports a sparkle icon file from lucide-react`);
    }
    for (const m of src.matchAll(MEMBER_ACCESS)) {
      offenders.push(`${rel}:${lineOf(m.index ?? 0)} references a sparkle icon (${m[0]})`);
    }
    for (const m of src.matchAll(ICON_NAME_STRING)) {
      offenders.push(`${rel}:${lineOf(m.index ?? 0)} names a sparkle icon (${m[0]})`);
    }
    const emoji = src.indexOf(SPARKLES_EMOJI);
    if (emoji !== -1) offenders.push(`${rel}:${lineOf(emoji)} uses the sparkles emoji`);
  }
  assert.deepEqual(
    offenders,
    [],
    `Sparkle icons are not used in nano. AI-driven UI uses PivtIcon; non-AI UI uses a plain lucide icon:\n${offenders.join('\n')}`,
  );
});
