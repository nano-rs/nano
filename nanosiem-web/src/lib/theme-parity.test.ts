// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

/**
 * Theme blocks in `index.css` must define the SAME set of tokens.
 *
 * The failure this guards is silent and ugly. A token defined in `.dark` but
 * missing from `.matte` does not inherit the dark value — `.matte` is a peer
 * block, so the token falls through to the `:root` LIGHT value. You get a white
 * card, or near-black text, on a near-black window. Nothing errors: the class is
 * valid, the var resolves, the build passes. Only a human looking at that one
 * screen would catch it, which is exactly the review step that misses things.
 *
 * Same reasoning as `theme-tokens.test.ts` (NAN-2191), different mechanism.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { THEMES, THEME_SWATCH } from './theme.ts';

const css = readFileSync(join(process.cwd(), 'src/index.css'), 'utf8');

/** Every theme class that carries a full token block. `:root` is the light one. */
const THEME_BLOCKS = [
  '.paper',
  ':root',
  '.dark',
  '.matte',
  '.mono',
  '.dark-pink',
  '.dark-violet',
  '.dark-emerald',
  '.dark-amber',
];

/**
 * Tokens deliberately defined ONCE, in `:root`, and inherited by every theme.
 * Only for values with no appearance component — a colour never belongs here.
 */
const THEME_INDEPENDENT = new Set(['--tracking-normal']);

/**
 * Tokens `.dark` defines that no theme needs to match, because nothing reads
 * them. `index.css` calls these "kept for back-compat until routes are ported",
 * but a repo-wide search finds zero `var(--border-primary|secondary)` uses — the
 * `border-primary` classes in components are Tailwind's `--color-primary`, a
 * different token. Deliberately NOT carried into new themes. Delete this set,
 * and the declarations, when someone confirms the port is finished.
 */
const DEAD_LEGACY = new Set(['--border-primary', '--border-secondary']);

/** Pull one brace-balanced block by its selector, then its `--token:` names. */
function tokensOf(selector: string): Set<string> {
  const start = css.indexOf(`\n  ${selector} {`);
  assert.notEqual(start, -1, `no \`${selector}\` block in index.css`);

  let depth = 0;
  let i = css.indexOf('{', start);
  const open = i;
  for (; i < css.length; i++) {
    if (css[i] === '{') depth++;
    else if (css[i] === '}' && --depth === 0) break;
  }

  const body = css.slice(open, i);
  return new Set(Array.from(body.matchAll(/^\s*(--[\w-]+)\s*:/gm), (m) => m[1]));
}

test('every theme block defines the same tokens', () => {
  const [light, ...rest] = THEME_BLOCKS.map((selector) => ({
    selector,
    tokens: tokensOf(selector),
  }));

  for (const theme of rest) {
    const missing = [...light.tokens].filter(
      (token) => !theme.tokens.has(token) && !THEME_INDEPENDENT.has(token),
    );
    const extra = [...theme.tokens].filter(
      (token) => !light.tokens.has(token) && !DEAD_LEGACY.has(token),
    );

    assert.deepEqual(
      missing,
      [],
      `${theme.selector} is missing tokens that ${light.selector} defines — ` +
        `they will silently resolve to the ${light.selector} (light) value`,
    );
    assert.deepEqual(
      extra,
      [],
      `${theme.selector} defines tokens ${light.selector} does not — ` +
        `they will be undefined in the other themes`,
    );
  }
});

test('dark-appearance themes all drive the `dark:` variant', () => {
  const variant = css.match(/@custom-variant dark \(([^)]*)\)/);
  assert.ok(variant, 'no `@custom-variant dark` in index.css');

  // A dark-appearance theme left out of the variant means the ~395 `dark:`
  // utilities across the app fall back to their LIGHT styling on a black window.
  for (const selector of [
    '.dark',
    '.matte',
    '.mono',
    '.dark-pink',
    '.dark-violet',
    '.dark-emerald',
    '.dark-amber',
  ]) {
    assert.ok(
      variant[1].includes(selector),
      `${selector} is a dark-appearance theme but is not in the \`dark:\` variant`,
    );
  }
});

/**
 * Chart modules must take their colours from `@/lib/chart-colors`.
 *
 * Six of these files each carried a private hex palette — four of them
 * byte-identical copies of the same eight colours — plus hardcoded axis greys.
 * None of it responded to the theme, so charts stayed blue-and-pink while the
 * rest of the app went matte (and, in light mode, painted `#9ca3af` ticks on
 * white). A raw hex here is how that regresses.
 */
test('chart modules carry no hardcoded colours', () => {
  const CHART_MODULES = [
    'src/components/dashboard/VisualizationRenderer.tsx',
    'src/components/dashboard/ObsMetricWidget.tsx',
    'src/components/observability/MetricViz.tsx',
    'src/components/observability/MetricsExplorer.tsx',
    'src/components/search/FlowVisualization.tsx',
    'src/components/search/TimechartView.tsx',
    'src/components/search/TimelineVisualization.tsx',
  ];

  for (const file of CHART_MODULES) {
    const source = readFileSync(join(process.cwd(), file), 'utf8');
    const hexes = source.match(/#[0-9a-fA-F]{6}\b/g) ?? [];
    assert.deepEqual(
      hexes,
      [],
      `${file} hardcodes ${hexes.join(', ')} — use CHART_SERIES / seriesColor() / ` +
        'the CHART_AXIS_* tokens from @/lib/chart-colors so charts follow the theme',
    );
  }
});

test('every theme in THEMES has a matching block and swatch', () => {
  for (const theme of THEMES) {
    const selector = theme === 'light' ? ':root' : `.${theme}`;
    assert.ok(
      THEME_BLOCKS.includes(selector),
      `${theme} is in THEMES but has no block in THEME_BLOCKS`,
    );

    const start = css.indexOf(`\n  ${selector} {`);
    assert.notEqual(start, -1, `no \`${selector}\` block in index.css`);

    let depth = 0;
    let i = css.indexOf('{', start);
    const open = i;
    for (; i < css.length; i++) {
      if (css[i] === '{') depth++;
      else if (css[i] === '}' && --depth === 0) break;
    }
    const body = css.slice(open, i);
    const bg = body.match(/^\s*--background:\s*(#[0-9a-fA-F]{6});/m)?.[1]?.toUpperCase();
    const primary = body.match(/^\s*--primary:\s*(#[0-9a-fA-F]{6});/m)?.[1]?.toUpperCase();

    const swatch = THEME_SWATCH[theme];
    assert.ok(swatch, `no swatch defined for ${theme}`);
    assert.equal(
      swatch.surface.toUpperCase(),
      bg,
      `swatch surface for ${theme} does not match --background in index.css`,
    );
    assert.equal(
      swatch.accent.toUpperCase(),
      primary,
      `swatch accent for ${theme} does not match --primary in index.css`,
    );
  }
});

test('every theme explicitly defines the logo accent token', () => {
  for (const theme of THEMES) {
    const selector = theme === 'light' ? ':root' : `.${theme}`;
    assert.ok(tokensOf(selector).has('--primary'), `${theme} must define --primary`);
  }
});
