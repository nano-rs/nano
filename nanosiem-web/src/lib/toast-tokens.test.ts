// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

/**
 * NAN-2788: toasts must be opaque and on-palette in EVERY theme.
 *
 * Sonner keys all of its surface tokens (`--normal-bg`, `--error-bg`, ...) on
 * `data-sonner-theme="light|dark"`. The Toaster used to pass the raw app theme
 * name, so in `matte`, `mono`, `dark-pink`, ... the attribute matched neither
 * block, `background: var(--normal-bg)` resolved to nothing, and every toast
 * rendered transparent. Tailwind `bg-*` classNames could not rescue it: sonner
 * injects its stylesheet unlayered, which beats any `@layer utilities` rule.
 *
 * Guarded three ways:
 *   1. `sonnerAppearance` only ever yields `light` / `dark`.
 *   2. `index.css` re-points EVERY token sonner defines for its dark theme at
 *      app tokens (so a sonner upgrade that adds a token fails here).
 *   3. every app token those mappings read is defined, and opaque, in every
 *      theme block.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { THEMES, sonnerAppearance } from './theme.ts';

const css = readFileSync(join(process.cwd(), 'src/index.css'), 'utf8');
const sonnerCss = readFileSync(
  join(process.cwd(), 'node_modules/sonner/dist/styles.css'),
  'utf8',
);

const TOASTER_SELECTOR = ':root [data-sonner-toaster][data-sonner-theme] {';

function blockBody(source: string, from: number): string {
  let depth = 0;
  let i = source.indexOf('{', from);
  const open = i;
  for (; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) break;
  }
  return source.slice(open + 1, i);
}

function declarations(body: string): Map<string, string> {
  return new Map(
    Array.from(body.matchAll(/^\s*(--[\w-]+)\s*:\s*([^;]+);/gm), (m) => [m[1], m[2].trim()]),
  );
}

function themeTokens(theme: string): Map<string, string> {
  const selector = theme === 'light' ? ':root' : `.${theme}`;
  const start = css.indexOf(`\n  ${selector} {`);
  assert.notEqual(start, -1, `no \`${selector}\` block in index.css`);
  return declarations(blockBody(css, start));
}

function toastMapping(): Map<string, string> {
  const start = css.indexOf(TOASTER_SELECTOR);
  assert.notEqual(start, -1, 'index.css has no sonner token block (TOASTS (sonner))');
  return declarations(blockBody(css, start));
}

/** A colour with no alpha channel: #rgb / #rrggbb, or rgb()/hsl()/oklch() without `/` or an alpha arg. */
function isOpaqueColor(value: string): boolean {
  if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(value)) return true;
  const fn = value.match(/^(rgb|hsl|oklch|oklab|lab|lch)\((.*)\)$/i);
  if (!fn) return false;
  const args = fn[2];
  if (args.includes('/')) return false;
  if (/^(rgb|hsl)$/i.test(fn[1]) && args.split(',').length > 3) return false;
  return true;
}

test('sonner is only ever handed light or dark', () => {
  for (const resolved of [...THEMES, 'system', undefined]) {
    const appearance = sonnerAppearance(resolved);
    assert.ok(
      appearance === 'light' || appearance === 'dark',
      `sonnerAppearance(${String(resolved)}) = ${appearance}`,
    );
  }
  assert.equal(sonnerAppearance('light'), 'light');
  assert.equal(sonnerAppearance('paper'), 'light');
  assert.equal(sonnerAppearance('matte'), 'dark');
  assert.equal(sonnerAppearance('dark-pink'), 'dark');
});

test('index.css maps every sonner surface token to an app token', () => {
  const darkStart = sonnerCss.indexOf("[data-sonner-toaster][data-sonner-theme='dark'] {");
  assert.notEqual(darkStart, -1, 'sonner styles.css changed shape — re-check the mapping');
  const sonnerTokens = [...declarations(blockBody(sonnerCss, darkStart)).keys()];
  assert.ok(sonnerTokens.includes('--normal-bg'));

  const mapping = toastMapping();
  const unmapped = sonnerTokens.filter((token) => !mapping.has(token));
  assert.deepEqual(
    unmapped,
    [],
    'sonner defines these per-theme tokens but index.css does not re-point them — ' +
      'they fall back to sonner\'s own light/dark palette',
  );
});

test('every app token a toast reads is defined and opaque in every theme', () => {
  const mapping = toastMapping();
  const referenced = new Set<string>(['--font-sans', '--radius']);
  for (const value of mapping.values()) {
    for (const m of value.matchAll(/var\((--[\w-]+)\)/g)) referenced.add(m[1]);
  }
  // Colours only: the semantic mixes must stay opaque, so every input must be.
  const colorTokens = [...referenced].filter((t) => t !== '--font-sans' && t !== '--radius');
  assert.ok(colorTokens.includes('--popover'));

  for (const theme of THEMES) {
    const tokens = themeTokens(theme);
    const root = themeTokens('light');
    for (const token of referenced) {
      assert.ok(
        tokens.has(token) || ((token === '--font-sans' || token === '--radius') && root.has(token)),
        `${theme} does not define ${token}, which the toast reads`,
      );
    }
    for (const token of colorTokens) {
      const value = tokens.get(token)!;
      assert.ok(
        isOpaqueColor(value),
        `${theme} ${token} = ${value} is not an opaque colour — toasts would show through`,
      );
    }
  }
});

test('toast mappings introduce no transparency of their own', () => {
  for (const [token, value] of toastMapping()) {
    if (!token.endsWith('-bg') && !token.endsWith('-bg-hover')) continue;
    assert.ok(
      /^var\(--[\w-]+\)$/.test(value) ||
        /^color-mix\(in srgb, var\(--[\w-]+\) \d+%, var\(--popover\)\)$/.test(value),
      `${token}: ${value} — use a theme token or a color-mix over the opaque --popover`,
    );
  }
});
