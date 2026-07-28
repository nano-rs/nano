// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

/**
 * NAN-2191: surface-colour tokens must not be used as text colours.
 *
 * The Access key / Assume role switch shipped unreadable because it used
 * `text-accent`. In this theme `--accent` is a near-BACKGROUND surface
 * (`#F1F5F9` light / `#161B23` dark), so it painted near-white text on a light
 * card and near-black on a dark one — invisible in both. `text-muted` has the
 * same shape (`#F8FAFC` / `#0F1319`); the real muted text token is
 * `--muted-foreground` (`#64748B` / `#A8ACB4`).
 *
 * Nothing caught it. These are VALID Tailwind classes — `--color-accent` and
 * `--color-muted` are both mapped in `index.css` — so typecheck, lint and build
 * all pass while rendering invisible text. Only a human looking at the screen
 * would notice, which is exactly the review step that missed it.
 *
 * `border-line` / `text-line` are a different failure: there is no
 * `--color-line` at all, so the class silently resolves to nothing and the
 * border simply never renders.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Surface tokens, banned in `text-*` position.
 *
 * Three tokens are deliberately ABSENT:
 *   - `background` — `text-background` is correct inverted styling on a
 *     `bg-foreground` or gradient-filled element, and the codebase uses it so.
 *   - `border` — `text-border` legitimately drives an SVG `stroke="currentColor"`
 *     (MitreCoverage's progress ring), where it is not text at all.
 *   - `primary` / `destructive` — saturated brand colours that read fine as
 *     text and are used as such throughout.
 */
const SURFACE_TOKENS = ['accent', 'muted', 'card', 'popover', 'secondary'];

/** Tokens that do not exist in `index.css` at all — these resolve to nothing. */
const PHANTOM_TOKENS = ['line'];

/**
 * Bare `text-<surface>` — not `text-<surface>-foreground` (correct), and not
 * `text-<surface>/50` (an opacity modifier, used deliberately for skeleton
 * shimmers where near-invisibility is the point).
 */
const surfaceAsText = new RegExp(
  `(?<![\\w-])text-(${SURFACE_TOKENS.join('|')})(?![\\w/-])`,
  'g',
);
const phantom = new RegExp(
  `(?<![\\w-])(?:text|bg|border)-(${PHANTOM_TOKENS.join('|')})(?![\\w-])`,
  'g',
);

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist') continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      sourceFiles(full, out);
    } else if (/\.tsx?$/.test(entry) && !entry.endsWith('.test.ts')) {
      out.push(full);
    }
  }
  return out;
}

function findAll(pattern: RegExp): string[] {
  const hits: string[] = [];
  for (const file of sourceFiles('src')) {
    const text = readFileSync(file, 'utf8');
    text.split('\n').forEach((line, i) => {
      for (const m of line.matchAll(pattern)) {
        hits.push(`${file}:${i + 1}  ${m[0]}  —  ${line.trim().slice(0, 90)}`);
      }
    });
  }
  return hits;
}

test('surface-colour tokens are never used as text colours', () => {
  const hits = findAll(surfaceAsText);
  assert.deepEqual(
    hits,
    [],
    `These render as near-invisible text — a surface colour painted on a surface.\n` +
      `Use the matching *-foreground token (e.g. text-muted-foreground), or\n` +
      `text-primary for an active/selected state:\n\n${hits.join('\n')}\n`,
  );
});

test('no class references a token that does not exist', () => {
  const hits = findAll(phantom);
  assert.deepEqual(
    hits,
    [],
    `There is no --color-line in index.css, so these resolve to nothing and the\n` +
      `border/colour never renders. Use border-border / text-fg:\n\n${hits.join('\n')}\n`,
  );
});
