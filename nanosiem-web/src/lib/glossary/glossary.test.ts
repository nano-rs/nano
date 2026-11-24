// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: every glossary entry is filled in, short, plain and links only to
// docs pages that exist.

import { describe, expect, it } from 'vitest';

import { GLOSSARY, glossarySections } from './index';
import { ENTERPRISE_DOCS_HREFS } from '@/enterprise/lib/glossary';
import { KNOWN_DOCS_HREFS, type GlossaryEntry } from './types';

const entries = Object.entries(GLOSSARY as Record<string, GlossaryEntry>);
const words = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;
/**
 * Sentences, counted by a full stop, ? or ! followed by a space and any letter
 * or digit. Lowercase counts too: a sentence may start with nano, pivt or nPL.
 * ("e.g." and "i.e." are banned below, and dotted ids such as
 * identity.authentication have no space after the dot.)
 */
const sentences = (s: string) => 1 + (s.trim().match(/[.?!]\s+(?=[A-Za-z0-9])/g)?.length ?? 0);

describe('sentence counter', () => {
  it('counts a second sentence that starts with a lowercase brand name', () => {
    expect(sentences('It stands for a schema. nano stores every event in it.')).toBe(2);
    expect(sentences('One thing. pivt helps.')).toBe(2);
    expect(sentences('Bindings such as identity.authentication count once.')).toBe(1);
  });
});

describe('glossary', () => {
  it('has entries', () => {
    expect(entries.length).toBeGreaterThan(20);
  });

  it('keeps enterprise docs links and enterprise paths out of open-core sections', () => {
    const leaks: string[] = [];
    for (const [section, terms] of Object.entries(glossarySections())) {
      if (!section.startsWith('core:')) continue;
      for (const [id, e] of Object.entries(terms)) {
        if (e.docsHref && ENTERPRISE_DOCS_HREFS.has(e.docsHref)) leaks.push(`${id}: enterprise docs link`);
        if (e.guardIn?.some((p) => p.startsWith('enterprise/'))) leaks.push(`${id}: enterprise guard path`);
      }
    }
    expect(leaks).toEqual([]);
  });

  it('never defines the same id in two sections', () => {
    const seen = new Map<string, string>();
    const dupes: string[] = [];
    for (const [section, terms] of Object.entries(glossarySections())) {
      for (const id of Object.keys(terms)) {
        if (seen.has(id)) dupes.push(`${id} (${seen.get(id)} and ${section})`);
        else seen.set(id, section);
      }
    }
    expect(dupes).toEqual([]);
  });

  it('uses kebab-case ids', () => {
    expect(entries.map(([id]) => id).filter((id) => !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(id))).toEqual([]);
  });

  it.each(entries)('%s is filled in and plain', (id, e) => {
    expect(e.term.trim(), `${id}.term`).not.toBe('');
    expect(e.short.trim(), `${id}.short`).not.toBe('');
    // Short: one sentence, a tooltip not a wall of text.
    expect(words(e.short), `${id}.short is too long`).toBeLessThanOrEqual(32);
    expect(e.short.trim(), `${id}.short ends a sentence`).toMatch(/[.?!]$/);
    expect(sentences(e.short), `${id}.short must be ONE sentence; move the rest to more`).toBe(1);
    if (e.more !== undefined) {
      expect(e.more.trim(), `${id}.more`).not.toBe('');
      expect(words(e.more), `${id}.more is too long`).toBeLessThanOrEqual(45);
      expect(sentences(e.more), `${id}.more is at most two sentences`).toBeLessThanOrEqual(2);
    }
    for (const text of [e.term, e.short, e.more ?? '']) {
      expect(text, `${id}: no em or en dashes`).not.toMatch(/[—–]/);
      expect(text, `${id}: US spelling`).not.toMatch(/\b(licence|behaviour|colour|organis|analys(e|ed|ing)\b|catalogue)/i);
      expect(text, `${id}: no "e.g." / "i.e."`).not.toMatch(/\b(e\.g|i\.e)\./i);
    }
    if (e.guard) expect(e.guard.flags, `${id}.guard must not be global`).not.toContain('g');
  });

  it('links only to docs pages that exist', () => {
    const known = new Set([...KNOWN_DOCS_HREFS, ...ENTERPRISE_DOCS_HREFS]);
    const bad = entries.filter(([, e]) => e.docsHref && !known.has(e.docsHref)).map(([id]) => id);
    expect(bad).toEqual([]);
  });
});
