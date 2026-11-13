// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// NAN-5328: highlighting respects OCSF dotted field names, numeric word
// boundaries, and field scoping.
import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import {
  extractHighlightTerms,
  extractKeywordsFromQuery,
  highlightEventRowLine,
  highlightText,
  keywordsForField,
} from './keyword-highlight';
import { buildEventRowLine } from './event-row-line';

const marks = (node: React.ReactNode) =>
  Array.from(render(<div>{node}</div>).container.querySelectorAll('mark')).map((m) => m.textContent);

describe('extractHighlightTerms (NAN-5328)', () => {
  it('treats an OCSF dotted path as one field, not a free-text term', () => {
    const t = extractHighlightTerms('actor.user.name="mallory" class_uid=1007');
    expect(t.free).toEqual([]);
    expect(t.scoped).toEqual([
      { field: 'actor.user.name', value: 'mallory' },
      { field: 'class_uid', value: '1007' },
    ]);
    expect(extractKeywordsFromQuery('actor.user.name="mallory"')).toEqual(['mallory']);
  });

  it('keeps bare terms free and IN-list values scoped', () => {
    const t = extractHighlightTerms('beacon user IN ("a","b")');
    expect(t.free).toEqual(['beacon']);
    expect(t.scoped).toEqual([{ field: 'user', value: 'a' }, { field: 'user', value: 'b' }]);
  });
});

describe('highlightText numeric boundaries (NAN-5328)', () => {
  it('does not mark 1007 inside 100701', () => {
    expect(marks(highlightText('type_uid 100701', ['1007']))).toEqual([]);
    expect(marks(highlightText('class_uid 1007', ['1007']))).toEqual(['1007']);
  });
  it('still marks text terms as substrings', () => {
    expect(marks(highlightText('powershell.exe', ['shell']))).toEqual(['shell']);
  });
});

describe('field-scoped highlighting (NAN-5328)', () => {
  const fields = {
    'actor.user.name': 'mallory',
    'process.cmd_line': 'runas /user:mallory cmd',
    class_uid: 1007,
    type_uid: 100701,
  };
  const terms = extractHighlightTerms('actor.user.name="mallory" class_uid=1007');

  it('marks the scoped value only in its own field, never in keys', () => {
    const node = highlightEventRowLine(fields, terms);
    expect(render(<div>{node}</div>).container.textContent).toBe(buildEventRowLine(fields));
    expect(marks(node)).toEqual(['mallory', '1007']);
  });

  it('a scoped term on a field the event lacks (alias) highlights everywhere', () => {
    const aliasTerms = extractHighlightTerms('user="mallory"');
    const keys = new Set(Object.keys(fields));
    expect(keywordsForField(aliasTerms, 'process.cmd_line', keys)).toEqual(['mallory']);
    expect(keywordsForField(terms, 'process.cmd_line', keys)).toEqual([]);
    expect(keywordsForField(terms, 'actor.user.name', keys)).toEqual(['mallory']);
  });

  it('truncates to maxLen with the same text as the plain line', () => {
    const node = highlightEventRowLine(fields, terms, 30);
    expect(render(<div>{node}</div>).container.textContent).toBe(buildEventRowLine(fields)!.substring(0, 30));
  });
});
