import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { Markdown } from './markdown';

/**
 * The renderer's job is half formatting, half containment: pivt's output is
 * attacker-influenceable (its context is log content), so "renders bold" and
 * "cannot be made to emit markup" are the same test suite.
 */
const render = (text: string) => renderToStaticMarkup(<Markdown text={text} />);

describe('Markdown — formatting', () => {
  it('renders bold, italic and inline code', () => {
    const html = render('**bold** and *italic* and `code`');
    expect(html).toContain('<strong');
    expect(html).toContain('bold');
    expect(html).toContain('<em');
    expect(html).toContain('italic');
    expect(html).toContain('<code');
  });

  it('prefers bold over italic on a double asterisk', () => {
    const html = render('**not italic**');
    expect(html).toContain('<strong');
    expect(html).not.toContain('<em');
  });

  it('renders fenced code blocks whole, without inline parsing inside them', () => {
    const html = render('```sql\nSELECT * FROM logs\n```');
    expect(html).toContain('<pre');
    expect(html).toContain('SELECT * FROM logs');
    // The `*` in the SQL must not have become emphasis.
    expect(html).not.toContain('<em');
  });

  it('renders an unterminated fence rather than swallowing the message', () => {
    const html = render('```\ntruncated mid-stream');
    expect(html).toContain('truncated mid-stream');
  });

  it('renders bullet and ordered lists', () => {
    const bullets = render('- one\n- two');
    expect(bullets).toContain('one');
    expect(bullets).toContain('two');
    expect(bullets).toContain('<li');

    const ordered = render('1. first\n2. second');
    expect(ordered).toContain('first');
    expect(ordered).toContain('2.');
  });

  it('renders the count-by table pivt actually answers with', () => {
    // Lifted from a real pivt run against the local instance.
    const html = render('| source_type | events |\n|---|---|\n| tenzir | 3 |\n| windows | 2 |');
    expect(html).toContain('<table');
    expect(html).toContain('<th');
    expect(html).toContain('source_type');
    expect(html).toContain('tenzir');
    expect(html).toContain('windows');
  });

  it('does not mistake a piped nPL query for a table', () => {
    // No delimiter row, so this is prose that happens to contain pipes.
    const html = render('Run `user=admin | stats count by src_ip` to see it.');
    expect(html).not.toContain('<table');
  });

  it('renders headings and block quotes', () => {
    expect(render('## Finding')).toContain('Finding');
    expect(render('> quoted evidence')).toContain('quoted evidence');
  });

  it('keeps plain prose intact', () => {
    expect(render('No markup at all.')).toContain('No markup at all.');
  });
});

describe('Markdown — SIEM identifiers survive', () => {
  // Underscores are identifiers here, not markup. A renderer that honours
  // `__…__`/`_…_` rewrites the field and tool names pivt talks about all day.
  it('leaves an MCP tool name alone', () => {
    const html = render('I called mcp__nano__search for you.');
    expect(html).toContain('mcp__nano__search');
    expect(html).not.toContain('<strong');
  });

  it('leaves UDM field names alone', () => {
    const html = render('Grouped by enriched_src_country and prevalence_file_hash.');
    expect(html).toContain('enriched_src_country');
    expect(html).toContain('prevalence_file_hash');
    expect(html).not.toContain('<em');
  });

  it('still renders asterisk emphasis, which models actually emit', () => {
    expect(render('*emphasised*')).toContain('<em');
    expect(render('**strong**')).toContain('<strong');
  });
});

describe('Markdown — containment', () => {
  it('renders raw HTML as inert text, never as markup', () => {
    const html = render('<script>alert(1)</script>');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('does not let an img/onerror payload through', () => {
    const html = render('<img src=x onerror="alert(1)">');
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
  });

  it('never emits an anchor, so a chosen link target cannot be clicked', () => {
    const html = render('[totally safe](javascript:alert(1))');
    expect(html).not.toContain('<a ');
    expect(html).not.toContain('href');
    // The target is still SHOWN, verbatim, so the analyst can judge it.
    expect(html).toContain('javascript:alert(1)');
  });

  it('shows the real target of a link that lies about where it goes', () => {
    const html = render('[https://nano.rs/docs](https://evil.example/phish)');
    expect(html).toContain('https://evil.example/phish');
    expect(html).not.toContain('<a ');
  });

  it('renders HTML inside a code fence as text too', () => {
    const html = render('```\n<script>alert(1)</script>\n```');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });
});
