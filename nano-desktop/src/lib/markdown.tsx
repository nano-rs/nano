import type { ReactNode } from 'react';

/**
 * A small markdown renderer for agent output.
 *
 * WHY NOT A LIBRARY: pivt's context is deliberately filled with log content, and
 * logs are written by the attackers being investigated. Everything pivt emits is
 * therefore attacker-influenceable, and the renderer is a security boundary — so
 * it is one this app owns. It produces React elements and nothing else: raw HTML
 * in the source text is never parsed, it stays inert text. There is no
 * `dangerouslySetInnerHTML` here, and there must never be one.
 *
 * LINKS ARE NOT CLICKABLE, on purpose. A link whose target the attacker chose,
 * rendered inside the console the analyst trusts, is a phishing primitive — and
 * in a webview, a navigation away from the app. Both the label and the target are
 * shown as text so the analyst can read where it would have gone and decide for
 * themselves.
 */

type Block =
  | { kind: 'p'; text: string }
  | { kind: 'heading'; level: number; text: string }
  | { kind: 'code'; lang: string; lines: string[] }
  | { kind: 'list'; ordered: boolean; items: string[] }
  | { kind: 'quote'; lines: string[] }
  | { kind: 'table'; header: string[]; rows: string[][] }
  | { kind: 'rule' };

const FENCE = /^\s*```(\w*)\s*$/;
const HEADING = /^(#{1,6})\s+(.*)$/;
const BULLET = /^\s*[-*+]\s+(.*)$/;
const ORDERED = /^\s*\d+[.)]\s+(.*)$/;
const QUOTE = /^\s*>\s?(.*)$/;
const RULE = /^\s*(?:---+|\*\*\*+|___+)\s*$/;
/** `| a | b |` — a table row. */
const ROW = /^\s*\|(.+)\|\s*$/;
/** `|---|:--:|` — the delimiter that makes the line above a header. */
const DELIMITER = /^\s*\|?[\s:|-]+\|[\s:|-]*$/;

function cells(line: string): string[] {
  const inner = ROW.exec(line)?.[1] ?? line;
  return inner.split('|').map((cell) => cell.trim());
}

function parse(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, '\n').split('\n');
  const blocks: Block[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];

    if (!line.trim()) {
      index += 1;
      continue;
    }

    const fence = FENCE.exec(line);
    if (fence) {
      const body: string[] = [];
      index += 1;
      // An unterminated fence (a truncated stream) still renders as code rather
      // than swallowing the rest of the message.
      while (index < lines.length && !FENCE.test(lines[index])) {
        body.push(lines[index]);
        index += 1;
      }
      index += 1; // closing fence
      blocks.push({ kind: 'code', lang: fence[1] ?? '', lines: body });
      continue;
    }

    if (RULE.test(line)) {
      blocks.push({ kind: 'rule' });
      index += 1;
      continue;
    }

    const heading = HEADING.exec(line);
    if (heading) {
      blocks.push({ kind: 'heading', level: heading[1].length, text: heading[2] });
      index += 1;
      continue;
    }

    // A table needs its delimiter row to be a table; without one, `| a | b |` is
    // just prose that happens to contain pipes (an nPL query, for instance).
    if (ROW.test(line) && index + 1 < lines.length && DELIMITER.test(lines[index + 1])) {
      const header = cells(line);
      index += 2;
      const rows: string[][] = [];
      while (index < lines.length && ROW.test(lines[index])) {
        rows.push(cells(lines[index]));
        index += 1;
      }
      blocks.push({ kind: 'table', header, rows });
      continue;
    }

    if (BULLET.test(line) || ORDERED.test(line)) {
      const ordered = !BULLET.test(line);
      const items: string[] = [];
      while (index < lines.length) {
        const item = (ordered ? ORDERED : BULLET).exec(lines[index]);
        if (!item) break;
        items.push(item[1]);
        index += 1;
      }
      blocks.push({ kind: 'list', ordered, items });
      continue;
    }

    if (QUOTE.test(line)) {
      const body: string[] = [];
      while (index < lines.length) {
        const quoted = QUOTE.exec(lines[index]);
        if (!quoted) break;
        body.push(quoted[1]);
        index += 1;
      }
      blocks.push({ kind: 'quote', lines: body });
      continue;
    }

    // A paragraph runs to the next blank line or the next block opener.
    const paragraph: string[] = [];
    while (index < lines.length) {
      const next = lines[index];
      if (
        !next.trim() ||
        FENCE.test(next) ||
        HEADING.test(next) ||
        BULLET.test(next) ||
        ORDERED.test(next) ||
        QUOTE.test(next) ||
        RULE.test(next)
      ) {
        break;
      }
      paragraph.push(next);
      index += 1;
    }
    blocks.push({ kind: 'p', text: paragraph.join('\n') });
  }

  return blocks;
}

/**
 * `code`, **bold**, *italic*, [label](target). Ordered so the longer fences win:
 * `**` must be tried before `*`, or bold parses as two empty italics.
 *
 * UNDERSCORE EMPHASIS IS DELIBERATELY NOT SUPPORTED. In a SIEM, underscores are
 * not markup — they are the identifiers. `mcp__nano__search`, `enriched_src_country`,
 * `tool_use_id` are what pivt talks about all day, and a renderer that honours
 * `__…__` / `_…_` silently rewrites them to "mcp<b>nano</b>search" and
 * "enriched<i>src</i>country": the emphasis eats the underscores and the analyst
 * reads a field name that does not exist. Models reach for `*` and `**` anyway,
 * so nothing of value is lost by refusing the underscore forms.
 */
const INLINE = /(`[^`\n]+`)|(\*\*[^\n]+?\*\*)|(\*[^*\n]+?\*)|(\[[^\]\n]*\]\([^)\s\n]*\))/g;

const LINK = /^\[([^\]\n]*)\]\(([^)\s\n]*)\)$/;

function inline(text: string, keyPrefix: string): ReactNode[] {
  const out: ReactNode[] = [];
  let cursor = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  INLINE.lastIndex = 0;
  while ((match = INLINE.exec(text)) !== null) {
    if (match.index > cursor) out.push(text.slice(cursor, match.index));
    const token = match[0];
    const id = `${keyPrefix}-${key++}`;

    if (token.startsWith('*') && !token.startsWith('**')) {
      out.push(
        <em key={id} className="italic">
          {token.slice(1, -1)}
        </em>
      );
    } else if (token.startsWith('`')) {
      out.push(
        <code
          key={id}
          className="rounded-[4px] border border-line-strong bg-black/30 px-1 py-px font-mono text-[11.5px] text-accent"
        >
          {token.slice(1, -1)}
        </code>
      );
    } else if (token.startsWith('**')) {
      out.push(
        <strong key={id} className="font-semibold text-t1">
          {token.slice(2, -2)}
        </strong>
      );
    } else {
      const link = LINK.exec(token);
      const label = link?.[1]?.trim() || link?.[2] || token;
      const target = link?.[2] ?? '';
      out.push(
        <span key={id}>
          <span className="text-t1 underline decoration-dotted underline-offset-2">{label}</span>
          {/* The target, verbatim and inert. Never an anchor: see the file header. */}
          {target && target !== label && (
            <span className="ml-1 font-mono text-[11px] break-all text-t4">({target})</span>
          )}
        </span>
      );
    }
    cursor = match.index + token.length;
  }

  if (cursor < text.length) out.push(text.slice(cursor));
  return out;
}

/**
 * Render agent-authored markdown. `break-words` everywhere is load-bearing, not
 * cosmetic: a 64-char hash or a long URL with no break opportunity will otherwise
 * push the 330px panel into a horizontal scroll.
 */
export function Markdown({ text }: { text: string }) {
  const blocks = parse(text);

  return (
    <div className="space-y-2 break-words">
      {blocks.map((block, index) => {
        const key = `b${index}`;
        switch (block.kind) {
          case 'heading':
            return (
              <div
                key={key}
                className={`font-semibold text-t1 ${block.level <= 2 ? 'text-[13px]' : 'text-[12.5px]'}`}
              >
                {inline(block.text, key)}
              </div>
            );

          case 'code':
            return (
              <pre
                key={key}
                className="overflow-x-auto rounded-[7px] border border-line-strong bg-black/35 px-2.5 py-2 font-mono text-[11.5px] leading-[1.5] text-t2"
              >
                <code>{block.lines.join('\n')}</code>
              </pre>
            );

          case 'list':
            return (
              <ul key={key} className="space-y-1 pl-1">
                {block.items.map((item, itemIndex) => (
                  <li key={itemIndex} className="flex gap-1.5">
                    <span className="shrink-0 text-t4">
                      {block.ordered ? `${itemIndex + 1}.` : '·'}
                    </span>
                    <span className="min-w-0">{inline(item, `${key}-${itemIndex}`)}</span>
                  </li>
                ))}
              </ul>
            );

          case 'table':
            // pivt answers count-by questions with a table — it is the single
            // most common shape in its output, so it gets real columns. Mono, and
            // scrollable inside its own box so a wide one can't push the panel.
            return (
              <div
                key={key}
                className="overflow-x-auto rounded-[7px] border border-line-strong bg-black/25"
              >
                <table className="w-full border-collapse text-left">
                  <thead>
                    <tr>
                      {block.header.map((cell, cellIndex) => (
                        <th
                          key={cellIndex}
                          className="border-b border-line px-2.5 py-1.5 text-[10.5px] font-bold tracking-[0.06em] whitespace-nowrap text-t4 uppercase"
                        >
                          {inline(cell, `${key}-h${cellIndex}`)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {block.rows.map((row, rowIndex) => (
                      <tr key={rowIndex}>
                        {row.map((cell, cellIndex) => (
                          <td
                            key={cellIndex}
                            className="px-2.5 py-1 font-mono text-[11.5px] whitespace-nowrap text-t2"
                          >
                            {inline(cell, `${key}-${rowIndex}-${cellIndex}`)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );

          case 'quote':
            return (
              <div key={key} className="border-l-2 border-line-strong pl-2.5 text-t3">
                {inline(block.lines.join('\n'), key)}
              </div>
            );

          case 'rule':
            return <div key={key} className="h-px bg-line-strong" />;

          default:
            return (
              <p key={key} className="whitespace-pre-wrap">
                {inline(block.text, key)}
              </p>
            );
        }
      })}
    </div>
  );
}
