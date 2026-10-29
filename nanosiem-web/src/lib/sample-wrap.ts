// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-4792: the Add data sample box sends one event per line. A paste copied
// from a terminal that soft-wrapped long lines arrives with each event split
// in two, and the parser draft then treats the tails as separate events. This
// module spots likely wrapped continuations so the wizard can say so and offer
// a one-click join. It only suggests; it never rewrites the text by itself.
//
// The heuristic is deliberately conservative: if the paste looks like a
// legitimate multi-line format (pretty JSON, a stack trace, XML events) it
// reports nothing.

export type LeadShape = 'syslog_pri' | 'iso_ts' | 'syslog_ts' | 'json' | 'other';

const MONTHS = 'Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec';
const SYSLOG_PRI = /^<\d{1,3}>/;
const ISO_TS = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/;
const SYSLOG_TS = new RegExp(`^(?:${MONTHS}) {1,2}\\d{1,2} \\d{2}:\\d{2}:\\d{2}`);

/** The leading shape of a raw line (not trimmed: indentation is a signal). */
export function leadShape(line: string): LeadShape {
  if (SYSLOG_PRI.test(line)) return 'syslog_pri';
  if (ISO_TS.test(line)) return 'iso_ts';
  if (SYSLOG_TS.test(line)) return 'syslog_ts';
  if (line.startsWith('{')) return 'json';
  return 'other';
}

/** Lines that belong to a legitimate multi-line event format. */
function isMultiLineFormatLine(line: string): boolean {
  const t = line.trim();
  // Pretty-printed JSON: a bare brace/bracket line.
  if (/^[[\]{}],?$/.test(t)) return true;
  // Java / JVM stack traces.
  if (/^at\s+\S/.test(t) || /^(?:Caused by|Suppressed):/.test(t) || /^\.\.\. \d+ (?:more|common frames omitted)/.test(t)) {
    return true;
  }
  if (/^(?:Exception in thread "[^"]+"\s+)?(?:[\w$]+\.)*[\w$]*(?:Exception|Error|Throwable)(?::|$)/.test(t)) return true;
  // Python tracebacks.
  if (/^Traceback \(most recent call last\)/.test(t) || /^\s+File "/.test(line)) return true;
  // XML (e.g. Windows events): a tag-led line that is not a syslog <pri>.
  if (/^<[^\d\s]/.test(t)) return true;
  return false;
}

export interface WrapAnalysis {
  /** Non-empty lines in the paste (what is sent as events). */
  lineCount: number;
  /** Indexes into `text.split(/\r?\n/)` of lines that look like wrapped tails. */
  continuations: number[];
}

/** More tails than this under one event line is not a terminal wrap. */
const MAX_TAILS_PER_EVENT = 3;

const NONE = (lineCount: number): WrapAnalysis => ({ lineCount, continuations: [] });

function splitLines(text: string): string[] {
  return text.split(/\r?\n/);
}

function isJsonDocument(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed) return false;
  try {
    JSON.parse(trimmed);
    return true;
  } catch {
    return false;
  }
}

/** JSON records may span lines without putting a brace on its own line. */
function hasMultilineJson(text: string): boolean {
  let start = -1;
  let depth = 0;
  let quoted = false;
  let escaped = false;
  let multiline = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (start < 0) {
      if (/\s/.test(c)) continue;
      if (c !== '{' && c !== '[') return false;
      start = i;
      multiline = false;
    }
    if (c === '\n') multiline = true;
    if (quoted) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') quoted = false;
    } else if (c === '"') {
      quoted = true;
    } else if (c === '{' || c === '[') {
      depth++;
    } else if (c === '}' || c === ']') {
      if (--depth === 0) {
        if (multiline && isJsonDocument(text.slice(start, i + 1))) return true;
        start = -1;
      }
    }
  }
  return false;
}

/** Count CSV columns across logical records, respecting quoted newlines. */
function isCsv(text: string): boolean {
  let fields = 1;
  let width = 0;
  let records = 0;
  let quoted = false;
  let fieldStart = true;
  let hasData = false;
  // A final virtual newline also checks the last record without a trailing LF.
  for (let i = 0; i <= text.length; i++) {
    const c = text[i] ?? '\n';
    if (quoted) {
      if (i === text.length) return false;
      if (c === '"') {
        if (text[i + 1] === '"') i++;
        else quoted = false;
      }
    } else if (c === ',') {
      fields++;
      fieldStart = true;
      hasData = true;
    } else if (c === '\n') {
      if (hasData) {
        if (fields < 2 || (width > 0 && fields !== width)) return false;
        width = fields;
        records++;
      }
      fields = 1;
      fieldStart = true;
      hasData = false;
    } else if (c.trim()) {
      if (fieldStart && c === '"') quoted = true;
      fieldStart = false;
      hasData = true;
    }
  }
  return records > 0;
}

/** Find lines that are probably terminal-wrapped continuations of the line above. */
export function detectWrappedLines(text: string): WrapAnalysis {
  const lines = splitLines(text);
  const nonEmpty = lines.filter((l) => l.trim());
  const lineCount = nonEmpty.length;
  if (lineCount < 3 || isJsonDocument(text) || hasMultilineJson(text) || isCsv(text)) return NONE(lineCount);
  if (nonEmpty.some(isMultiLineFormatLine)) return NONE(lineCount);

  const shapes = lines.map((l) => (l.trim() ? leadShape(l) : null));
  const tally = new Map<LeadShape, number>();
  for (const s of shapes) if (s && s !== 'other') tally.set(s, (tally.get(s) ?? 0) + 1);
  // A dominant shape does not make other event formats wrapped tails.
  if (tally.size > 1) return NONE(lineCount);
  let dominant: LeadShape | null = null;
  let dominantCount = 0;
  for (const [s, n] of tally) {
    if (n > dominantCount) {
      dominant = s;
      dominantCount = n;
    }
  }

  const continuations: number[] = [];
  // Rule A needs event lines to be at least half the paste: a wrap at most
  // doubles the line count, and a paste where few lines share a shape is a
  // mixed-format paste, not a wrapped one.
  if (dominant && dominantCount >= 2 && dominantCount * 2 >= lineCount) {
    // Rule A: most events start with a recognizable shape. A shapeless line
    // directly after an event line (or after another flagged tail) is a tail.
    // Lines with a different recognized shape are a mixed-format paste, not
    // tails, so they are never flagged.
    // A wrap splits a line into a few pieces; a long shapeless run under one
    // event line is some other structure, so the whole paste is left alone.
    let inEvent = false;
    let run = 0;
    for (let i = 0; i < lines.length; i++) {
      const s = shapes[i];
      if (s === null) {
        inEvent = false;
      } else if (s === 'other') {
        if (inEvent) {
          continuations.push(i);
          if (++run > MAX_TAILS_PER_EVENT) return NONE(lineCount);
        }
      } else {
        inEvent = true;
        run = 0;
      }
    }
  } else if (!dominant) {
    // Rule B: no recognizable shape; only indentation is a signal, and only
    // when indented lines are the minority and each follows an unindented one.
    const indented = (l: string) => /^\s/.test(l);
    const indentedCount = nonEmpty.filter(indented).length;
    if (indentedCount === 0 || indentedCount * 2 > lineCount) return NONE(lineCount);
    for (let i = 1; i < lines.length; i++) {
      const prev = lines[i - 1];
      if (lines[i].trim() && indented(lines[i]) && prev.trim() && !indented(prev)) continuations.push(i);
    }
    // An indented line after another indented one is a block, not a wrap.
    if (continuations.length !== indentedCount) return NONE(lineCount);
  }
  return { lineCount, continuations };
}

/** Join each flagged continuation onto the line above it. */
export function joinWrappedLines(text: string, analysis: WrapAnalysis = detectWrappedLines(text)): string {
  if (analysis.continuations.length === 0) return text;
  const flagged = new Set(analysis.continuations);
  const lines = splitLines(text);
  const out: string[] = [];
  lines.forEach((line, i) => {
    if (flagged.has(i) && out.length > 0) {
      const prev = out[out.length - 1];
      // An indented tail had whitespace at the wrap point; keep one space.
      // An unindented tail was cut mid-run by the terminal; rejoin exactly.
      out[out.length - 1] = /^\s/.test(line) ? `${prev.replace(/\s+$/, '')} ${line.trimStart()}` : prev + line;
    } else {
      out.push(line);
    }
  });
  return out.join('\n');
}

/** How the box's text is split into events, for the live count under it. */
export function describeSampleSplit(text: string, count: number): string {
  if (!text.trim()) return 'No samples';
  if (isJsonDocument(text)) return `${count} sample event${count === 1 ? '' : 's'} · JSON`;
  return `${count} sample line${count === 1 ? '' : 's'} · one event per line`;
}

export type ParserDraftStage = 'reasoning' | 'writing VRL' | 'validating' | 'working';

/** Map the job's progress text to a plain stage word (no fake percentage). */
export function parserDraftStage(message: string | null | undefined): ParserDraftStage {
  const m = (message ?? '').toLowerCase();
  if (/validat|testing|compil|retrying/.test(m)) return 'validating';
  if (/writing|generating/.test(m)) return 'writing VRL';
  if (/reasoning|thinking/.test(m)) return 'reasoning';
  return 'working';
}
