// SPDX-License-Identifier: AGPL-3.0-or-later

const RAW_PASSTHROUGH_VRL = '. = .';
const MAX_SAMPLE_COUNT = 5;
const MAX_SAMPLE_CHARS = 16_000;

export function isRawPassThroughVrl(vrl: string): boolean {
  return vrl.trim() === RAW_PASSTHROUGH_VRL;
}

/**
 * Prefer the original message retained by ingestion. If it is unavailable,
 * the complete search result is still a useful representative event shape.
 */
export function extractRecentParserSamples(
  results: Record<string, unknown>[],
  limit = MAX_SAMPLE_COUNT,
): string[] {
  const samples: string[] = [];
  const seen = new Set<string>();

  for (const event of results) {
    const message = event.message;
    const raw = typeof message === 'string' && message.trim()
      ? message.trim()
      : JSON.stringify(event);
    if (!raw) continue;

    const bounded = raw.slice(0, MAX_SAMPLE_CHARS);
    if (seen.has(bounded)) continue;
    seen.add(bounded);
    samples.push(bounded);
    if (samples.length >= limit) break;
  }

  return samples;
}

export function buildLogSourceParserPrompt({
  userMessage,
  sourceName,
  sourceType,
  isRawPassThrough,
}: {
  userMessage: string;
  sourceName: string;
  sourceType: string;
  isRawPassThrough: boolean;
}): string {
  const parserState = isRawPassThrough
    ? 'The current `. = .` program is an intentional raw pass-through placeholder, not a completed parser.'
    : 'This Log Source originated from a raw collector and its recent events are attached for parser context.';

  return `${userMessage}\n\n## Active Log Source context supplied by nano\n- Name: ${sourceName}\n- source_type: ${sourceType}\n- Parser state: ${parserState}\n\nRecent source-scoped raw events are attached below as Sample Logs. Use this metadata and those samples directly. If the user asks to build or create the parser, generate the complete VRL parser now; do not ask the user to identify the source or paste samples that nano already supplied.`;
}
