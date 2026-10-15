// SPDX-License-Identifier: AGPL-3.0-or-later

/** Saved parser samples (hosted-shared, NAN-2617): client-side mirror of the server bounds. */

export const PARSER_SAMPLES_QUERY_KEY = (logSourceId: string) => ['parser-samples', logSourceId] as const;

/** Server bounds when the response omits them (NAN-2604 build inputs). */
export const DEFAULT_MAX_SAMPLES = 32;
export const DEFAULT_MAX_SAMPLE_BYTES = 65_536;

const utf8 = new TextEncoder();
export function sampleBytes(sample: string): number {
  return utf8.encode(sample).length;
}

/**
 * Mirror the server's `normalize_samples` + `validate_samples`: trimmed,
 * blank entries dropped, at most `maxSamples`, each 1..`maxBytes` bytes.
 * Returns the samples to send, or per-entry problems keyed by index.
 */
export function checkSamples(
  drafts: string[],
  maxSamples: number,
  maxBytes: number,
): { samples: string[]; problems: Record<number, string>; tooMany: boolean } {
  const problems: Record<number, string> = {};
  const samples: string[] = [];
  drafts.forEach((draft, i) => {
    const trimmed = draft.trim();
    if (!trimmed) return;
    const bytes = sampleBytes(trimmed);
    if (bytes > maxBytes) problems[i] = `${bytes.toLocaleString()} bytes; the limit is ${maxBytes.toLocaleString()}`;
    samples.push(trimmed);
  });
  return { samples, problems, tooMany: samples.length > maxSamples };
}
