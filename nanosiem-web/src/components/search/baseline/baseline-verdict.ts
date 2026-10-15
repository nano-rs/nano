// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3256: the ONE trust verdict the panel shows. Coverage and the
 * comparison caveats used to render side by side ("sufficient" next to
 * "baseline unknown"); a caveat now replaces the coverage claim instead.
 * Precedence: no history > baseline unknown > incomplete > coverage.
 *
 * NAN-3277: coverage `unknown` means the entity's history was NOT read to a
 * positive answer (deadline, refusal, read error). It is never rendered as
 * "no history" — that claim is reserved for a completed read that found
 * nothing.
 */
export type BaselineVerdict = 'sufficient' | 'thin' | 'no_history' | 'unknown' | 'incomplete';

export function baselineVerdict(
  coverage: string,
  anyUnknown: boolean,
  anyIncomplete: boolean,
): BaselineVerdict {
  if (coverage === 'unknown') return 'incomplete';
  if (coverage !== 'sufficient' && coverage !== 'thin') return 'no_history';
  if (anyUnknown) return 'unknown';
  if (anyIncomplete) return 'incomplete';
  return coverage;
}
