// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ParserDraftResponse } from '@/lib/api/types';

/**
 * NAN-5079: whether a parser-draft job result is incomplete. The agent's own
 * verdict wins (a draft can compile and still fail OCSF validation on its
 * samples); a draft that does not compile is always incomplete.
 */
export function parserDraftIncomplete(draft: ParserDraftResponse): boolean {
  return Boolean(draft.parser.incomplete) || !draft.parser.validation_result.valid;
}

/** The persisted step status of an incomplete draft ("Draft incomplete: …"). */
export function isIncompleteDraftStatus(status: string): boolean {
  return status.startsWith('Draft incomplete');
}
