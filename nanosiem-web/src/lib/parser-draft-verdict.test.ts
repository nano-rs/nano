import { describe, expect, it } from 'vitest';
import type { ParserDraftResponse } from '@/lib/api/types';
import { isIncompleteDraftStatus, parserDraftIncomplete } from './parser-draft-verdict';

function draft(valid: boolean, incomplete?: string): ParserDraftResponse {
  return {
    message: incomplete ?? 'Draft compiles and runs on 10 of 10 sample event(s). Review it before publishing.',
    parser: {
      name: 'acme',
      description: '',
      vrl_code: '. = {}',
      output_fields: [],
      validation_result: { valid, errors: valid ? [] : ['E203'] },
      test_results: [],
      incomplete,
    },
  };
}

describe('parser draft verdict (NAN-5079)', () => {
  it('a draft that compiles but fails OCSF validation is incomplete, not green', () => {
    const d = draft(true, 'Draft incomplete: 0/10 samples pass OCSF 1.9.0 validation. Remaining: is_mfa type.');
    expect(parserDraftIncomplete(d)).toBe(true);
    expect(isIncompleteDraftStatus(d.message)).toBe(true);
  });

  it('a draft that does not compile is incomplete', () => {
    expect(parserDraftIncomplete(draft(false))).toBe(true);
  });

  it('a successful draft is not incomplete', () => {
    const d = draft(true);
    expect(parserDraftIncomplete(d)).toBe(false);
    expect(isIncompleteDraftStatus(d.message)).toBe(false);
  });
});
