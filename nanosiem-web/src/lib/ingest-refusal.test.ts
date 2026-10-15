// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-3680: the one-line refused-rows sentence every surface shows. */
import { describe, expect, it } from 'vitest';
import { hasRefusals, refusalCause, refusalReasonLabel, refusalSentence } from './ingest-refusal';

describe('ingest refusal copy', () => {
  it('names the count, the reason and the OCSF attribute', () => {
    expect(refusalSentence(100, { reason: 'ocsf_constraint_failed', field: 'device' })).toBe(
      '100 events refused by OCSF validation (constraint_failed at device)',
    );
    expect(refusalSentence(1, { reason: 'time_invalid', field: 'time' })).toBe('1 event refused by OCSF validation (time_invalid at time)');
    expect(refusalSentence(3, { reason: 'unclassified' })).toBe('3 events refused by OCSF validation (unclassified)');
    expect(refusalSentence(3, null)).toBe('3 events refused by OCSF validation');
  });

  it('says nothing for zero or an unknown count', () => {
    expect(refusalSentence(0, { reason: 'ocsf_constraint_failed' })).toBeNull();
    expect(refusalSentence(null, null)).toBeNull();
    expect(refusalSentence(undefined, null)).toBeNull();
    expect(hasRefusals(null)).toBe(false);
    expect(hasRefusals(2)).toBe(true);
  });

  it('strips only the ocsf_ prefix', () => {
    expect(refusalReasonLabel('ocsf_attribute_unknown')).toBe('attribute_unknown');
    expect(refusalReasonLabel('uid_missing')).toBe('uid_missing');
    expect(refusalCause({ reason: '' })).toBeNull();
  });
});
