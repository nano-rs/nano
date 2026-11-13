import { describe, expect, it } from 'vitest';
import { descriptionSummary } from './description-summary';

// NAN-5326: headers show the summary paragraph, not the whole changelog.
describe('descriptionSummary', () => {
  it('returns the first paragraph on one line', () => {
    const d = 'Parses Apache logs\ninto OCSF.\n\nv1.1.0 — upgrade:\n  * metadata.version bump';
    expect(descriptionSummary(d)).toBe('Parses Apache logs into OCSF.');
  });
  it('handles empty input', () => {
    expect(descriptionSummary(undefined)).toBe('');
  });
});
