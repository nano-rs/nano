import { describe, it, expect } from 'vitest';
import { extractDataset } from './detection-linter';

// NAN-5275: the editor sends the rule's dataset to /api/rules/validate so a
// `dataset: risk` rule's `score_24h` validates against the risk schema.
describe('extractDataset', () => {
  const doc = (yaml: string) =>
    `---\n${yaml}\n---\n* | where score_24h > 500 or score_7d > 1000`;

  it('reads the dataset from the YAML front matter', () => {
    expect(extractDataset(doc('title: accumulated_risk_threshold_exceeded\ndataset: risk'))).toBe('risk');
    expect(extractDataset(doc("dataset: 'spans'"))).toBe('spans');
  });

  it('is undefined when the rule has no dataset key (logs default)', () => {
    expect(extractDataset(doc('title: x\nseverity: high'))).toBeUndefined();
    expect(extractDataset('* | head 1')).toBeUndefined();
  });

  it('ignores a dataset= token in the query body', () => {
    expect(extractDataset(doc('title: x') + '\ndataset: risk')).toBeUndefined();
  });
});
