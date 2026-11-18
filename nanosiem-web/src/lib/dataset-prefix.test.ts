// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-5612: panels and drilldown links carry the dataset as a leading token. */
import { describe, expect, it } from 'vitest';
import { datasetOfQuery, splitDatasetPrefix, withDatasetPrefix } from './dataset-prefix';

describe('dataset prefix', () => {
  it('reads a leading dataset token', () => {
    expect(splitDatasetPrefix('dataset=signals | timechart span=1h count by severity')).toEqual({
      dataset: 'signals',
      query: '| timechart span=1h count by severity',
    });
    expect(splitDatasetPrefix('dataset=risk')).toEqual({ dataset: 'risk', query: '' });
    expect(datasetOfQuery('dataset=signals rule_name="x"')).toBe('signals');
  });

  it('leaves anything else alone', () => {
    for (const q of ['status=500', 'dataset="signals"', 'dataset=bogus | stats count', 'x dataset=signals', 'dataset=signalsX']) {
      expect(splitDatasetPrefix(q)).toEqual({ dataset: null, query: q });
      expect(datasetOfQuery(q)).toBe('logs');
    }
  });

  it('sets, replaces and removes the token', () => {
    expect(withDatasetPrefix('| stats count by rule_name', 'signals')).toBe('dataset=signals | stats count by rule_name');
    expect(withDatasetPrefix('dataset=signals | stats count', 'risk')).toBe('dataset=risk | stats count');
    expect(withDatasetPrefix('dataset=risk | sort -score_24h', 'logs')).toBe('| sort -score_24h');
    expect(withDatasetPrefix('', 'signals')).toBe('dataset=signals');
  });
});
