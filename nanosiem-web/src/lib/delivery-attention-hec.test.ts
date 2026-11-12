// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { deliveryAttentionBySource, pullAttention } from './delivery-attention';

// NAN-5318: every HEC-fed source showed "PULL PAUSED" because its dispatch
// config is the (disabled) splunk_hec routing profile over the always-on
// platform HEC listener.
const hecProfile = { id: 'hec', name: 'Splunk HEC', enabled: false, deployed: false, config_type: 'splunk_hec' as const };

describe('delivery attention for push listener configs', () => {
  it('a disabled splunk_hec routing profile raises no attention', () => {
    expect(pullAttention('hec', hecProfile)).toBeNull();
    const byId = deliveryAttentionBySource(
      [{ id: 'ls', source_type: 'routed', match_values: ['apache_access'], dispatch_source_config_id: 'hec' }],
      [hecProfile],
      [],
    );
    expect(byId.size).toBe(0);
  });

  it('a disabled HTTP listener is push, not pull', () => {
    const a = pullAttention('h', { id: 'h', name: 'HTTP', enabled: false, deployed: false, config_type: 'http' });
    expect(a).toMatchObject({ kind: 'push', level: 'paused' });
  });

  it('a disabled Kafka config is still pull paused', () => {
    const a = pullAttention('k', { id: 'k', name: 'Kafka', enabled: false, deployed: false, config_type: 'kafka' });
    expect(a).toMatchObject({ kind: 'pull', level: 'paused' });
  });

  it('a missing config is still failed', () => {
    expect(pullAttention('gone', null)).toMatchObject({ level: 'failed' });
  });
});
