// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';

import type { SourceConfigurationWithRules } from '@/lib/api/types';
import { buildConnectionSummary } from './SourceConfigurationDetail';

describe('HEC connection summary', () => {
  it('includes the stable request channel required by indexer acknowledgement', () => {
    const summary = buildConnectionSummary({
      id: 'hec',
      name: 'HEC',
      config_type: 'splunk_hec',
      connection_config: { port: 8088 },
      enabled: true,
      deployed: true,
      created_at: '',
      updated_at: '',
      routing_rules: [],
    } satisfies SourceConfigurationWithRules);

    expect(summary.headers).toContainEqual(expect.objectContaining({
      key: 'X-Splunk-Request-Channel',
      value: '<stable-uuid>',
    }));
    expect(summary.snippet).toContain("-H 'X-Splunk-Request-Channel: <stable-uuid>'");
  });
});
