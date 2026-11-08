// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4941 (main's NAN-3661): the Log Sources list flags a source whose pull
 * config or connector feed needs attention. Derived from dev's source
 * configuration and connector feed lists (main read the hosted pipe-inputs API).
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { TooltipProvider } from '@/components/ui/tooltip';
import { DeliveryAttentionBadge } from './DeliveryAttentionBadge';
import { attentionSummary, deliveryAttentionBySource, worstAttention } from '@/lib/delivery-attention';

afterEach(cleanup);

const sources = [
  { id: 'ls_pull', source_type: 'cloudtrail', match_values: ['cloudtrail'], dispatch_source_config_id: 'sc_ct' },
  { id: 'ls_okta', source_type: 'splunk_hec', match_values: ['okta'], dispatch_source_config_id: null },
  { id: 'ls_ok', source_type: 'routed', match_values: ['acme'], dispatch_source_config_id: 'sc_ok' },
  { id: 'ls_gone', source_type: 'kafka', match_values: ['k'], dispatch_source_config_id: 'sc_deleted' },
];
const configs = [
  { id: 'sc_ct', name: 'CloudTrail queue', enabled: true, deployed: false },
  { id: 'sc_ok', name: 'Acme queue', enabled: true, deployed: true },
];
const feeds = [
  { id: 'cf_1', name: 'Okta prod', enabled: true, last_status: 'failed', source_type: 'okta' },
  { id: 'cf_2', name: 'Okta paused', enabled: false, last_status: 'success', source_type: 'okta' },
  { id: 'cf_3', name: 'Acme feed', enabled: true, last_status: 'success', source_type: 'acme' },
];

describe('deliveryAttentionBySource', () => {
  it('flags an undeployed pull config, a missing one, and failed or paused feeds on the lane; healthy ones stay quiet', () => {
    const map = deliveryAttentionBySource(sources, configs, feeds);
    expect(map.get('ls_pull')).toEqual([{ kind: 'pull', id: 'sc_ct', name: 'CloudTrail queue', level: 'blocked', reason: 'not deployed' }]);
    expect(map.get('ls_gone')?.[0]).toMatchObject({ kind: 'pull', level: 'failed', reason: 'source configuration missing' });
    expect(map.get('ls_okta')?.map((a) => a.level)).toEqual(['failed', 'paused']);
    expect(map.has('ls_ok')).toBe(false);
    expect(worstAttention(map.get('ls_okta')!)).toBe('failed');
    expect(attentionSummary(map.get('ls_pull')!)).toEqual(['pull · CloudTrail queue: blocked (not deployed)']);
  });

  it('raises no pull flag while the configs list is unreadable (no source_configs:view)', () => {
    const map = deliveryAttentionBySource(sources, undefined, undefined);
    expect(map.size).toBe(0);
  });
});

describe('DeliveryAttentionBadge', () => {
  it('names the worst level and the kind, with every reason in its label', () => {
    const items = deliveryAttentionBySource(sources, configs, feeds).get('ls_okta')!;
    render(<TooltipProvider><DeliveryAttentionBadge items={items} /></TooltipProvider>);
    const badge = screen.getByTestId('delivery-attention-badge');
    expect(badge.textContent).toContain('connector failed');
    expect(badge.getAttribute('aria-label')).toContain('connector · Okta paused: paused');
  });

  it('renders nothing without attention', () => {
    render(<TooltipProvider><DeliveryAttentionBadge items={[]} /></TooltipProvider>);
    expect(screen.queryByTestId('delivery-attention-badge')).toBeNull();
  });
});
