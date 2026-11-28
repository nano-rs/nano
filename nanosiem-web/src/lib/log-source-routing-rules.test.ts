// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiClientError } from '@/lib/api';
import type { SourceConfiguration, SourceConfigurationWithRules } from '@/lib/api/types';
import { findAssociatedRoutingRules, type RoutingRuleLookupApi } from './log-source-routing-rules';

const forbidden = () =>
  new ApiClientError('Forbidden: Missing permission: source_configs:view', 'FORBIDDEN', undefined, 403);

function client(over: Partial<RoutingRuleLookupApi> = {}) {
  return {
    listSourceConfigs: vi.fn(async () => [
      { id: 'sc1', name: 'http in' } as SourceConfiguration,
      { id: 'sc2', name: 'kafka in' } as SourceConfiguration,
    ]),
    getSourceConfigWithRules: vi.fn(async (id: string) => ({
      id,
      routing_rules: id === 'sc1'
        ? [
            { id: 'r1', target_source_type: 'okta', match_value: 'okta*' },
            { id: 'r2', target_source_type: 'other', match_value: 'x' },
          ]
        : [{ id: 'r3', target_source_type: 'okta', match_value: '' }],
    }) as unknown as SourceConfigurationWithRules),
    ...over,
  };
}

describe('findAssociatedRoutingRules (NAN-5972)', () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => errorSpy.mockRestore());

  it('without source_configs:view, makes no API call and logs nothing', async () => {
    const c = client();
    expect(await findAssociatedRoutingRules(['okta'], false, c)).toEqual([]);
    expect(c.listSourceConfigs).not.toHaveBeenCalled();
    expect(c.getSourceConfigWithRules).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('with the permission, lists the rules that route to the source', async () => {
    const c = client();
    expect(await findAssociatedRoutingRules(['okta'], true, c)).toEqual([
      { configId: 'sc1', configName: 'http in', ruleId: 'r1', matchValue: 'okta*' },
      { configId: 'sc2', configName: 'kafka in', ruleId: 'r3', matchValue: '(default)' },
    ]);
    expect(c.listSourceConfigs).toHaveBeenCalledWith({ enabled: true });
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('skips the lookup for a source with no match values', async () => {
    const c = client();
    expect(await findAssociatedRoutingRules([], true, c)).toEqual([]);
    expect(await findAssociatedRoutingRules(undefined, true, c)).toEqual([]);
    expect(c.listSourceConfigs).not.toHaveBeenCalled();
  });

  it('a 403 (permission removed mid-session) reads as nothing to show, quietly', async () => {
    const c = client({ listSourceConfigs: vi.fn(async () => { throw forbidden(); }) });
    expect(await findAssociatedRoutingRules(['okta'], true, c)).toEqual([]);
    expect(errorSpy).not.toHaveBeenCalled();

    const perConfig = client({ getSourceConfigWithRules: vi.fn(async () => { throw forbidden(); }) });
    expect(await findAssociatedRoutingRules(['okta'], true, perConfig)).toEqual([]);
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('other errors are still logged and never throw', async () => {
    const boom = new ApiClientError('Internal error', 'INTERNAL', undefined, 500);
    const c = client({ listSourceConfigs: vi.fn(async () => { throw boom; }) });
    expect(await findAssociatedRoutingRules(['okta'], true, c)).toEqual([]);
    expect(errorSpy).toHaveBeenCalledWith('Failed to check associated routing rules:', boom);

    errorSpy.mockClear();
    const one = client({
      getSourceConfigWithRules: vi.fn(async (id: string) => {
        if (id === 'sc2') throw new Error('network');
        return { id, routing_rules: [{ id: 'r1', target_source_type: 'okta', match_value: 'a' }] } as unknown as
          SourceConfigurationWithRules;
      }),
    });
    expect(await findAssociatedRoutingRules(['okta'], true, one)).toEqual([
      { configId: 'sc1', configName: 'http in', ruleId: 'r1', matchValue: 'a' },
    ]);
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(String(errorSpy.mock.calls[0][0])).toContain('kafka in');
  });
});
