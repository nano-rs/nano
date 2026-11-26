// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5131: deploy/undeploy/publish/deploy-all must outlast the default 60 s
// client timeout (they take 90 s+ on a small host); other calls keep it.
import { describe, expect, it, vi } from 'vitest';
import { DEPLOY_REQUEST_TIMEOUT_MS, LogSourcesApi } from './log-sources';
import { SourceConfigsApi } from './source-configs';
import { ConnectorFeedsApi } from './connector-feeds';

function apis() {
  const request = vi.fn().mockResolvedValue({});
  const longRequest = vi.fn().mockResolvedValue({});
  return { request, longRequest, ls: new LogSourcesApi(request, longRequest), sc: new SourceConfigsApi(request, longRequest) };
}

describe('deploy request timeout (NAN-5131)', () => {
  it('is longer than the 300 s edge budget for deploy routes', () => {
    expect(DEPLOY_REQUEST_TIMEOUT_MS).toBeGreaterThan(300_000);
  });

  it('sends every log-source and source-config deploy/publish through the long request', async () => {
    const { request, longRequest, ls, sc } = apis();
    await ls.deployLogSource('a');
    await ls.undeployLogSource('a');
    await ls.deployAllLogSources();
    await ls.publishLogSource('a');
    await sc.deploySourceConfig('b');
    await sc.undeploySourceConfig('b');
    await sc.deployAllSourceConfigs();
    expect(request).not.toHaveBeenCalled();
    const endpoints = longRequest.mock.calls.map(([endpoint]) => endpoint);
    // NAN-5132: log-source deploys start a job (`wait=false`); a server
    // without jobs answers synchronously, so the start keeps the long budget.
    expect(endpoints).toEqual([
      '/api/log-sources/a/deploy?wait=false',
      '/api/log-sources/a/undeploy?wait=false',
      '/api/log-sources/deploy-all?wait=false',
      '/api/log-sources/a/publish?wait=false',
      '/api/source-configurations/b/deploy',
      '/api/source-configurations/b/undeploy',
      '/api/source-configurations/deploy-all',
    ]);
    for (const call of longRequest.mock.calls) expect(call[2]).toBe(DEPLOY_REQUEST_TIMEOUT_MS);
  });

  // NAN-5678: a delete reloads Vector too (one reload for a bulk delete).
  it('sends single and bulk log-source deletes through the long request', async () => {
    const { request, longRequest, ls } = apis();
    await ls.deleteLogSource('a');
    await ls.bulkDeleteLogSources(['a', 'b']);
    expect(request).not.toHaveBeenCalled();
    expect(longRequest.mock.calls.map(([endpoint, init]) => [endpoint, init.method])).toEqual([
      ['/api/log-sources/a', 'DELETE'],
      ['/api/log-sources/bulk-delete', 'POST'],
    ]);
    expect(JSON.parse(longRequest.mock.calls[1][1].body)).toEqual({ ids: ['a', 'b'] });
    for (const call of longRequest.mock.calls) expect(call[2]).toBe(DEPLOY_REQUEST_TIMEOUT_MS);
  });

  it('keeps the default timeout for ordinary calls', async () => {
    const { request, longRequest, ls } = apis();
    await ls.listLogSources();
    expect(request).toHaveBeenCalledWith('/api/log-sources');
    expect(longRequest).not.toHaveBeenCalled();
  });
});

// NAN-5903: a pull feed start that sets up log sources deploys them first, so
// it runs under the deploy budget; a plain start keeps the default timeout.
describe('connector feed starts', () => {
  it('use the deploy budget only when they set up log sources', async () => {
    const request = vi.fn().mockResolvedValue({});
    const longRequest = vi.fn().mockResolvedValue({});
    const feeds = new ConnectorFeedsApi(request, longRequest);
    await feeds.create({ name: 'f', connector: 'okta_system_log', config: {}, set_up_log_sources: true });
    await feeds.setEnabled('cfeed_1', true, true);
    await feeds.adoptSpec('cfeed_1', true);
    expect(longRequest.mock.calls.map(([endpoint, init]) => [endpoint, init.method])).toEqual([
      ['/api/connector-feeds', 'POST'],
      ['/api/connector-feeds/cfeed_1', 'PATCH'],
      ['/api/connector-feeds/cfeed_1/adopt-spec', 'POST'],
    ]);
    for (const call of longRequest.mock.calls) expect(call[2]).toBe(DEPLOY_REQUEST_TIMEOUT_MS);
    expect(request).not.toHaveBeenCalled();
    await feeds.create({ name: 'f', connector: 'okta_system_log', config: {}, set_up_log_sources: false });
    await feeds.setEnabled('cfeed_1', false);
    await feeds.plan('okta_system_log', {});
    expect(request).toHaveBeenCalledTimes(3);
    expect(longRequest).toHaveBeenCalledTimes(3);
  });
});
