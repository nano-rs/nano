// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2607: the parser rollout / base offer / samples client methods hit the documented paths. */
import { describe, expect, it, vi } from 'vitest';
import { LogSourcesApi } from './log-sources';

function client() {
  const request = vi.fn().mockResolvedValue({});
  return { api: new LogSourcesApi(request as never), request };
}

describe('LogSourcesApi parser rollouts', () => {
  it('sends wizard samples with deploy and publish, keeping ocsf_sample_logs', async () => {
    const { api, request } = client();
    await api.deployLogSource('lsrc_1');
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/deploy', { method: 'POST' });
    await api.deployLogSource('lsrc_1', ['o'], ['a', 'b']);
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/deploy', {
      method: 'POST', body: JSON.stringify({ ocsf_sample_logs: ['o'], samples: ['a', 'b'] }),
    });
    await api.deployLogSource('lsrc_1', undefined, ['a']);
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/deploy', { method: 'POST', body: '{"samples":["a"]}' });
    await api.publishLogSource('lsrc_1', ['x']);
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/publish', { method: 'POST', body: '{"samples":["x"]}' });
    await api.publishLogSource('lsrc_1');
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/publish', { method: 'POST' });
  });

  it('reads and requests rollouts', async () => {
    const { api, request } = client();
    await api.requestParserRollout('lsrc_1', { reason: 'retry' });
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/rollout', { method: 'POST', body: '{"reason":"retry"}' });
    await api.listLogSourceRollouts('lsrc_1', 10);
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/rollouts?limit=10');
    await api.listParserRollouts({ states: ['pending', 'building'], limit: 5 });
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/rollouts?state=pending%2Cbuilding&limit=5');
    await api.listParserRollouts();
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/rollouts');
    await api.getParserRollout('r-1');
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/rollouts/r-1');
  });

  it('lists and merges platform base offers, and stores samples', async () => {
    const { api, request } = client();
    await api.listParserBaseOffers();
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/parser-base-offers');
    await api.mergeParserBaseOffer('o-1');
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/parser-base-offers/o-1/merge', { method: 'POST', body: '{}' });
    await api.getLogSourceSamples('lsrc_1');
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/samples');
    await api.putLogSourceSamples('lsrc_1', ['s']);
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/lsrc_1/samples', { method: 'PUT', body: '{"samples":["s"]}' });
  });
});

describe('LogSourcesApi ingest credential precheck (NAN-2617)', () => {
  it('posts the kind and slugs to the precheck path', async () => {
    const { api, request } = client();
    await api.precheckIngestCredential({ kind: 'collector', source_slugs: ['okta', 'palo_alto_traffic'] });
    expect(request).toHaveBeenLastCalledWith('/api/log-sources/ingest-credentials/precheck', {
      method: 'POST',
      body: '{"kind":"collector","source_slugs":["okta","palo_alto_traffic"]}',
    });
  });
});
