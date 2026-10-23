import { expect, it, vi } from 'vitest';
import { SearchApi } from './search';
import { ObservabilityApi } from './observability';
const range = { start: '2026-10-18T01:00:00Z', end: '2026-10-18T01:15:00Z' };
it('sends exact selected bounds for tag keys and values through the observability facade', async () => {
  const request = vi.fn(async (_path: string) => ({ tag_keys: [], tag_values: [] }));
  const search = new SearchApi(request as never);
  const unused = async () => { throw new Error('unexpected endpoint'); };
  const obs = new ObservabilityApi(request as never, unused, unused, unused, unused,
    (metric, key, timeRange) => search.listMetricTags(metric, key, timeRange));
  await obs.listMetricTags('node metric/+value', undefined, range);
  await obs.listMetricTags('node metric/+value', 'host.name', range);
  const urls = request.mock.calls.map(c => new URL(String(c[0]), 'https://example.test'));
  expect(urls.map(u => Object.fromEntries(u.searchParams))).toEqual([
    { metric_name: 'node metric/+value', ...range },
    { metric_name: 'node metric/+value', key: 'host.name', ...range },
  ]);
});
it('retains the backend default for callers that omit a range', async () => {
  const request = vi.fn(async () => ({}));
  await new SearchApi(request as never).listMetricTags('cpu', 'host');
  expect(request).toHaveBeenCalledWith('/api/search/metrics/tags?metric_name=cpu&key=host');
});
