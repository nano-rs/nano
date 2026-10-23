import { describe, expect, it, vi } from 'vitest';
import { addMetricToDashboard } from './metric-widget';
vi.mock('@/lib/api', () => ({ api: {} }));
describe('metric dashboard transport seam', () => {
  it('preserves panels/layout and uses only injected transport', async () => {
    const getDashboard = vi
      .fn()
      .mockResolvedValue({
        panels: [{ id: 'existing' }],
        layout: {
          columns: 12,
          rowHeight: 80,
          items: [{ i: 'existing', x: 0, y: 3, w: 6, h: 4 }],
          variables: [{ name: 'region' }],
          autoRun: true,
        },
      });
    const updateDashboard = vi.fn().mockResolvedValue({});
    const createDashboard = vi.fn().mockResolvedValue({ id: 'new' });
    const config = {
      metric_name: 'cpu',
      agg: 'avg' as const,
      viz: 'timeseries' as const,
    };
    expect(
      await addMetricToDashboard(
        { dashboardId: 'board', title: 'CPU', metricConfig: config },
        { getDashboard, updateDashboard, createDashboard },
      ),
    ).toBe('board');
    const update = updateDashboard.mock.calls[0][1];
    expect(update.panels[0].id).toBe('existing');
    expect(update.panels[1].visualizationType).toBe('obs_metric');
    expect(update.layout.items[1].y).toBe(7);
    expect(update.layout.variables).toEqual([{ name: 'region' }]);
    expect(createDashboard).not.toHaveBeenCalled();
    expect(
      await addMetricToDashboard(
        { newDashboardName: 'Metrics', title: 'CPU', metricConfig: config },
        { getDashboard, updateDashboard, createDashboard },
      ),
    ).toBe('new');
  });
});
