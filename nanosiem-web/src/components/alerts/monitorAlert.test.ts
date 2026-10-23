import { describe, expect, it } from 'vitest';
import { monitorLabelText, parseMonitorAlert } from './monitorAlert';

describe('metric alert labels', () => {
  it('preserves node, mountpoint, cluster and pool labels', () => {
    const alert = parseMonitorAlert({ kind: 'metric_monitor', source_id: 'monitor:node-a', matched_events: [{ group_by: 'instance', series_key: 'node-a', labels: { mountpoint: '/', 'nano.cluster': 'iad1', pool: 'workers', ignored: 7 }, evaluated_at: '2026-10-16T21:00:00Z', value: 6.4 }] });
    expect(alert?.labels).toEqual({ instance: 'node-a', mountpoint: '/', 'nano.cluster': 'iad1', pool: 'workers' });
    expect(monitorLabelText(alert!)).toContain('instance=node-a');
    expect(monitorLabelText(alert!)).toContain('mountpoint=/');
    expect(alert?.evaluatedAt).toBe('2026-10-16T21:00:00Z');
  });
  it('renders legacy payload group keys and tolerates missing labels', () => {
    const alert = parseMonitorAlert({ kind: 'metric_monitor', matched_events: [{ group_by: 'instance', series_key: 'node-b' }] });
    expect(monitorLabelText(alert!)).toBe('instance=node-b');
    expect(monitorLabelText(parseMonitorAlert({ kind: 'metric_monitor', matched_events: [] })!)).toBe('');
  });
});
