import { describe, expect, it } from 'vitest';
import { backgroundHealth, isBackgroundService, latencyClass } from './workload';

describe('background APM policy', () => {
  it('classifies complete job and scheduler roles without hiding interactive services', () => {
    for (const service of ['lake-jobs', 'job', 'tenant.scheduler.2', 'JOBS']) expect(isBackgroundService(service)).toBe(true);
    for (const service of ['jobs-api', 'myjobs', 'jobs-search', 'api']) expect(isBackgroundService(service)).toBe(false);
  });
  it('keeps slow jobs and scheduler operations neutral while preserving foreground thresholds', () => {
    expect(latencyClass('lake-jobs', 'p99', 2320)).toBe('text-fg-2');
    expect(latencyClass('lake-jobs', 'p95', 1160)).toBe('text-fg-2');
    expect(latencyClass('api', 'p95', 5000, 'evaluate_metric_monitor')).toBe('text-fg-2');
    expect(latencyClass('api', 'p95', 5000, 'scheduler.tick')).toBe('text-fg-2');
    expect(latencyClass('api', 'p99', 2320)).toBe('text-danger');
    expect(latencyClass('api', 'p95', 1160)).toBe('text-warn');
  });
  it('still reports background failures', () => {
    expect(backgroundHealth(0)).toBe('neutral');
    expect(backgroundHealth(0.01)).toBe('warn');
    expect(backgroundHealth(0.05)).toBe('danger');
  });
});
