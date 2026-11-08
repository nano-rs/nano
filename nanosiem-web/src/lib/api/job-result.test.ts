// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4753: custom enrichment and integration code generation run as jobs.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CustomEnrichmentApi } from '@/enterprise/api/custom-enrichment';
import { IntegrationsApi } from './integrations';
import { resolveJobResult } from './job-result';

const CF_524 = '<!DOCTYPE html><html><head><title>524</title><script>x()</script></head><body>Cloudflare Ray ID: <strong>a51666239c020c02</strong></body></html>';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('resolveJobResult', () => {
  it('reports job progress while polling', async () => {
    vi.useFakeTimers();
    const fetchJob = vi.fn()
      .mockResolvedValueOnce({ status: 'running', progress: 'pivt is writing the enrichment module' })
      .mockResolvedValueOnce({ status: 'completed', result: { ok: true } });
    const onProgress = vi.fn();
    const pending = resolveJobResult({ job_id: 'job-p' }, fetchJob as never, { failure: 'x', onProgress });
    await vi.advanceTimersByTimeAsync(4_100);
    await expect(pending).resolves.toEqual({ ok: true });
    expect(onProgress).toHaveBeenNthCalledWith(1, expect.objectContaining({ jobId: 'job-p', status: 'pending' }));
    expect(onProgress).toHaveBeenNthCalledWith(2, expect.objectContaining({ status: 'running', message: 'pivt is writing the enrichment module' }));
  });
});

describe('CustomEnrichmentApi.generateCode', () => {
  const result = { code: 'export default 1', explanation: 'x', detected_fields: [], suggested_domains: [] };

  it('asks for a job and polls it to its result', async () => {
    vi.useFakeTimers();
    const request = vi.fn()
      .mockResolvedValueOnce({ job_id: 'job-9', status: 'pending' })
      .mockResolvedValueOnce({ status: 'running', progress: 'Working...' })
      .mockResolvedValueOnce({ status: 'completed', result });
    const api = new CustomEnrichmentApi(request as never);
    const pending = api.generateCode({ enrichment_type: 'data', description: 'd', key_type: 'ip' } as never);
    await vi.advanceTimersByTimeAsync(4_100);
    await expect(pending).resolves.toEqual(result);
    expect(request).toHaveBeenNthCalledWith(1, '/api/custom-enrichments/generate-code', expect.objectContaining({ headers: { Prefer: 'respond-async' } }));
    expect(request).toHaveBeenNthCalledWith(2, '/api/melod/jobs/job-9');
  });

  it('a synchronous answer is returned as is', async () => {
    const api = new CustomEnrichmentApi(vi.fn().mockResolvedValue(result) as never);
    await expect(api.generateCode({} as never)).resolves.toEqual(result);
  });

  it('a failed job surfaces its message, never markup', async () => {
    vi.useFakeTimers();
    const request = vi.fn()
      .mockResolvedValueOnce({ job_id: 'job-2', status: 'pending' })
      .mockResolvedValueOnce({ status: 'failed', error: CF_524 });
    const api = new CustomEnrichmentApi(request as never);
    const pending = api.generateCode({} as never);
    const assertion = expect(pending).rejects.toThrow('Code generation failed. Retry in a moment. Reference a51666239c020c02.');
    await vi.advanceTimersByTimeAsync(2_100);
    await assertion;
  });
});

describe('IntegrationsApi.generateCustomCollectorCode', () => {
  it('polls the collector job to its code', async () => {
    vi.useFakeTimers();
    const code = { code: 'export default {}', explanation: 'e', warnings: [] };
    const request = vi.fn()
      .mockResolvedValueOnce({ job_id: 'job-c', status: 'running' })
      .mockResolvedValueOnce({ status: 'completed', result: code });
    const api = new IntegrationsApi(request as never);
    const pending = api.generateCustomCollectorCode({ description: 'd' } as never);
    await vi.advanceTimersByTimeAsync(2_100);
    await expect(pending).resolves.toEqual(code);
    expect(request).toHaveBeenNthCalledWith(1, '/api/integrations/custom/generate-code', expect.objectContaining({ headers: expect.objectContaining({ Prefer: 'respond-async' }) }));
    expect(request).toHaveBeenNthCalledWith(2, '/api/melod/jobs/job-c');
  });
});
