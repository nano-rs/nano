// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from 'vitest';
import { ApiClientError } from '@/lib/api';
import { isAdmissionDenied, isViewMemoryBusy, retryOnAdmissionDenied } from './admission-retry';

describe('admission retry (NAN-4664)', () => {
  it('recognizes only admission refusals', () => {
    expect(isAdmissionDenied(new ApiClientError('busy', 'ADMISSION_DENIED', undefined, 429))).toBe(true);
    expect(isAdmissionDenied(new ApiClientError('bad', 'INVALID_QUERY', undefined, 400))).toBe(false);
    expect(isAdmissionDenied(new Error('x'))).toBe(false);
  });

  it('retries a refusal and returns the eventual result', async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new ApiClientError('busy', 'ADMISSION_DENIED', undefined, 429))
      .mockResolvedValueOnce('rows');
    const result = retryOnAdmissionDenied(fn);
    await vi.runAllTimersAsync();
    await expect(result).resolves.toBe('rows');
    expect(fn).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it('retries a transient view memory refusal but never a too-large view (NAN-3077)', async () => {
    expect(isViewMemoryBusy(new ApiClientError('busy', 'VIEW_MEMORY_BUSY', undefined, 503))).toBe(true);
    expect(isViewMemoryBusy(new ApiClientError('big', 'VIEW_TOO_LARGE', undefined, 413))).toBe(false);
    vi.useFakeTimers();
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new ApiClientError('busy', 'VIEW_MEMORY_BUSY', undefined, 503))
      .mockResolvedValueOnce('view');
    const result = retryOnAdmissionDenied(fn);
    await vi.runAllTimersAsync();
    await expect(result).resolves.toBe('view');
    vi.useRealTimers();
    const big = vi.fn<() => Promise<string>>().mockRejectedValue(new ApiClientError('big', 'VIEW_TOO_LARGE', undefined, 413));
    await expect(retryOnAdmissionDenied(big)).rejects.toThrow('big');
    expect(big).toHaveBeenCalledTimes(1);
  });

  it('never retries a real error', async () => {
    const fn = vi.fn<() => Promise<string>>().mockRejectedValue(new ApiClientError('bad', 'INVALID_QUERY', undefined, 400));
    await expect(retryOnAdmissionDenied(fn)).rejects.toThrow('bad');
    expect(fn).toHaveBeenCalledTimes(1);
  });
});
