// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Human-readable detail for a failed API call (NAN-2787).
 *
 * The API wraps extractor rejections as
 * `{ code: 'VALIDATION_ERROR', message: 'Invalid request body', details: { validation: 'missing field `sla`' } }`
 * and handler errors as `{ message: '<reason>' }`. Prefer the field-level
 * validation hint over the generic message so a toast says *why* a save failed.
 */
export function apiErrorDetail(err: unknown): string | undefined {
  if (!(err instanceof Error)) return undefined;
  const details = (err as { details?: unknown }).details;
  if (details && typeof details === 'object') {
    const validation = (details as Record<string, unknown>).validation;
    if (typeof validation === 'string' && validation.trim()) {
      return `${err.message}: ${validation}`;
    }
  }
  return err.message || undefined;
}
