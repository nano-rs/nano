// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { ApiClientError } from '@/lib/api';
import { apiErrorDetail } from './api-error-detail';

describe('apiErrorDetail', () => {
  it('appends the server validation hint to the generic message', () => {
    const err = new ApiClientError('Invalid request body', 'VALIDATION_ERROR', {
      validation: 'missing field `sla`',
    }, 422);
    expect(apiErrorDetail(err)).toBe('Invalid request body: missing field `sla`');
  });

  it('falls back to the message for handler errors', () => {
    const err = new ApiClientError('max_alerts_per_case must be between 1 and 1000', 'BAD_REQUEST', undefined, 400);
    expect(apiErrorDetail(err)).toBe('max_alerts_per_case must be between 1 and 1000');
  });

  it('returns undefined for non-errors', () => {
    expect(apiErrorDetail('nope')).toBeUndefined();
  });
});
