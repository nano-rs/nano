import { describe, expect, it } from 'vitest';
import { QUERY_TOO_LARGE, searchJobFailure } from './search-job-error';

describe('searchJobFailure (NAN-3911)', () => {
  it('maps query_too_large to its own non-retry code with the actionable text', () => {
    const message =
      'This search needs more memory than one query can use. Narrow the time range, add filters, or reduce distinct-count fields.';
    expect(searchJobFailure({ error: message, error_code: 'query_too_large' })).toEqual({
      code: QUERY_TOO_LARGE,
      message,
    });
  });

  it('falls back to actionable text when the error is missing', () => {
    const failure = searchJobFailure({ error_code: 'query_too_large' });
    expect(failure.code).toBe(QUERY_TOO_LARGE);
    expect(failure.message).toMatch(/Narrow the time range/);
  });

  it('keeps generic failures on the retryable JOB_FAILED path', () => {
    expect(searchJobFailure({ error: 'isolated query execution failed' })).toEqual({
      code: 'JOB_FAILED',
      message: 'isolated query execution failed',
    });
    expect(searchJobFailure({}, 'PARSE_ERROR')).toEqual({ code: 'PARSE_ERROR', message: 'Search job failed' });
  });
});
