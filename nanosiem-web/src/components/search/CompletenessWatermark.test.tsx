// SPDX-License-Identifier: AGPL-3.0-or-later

import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { CompletenessWatermark } from './CompletenessWatermark';

describe('CompletenessWatermark', () => {
  for (const notice of [false, true, undefined]) {
    it(`shows the watermark regardless of notice decision ${notice}`, () => {
      const markup = renderToStaticMarkup(<CompletenessWatermark completeness={{
        status: 'stale',
        reason: 'publication_consumer_lag',
        events_complete_through_ms: Date.parse('2026-09-18T22:56:08Z'),
        freshness_notice_required: notice,
      }} />);
      expect(markup).toContain('complete through 22:56:08Z');
      expect(markup).toContain('2026-09-18T22:56:08.000Z (publication_consumer_lag)');
      expect(markup).toContain('font-mono text-[10.5px]');
      expect(markup).not.toContain('Re-run');
      expect(markup).not.toContain('role="alert"');
    });
  }

  it('omits missing and invalid watermarks', () => {
    expect(renderToStaticMarkup(<CompletenessWatermark />)).toBe('');
    expect(renderToStaticMarkup(<CompletenessWatermark completeness={{
      status: 'stale', events_complete_through_ms: NaN,
    }} />)).toBe('');
  });
});
