// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { overlayLogSourceStatus } from './onboarding-status';
import type { OnboardingStatus } from '@/lib/api/onboarding';

const base: OnboardingStatus = {
  has_ai_provider: true,
  has_org_context: false,
  has_users: false,
  has_sso: false,
  has_log_sources: false,
  has_parsers: false,
  has_search_history: true,
};

describe('overlayLogSourceStatus', () => {
  it('passes status through when there are no registry sources', () => {
    expect(overlayLogSourceStatus(base, [])).toBe(base);
    expect(overlayLogSourceStatus(base, undefined)).toBe(base);
    expect(overlayLogSourceStatus(undefined, [{ deployed: true, parser_vrl: '.' }])).toBeUndefined();
  });

  it('marks sources and parsers done for deployed registry sources', () => {
    const out = overlayLogSourceStatus(base, [{ deployed: true, parser_vrl: '' }]);
    expect(out).toMatchObject({ has_log_sources: true, has_parsers: true, has_search_history: true });
  });

  it('counts an undeployed source with VRL as a parser, and an empty draft as a source only', () => {
    expect(overlayLogSourceStatus(base, [{ deployed: false, parser_vrl: '. = parse_json!(.message)' }]))
      .toMatchObject({ has_log_sources: true, has_parsers: true });
    expect(overlayLogSourceStatus(base, [{ deployed: false, parser_vrl: '  ' }]))
      .toMatchObject({ has_log_sources: true, has_parsers: false });
  });
});
