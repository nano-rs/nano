// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
  countTeamMembers,
  isOrgContextConfigured,
  overlayLogSourceStatus,
  resolveHostedChecklistStatus,
} from './onboarding-status';
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

describe('isOrgContextConfigured (NAN-4779)', () => {
  const empty = {
    organization_name: null, industry: null, environment: null,
    attack_vectors: null, compliance_frameworks: [], custom_context: null,
  };
  it('is false for no context or only blank fields', () => {
    expect(isOrgContextConfigured(undefined)).toBe(false);
    expect(isOrgContextConfigured(empty)).toBe(false);
    expect(isOrgContextConfigured({ ...empty, organization_name: '   ' })).toBe(false);
  });
  it('is true for any saved guidance field, not only the name', () => {
    expect(isOrgContextConfigured({ ...empty, organization_name: 'Acme' })).toBe(true);
    expect(isOrgContextConfigured({ ...empty, custom_context: 'We run Okta' })).toBe(true);
    expect(isOrgContextConfigured({ ...empty, compliance_frameworks: ['HIPAA'] })).toBe(true);
  });
});

describe('countTeamMembers (NAN-4779)', () => {
  it('counts active dedicated users', () => {
    expect(countTeamMembers([{ status: 'active' }, { status: 'disabled' }, { status: 'active' }])).toBe(2);
  });
  it('counts active memberships and pending invitations on hosted-shared', () => {
    expect(
      countTeamMembers([
        { status: 'active', membership_status: 'active', invitation_state: 'consumed' },
        { status: 'active', membership_status: 'suspended', invitation_state: 'pending' },
        { status: 'active', membership_status: 'suspended', invitation_state: 'expired' },
      ]),
    ).toBe(2);
  });
});

describe('resolveHostedChecklistStatus (NAN-4779)', () => {
  it('only ever turns steps on', () => {
    const done = { ...base, has_org_context: true, has_users: true };
    expect(resolveHostedChecklistStatus(done, {})).toMatchObject({ has_org_context: true, has_users: true });
    expect(resolveHostedChecklistStatus(base, {})).toMatchObject({ has_org_context: false, has_users: false });
    expect(resolveHostedChecklistStatus(undefined, { users: [] })).toBeUndefined();
  });
});
