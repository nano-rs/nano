// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, test } from 'vitest';
import { CapabilitiesContext, type CapabilitiesContextValue } from '@/hooks/use-capabilities';
import { AccessHeader } from './AccessHeader';

afterEach(cleanup);

function withSso(sso: boolean) {
  const value = {
    edition: sso ? 'enterprise' : 'open',
    version: 'test',
    capabilities: { sso },
  } as unknown as CapabilitiesContextValue;
  return render(
    <CapabilitiesContext.Provider value={value}>
      <AccessHeader tab="groups" />
    </CapabilitiesContext.Provider>,
  );
}

// NAN-5274: open builds never claim SCIM; enterprise (SSO) builds do.
test('open builds do not mention SCIM on the Groups page', () => {
  withSso(false);
  expect(screen.getByText('Put users in groups so they share a role and the sources they can see.')).toBeTruthy();
  expect(screen.queryByText(/SCIM/)).toBeNull();
});

test('SSO builds describe IdP-managed membership', () => {
  withSso(true);
  expect(screen.getByText(/SSO and SCIM can manage who is in each group/)).toBeTruthy();
});

test('without a capabilities provider nothing SCIM renders', () => {
  render(<AccessHeader tab="groups" />);
  expect(screen.queryByText(/SCIM/)).toBeNull();
});
