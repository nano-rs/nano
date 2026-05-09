// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for the OIDC provider create/edit flyout. The real
// component is gated behind `capabilities.sso` so this stub is unreachable
// from the open Login + Settings surfaces; it exists only to satisfy the
// `@/enterprise/pages/Settings/OidcProviderSheet` import resolution and any
// dead-code path that survives tree-shaking.

interface OidcProviderSheetProps {
  providerKey: string | null;
  onClose: () => void;
  onSaved: () => void;
}

export function OidcProviderSheet(_props: OidcProviderSheetProps) {
  return null;
}

export default OidcProviderSheet;
