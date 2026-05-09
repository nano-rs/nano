// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stubs for SSO provider icons. The real icons (Microsoft,
// Google, Okta, generic) live under `@/enterprise/components/icons/SsoIcons`.
// Login.tsx gates the SSO surface behind `capabilities.sso` so these stubs
// are unreachable in an open build; they exist purely to satisfy the alias
// resolution and any rare residual reference.

import type { FC } from 'react';

interface IconProps {
  className?: string;
}

const NullIcon: FC<IconProps> = () => null;

export const MicrosoftIcon: FC<IconProps> = NullIcon;
export const GoogleIcon: FC<IconProps> = NullIcon;
export const OktaIcon: FC<IconProps> = NullIcon;
export const GenericSsoIcon: FC<IconProps> = NullIcon;

export function getSsoIcon(_provider: { name: string; slug: string }): FC<IconProps> {
  return NullIcon;
}
