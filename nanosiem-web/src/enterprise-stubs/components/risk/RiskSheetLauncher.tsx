// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub. The risk-object sheet (entity risk breakdown) is
// enterprise-only; surfaces get `null` and keep their own behaviour.

import type { ReactNode } from 'react';

export interface RiskSheetLauncherProps {
  entity: string;
  entityType: string;
  score?: number | null;
  children: (open: (() => void) | null) => ReactNode;
}

export function RiskSheetLauncher({ children }: RiskSheetLauncherProps) {
  return <>{children(null)}</>;
}

export default RiskSheetLauncher;
