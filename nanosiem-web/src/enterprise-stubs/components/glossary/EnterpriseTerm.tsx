// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: open-edition stub. Enterprise terms have no definition in open
// core, so the label renders as plain text.

import type { ReactNode } from 'react';

export interface EnterpriseTermProps {
  id: string;
  children?: ReactNode;
  side?: 'top' | 'right' | 'bottom' | 'left';
  align?: 'start' | 'center' | 'end';
  nested?: boolean;
  className?: string;
  'data-testid'?: string;
}

export function EnterpriseTerm({ children }: EnterpriseTermProps) {
  return <>{children}</>;
}
