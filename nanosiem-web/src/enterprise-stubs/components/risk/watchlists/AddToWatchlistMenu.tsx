// SPDX-License-Identifier: AGPL-3.0-or-later
/* eslint-disable @typescript-eslint/no-unused-vars -- open-edition stub keeps the enterprise signatures */

// Open-edition stub. Risk watchlists are enterprise-only; the trigger is not rendered.

import type { ReactNode } from 'react';

export interface AddToWatchlistMenuProps {
  entity: string;
  entityType: string;
  children: ReactNode;
  align?: 'start' | 'end';
}

export function AddToWatchlistMenu(_props: AddToWatchlistMenuProps) {
  return null;
}

export default AddToWatchlistMenu;
