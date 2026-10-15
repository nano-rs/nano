// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub: pull collectors are enterprise-only (NAN-3861). The open
// `useHostedCollectors` stub yields no rows, so no card is ever rendered; one
// that is would be a wiring bug, so it fails loudly instead of rendering
// nothing (check-enterprise-stub-gating).
import type { CollectorRow } from './useHostedCollectors';

export function CollectorCard(_props: CollectorRow & {
  canInstall: boolean; canRemove: boolean; canRotate?: boolean; queryKey: readonly unknown[];
}): never {
  throw new Error('Pull collectors are not available in the open edition');
}
