// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub: SOAR never ships in open builds, so it is never on.

export interface SoarStatus {
  /** SOAR is switched on (Automation nav + routes usable). */
  enabled: boolean;
  /** Pending approvals visible to the viewer (0 when unknown). */
  pendingApprovals: number;
}

export function useSoarStatus(): SoarStatus {
  return { enabled: false, pendingApprovals: 0 };
}
