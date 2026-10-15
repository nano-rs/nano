// SPDX-License-Identifier: AGPL-3.0-or-later

interface VersionHistoryModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  versions: unknown[];
  onRevert: (versionId: number) => Promise<void>;
  loading?: boolean;
}

/** Hosted rule-version history is unavailable in the open edition. */
export function VersionHistoryModal(_props: VersionHistoryModalProps) {
  return null;
}
