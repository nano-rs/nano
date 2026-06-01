// SPDX-License-Identifier: AGPL-3.0-or-later

import { ConfirmDialog } from '@/components/ui/confirm-dialog';

interface ArchiveConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  ruleName?: string;
  isArchived?: boolean;
  loading?: boolean;
}

export function ArchiveConfirmDialog({
  open,
  onOpenChange,
  onConfirm,
  ruleName,
  isArchived,
  loading,
}: ArchiveConfirmDialogProps) {
  if (isArchived) {
    // Unarchive dialog
    return (
      <ConfirmDialog
        open={open}
        onOpenChange={onOpenChange}
        variant="default"
        title="Unarchive Detection Rule?"
        description={
          <>
            This will unarchive the detection rule "
            <span className="text-foreground font-medium">{ruleName}</span>" and move it to staging
            mode. You can then edit and test the rule before enabling it.
          </>
        }
        confirmLabel="Unarchive Rule"
        loading={loading}
        onConfirm={onConfirm}
      />
    );
  }

  // Archive dialog
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      variant="warning"
      title="Archive Detection Rule?"
      description={
        <>
          This will archive the detection rule "
          <span className="text-foreground font-medium">{ruleName}</span>". Archived rules are
          hidden by default and must be unarchived before they can be activated. The rule will be set
          to staging mode.
        </>
      }
      confirmLabel="Archive Rule"
      loading={loading}
      onConfirm={onConfirm}
    />
  );
}
