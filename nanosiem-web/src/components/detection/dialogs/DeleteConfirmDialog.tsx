// SPDX-License-Identifier: AGPL-3.0-or-later

import { ConfirmDialog } from '@/components/ui/confirm-dialog';

interface DeleteConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  ruleName?: string;
  loading?: boolean;
}

export function DeleteConfirmDialog({
  open,
  onOpenChange,
  onConfirm,
  ruleName,
  loading,
}: DeleteConfirmDialogProps) {
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      variant="danger"
      title="Delete Detection Rule?"
      description={
        <>
          This will permanently delete the detection rule "
          <span className="text-foreground font-medium">{ruleName}</span>". This action cannot be
          undone. All associated alerts and matches will remain but will no longer be linked to this
          rule.
        </>
      }
      confirmLabel="Delete Rule"
      loadingLabel="Deleting…"
      loading={loading}
      onConfirm={onConfirm}
    />
  );
}
