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
          The detection rule "
          <span className="text-foreground font-medium">{ruleName}</span>" stops running and moves to
          Archived. Its matches and alerts are kept and stay linked to it.
        </>
      }
      confirmLabel="Delete Rule"
      loadingLabel="Deleting…"
      loading={loading}
      onConfirm={onConfirm}
    />
  );
}
