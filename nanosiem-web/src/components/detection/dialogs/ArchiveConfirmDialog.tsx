// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';

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
      <AlertDialog open={open} onOpenChange={onOpenChange}>
        <AlertDialogContent className="bg-card border-border text-foreground">
          <AlertDialogHeader>
            <AlertDialogTitle>Unarchive Detection Rule?</AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground">
              This will unarchive the detection rule "{ruleName}" and move it to staging mode.
              You can then edit and test the rule before enabling it.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent" disabled={loading}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={onConfirm}
              disabled={loading}
              className=""
            >
              Unarchive Rule
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    );
  }

  // Archive dialog
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="bg-card border-border text-foreground">
        <AlertDialogHeader>
          <AlertDialogTitle>Archive Detection Rule?</AlertDialogTitle>
          <AlertDialogDescription className="text-muted-foreground">
            This will archive the detection rule "{ruleName}". Archived rules are hidden by default
            and must be unarchived before they can be activated. The rule will be set to staging mode.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent" disabled={loading}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            disabled={loading}
            className="bg-yellow-600 hover:bg-yellow-700 text-foreground"
          >
            Archive Rule
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
