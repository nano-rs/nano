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
import { Loader2 } from 'lucide-react';

interface SaveConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  ruleName?: string;
  mode?: 'staging' | 'live' | 'alerting' | 'paused';
  previousMode?: 'staging' | 'live' | 'alerting' | 'paused';
  loading?: boolean;
}

export function SaveConfirmDialog({
  open,
  onOpenChange,
  onConfirm,
  ruleName,
  mode,
  loading,
}: SaveConfirmDialogProps) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="bg-card border-border text-foreground">
        <AlertDialogHeader>
          <AlertDialogTitle>Save Detection Rule?</AlertDialogTitle>
          <AlertDialogDescription className="text-muted-foreground">
            This will update the detection rule "{ruleName}".
            {mode === 'live' && ' The rule is in live mode and will start detecting immediately.'}
            {mode === 'alerting' && ' The rule is in alerting mode and will create alerts on matches.'}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel className="bg-accent/50 border-border text-foreground hover:bg-accent">
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            disabled={loading}
            className="bg-primary hover:bg-primary/90 text-foreground"
          >
            {loading ? <><Loader2 className="w-4 h-4 mr-1 animate-spin" />Saving...</> : 'Save Rule'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
