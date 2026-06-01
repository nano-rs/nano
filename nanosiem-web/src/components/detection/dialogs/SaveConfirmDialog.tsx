// SPDX-License-Identifier: AGPL-3.0-or-later

import { ConfirmDialog } from '@/components/ui/confirm-dialog';

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
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      variant="default"
      title="Save Detection Rule?"
      description={
        <>
          This will update the detection rule "{ruleName}".
          {mode === 'live' && ' The rule is in live mode and will start detecting immediately.'}
          {mode === 'alerting' &&
            ' The rule is in alerting mode and will create alerts on matches.'}
        </>
      }
      confirmLabel="Save Rule"
      loadingLabel="Saving…"
      loading={loading}
      onConfirm={onConfirm}
    />
  );
}
