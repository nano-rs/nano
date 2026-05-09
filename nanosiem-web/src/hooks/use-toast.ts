// SPDX-License-Identifier: AGPL-3.0-or-later

import { toast as sonnerToast } from 'sonner';

interface ToastAction {
  label: string;
  onClick: () => void;
}

interface ToastOptions {
  title?: string;
  description?: string;
  variant?: 'default' | 'destructive';
  action?: ToastAction;
  duration?: number;
}

function toast({ title, description, variant, action, duration }: ToastOptions) {
  const opts: Record<string, unknown> = { description };
  if (action) {
    opts.action = { label: action.label, onClick: action.onClick };
  }
  if (duration !== undefined) {
    opts.duration = duration;
  }
  if (variant === 'destructive') {
    return sonnerToast.error(title, opts);
  }
  return sonnerToast.success(title, opts);
}

function useToast() {
  return { toast };
}

export { useToast, toast };
