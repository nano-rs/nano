// SPDX-License-Identifier: AGPL-3.0-or-later

import { toast as sonnerToast } from 'sonner';
import { SESSION_EXPIRED_MESSAGE } from '@/lib/session-credentials';

interface ToastAction {
  label: string;
  onClick: () => void;
}

interface ToastOptions {
  title?: string;
  description?: string;
  /** `info`: neutral, e.g. a deploy still being installed (NAN-5279). */
  variant?: 'default' | 'destructive' | 'info';
  action?: ToastAction;
  duration?: number;
}

function toast({ title, description, variant, action, duration }: ToastOptions) {
  // NAN-2453: AuthContext owns the single session-expired prompt; a
  // SessionExpiredError surfaced by N failed requests must not toast N times.
  if (description === SESSION_EXPIRED_MESSAGE || title === SESSION_EXPIRED_MESSAGE) return;
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
  if (variant === 'info') {
    return sonnerToast.info(title, opts);
  }
  return sonnerToast.success(title, opts);
}

function useToast() {
  return { toast };
}

export { useToast, toast };
