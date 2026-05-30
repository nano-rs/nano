// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-967: Alert detail page (`/alerts/:id`) had no triage CTAs — analysts
// had to bounce back to the /alerts list to act on an alert they were
// already looking at. This component bundles the Acknowledge / Assign /
// Close button row + their dialogs into a self-contained surface that
// AlertDetail.tsx can drop in beneath AlertHero. Mirrors the per-row
// pattern from /alerts (Alerts.tsx).
//
// NAN-1066: open-core surface only — enterprise tenants triage via Cases,
// so the whole bar is hidden when `capabilities.cases` is true.
//
// Escalate-to-case is intentionally NOT included — the backend endpoint
// `/api/alerts/{id}/escalate-to-case` doesn't exist yet. Tracked
// separately as a follow-up.

import { useCallback, useEffect, useState } from 'react';
import { Check, CircleCheck, UserPlus, Loader2 } from 'lucide-react';

import { api } from '@/lib/api';
import type { UserDetail } from '@/lib/api/types';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

type Disposition = 'true_positive' | 'false_positive' | 'benign';

interface AlertTriageBarProps {
  alertId: string;
  ruleName?: string;
  status: 'new' | 'open' | 'acknowledged' | 'closed';
  /** Optional: pre-fill the assignee picker (e.g. with the current owner). */
  currentAssignee?: string | null;
  /** Called after a successful mutation so the page can refetch + reflect. */
  onActionComplete?: () => void;
}

export function AlertTriageBar({
  alertId,
  ruleName,
  status,
  currentAssignee,
  onActionComplete,
}: AlertTriageBarProps) {
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();
  const { toast } = useToast();

  const canAck = hasPermission('alerts:acknowledge');
  const canClose = hasPermission('alerts:close');
  const canAssign = hasPermission('alerts:assign');

  const [busy, setBusy] = useState(false);
  const [closeOpen, setCloseOpen] = useState(false);
  const [closeDisposition, setCloseDisposition] = useState<Disposition>('true_positive');
  const [assignOpen, setAssignOpen] = useState(false);
  const [assignTo, setAssignTo] = useState<string>('');
  const [users, setUsers] = useState<UserDetail[]>([]);

  const isOpen = status === 'open' || status === 'new';
  const isClosed = status === 'closed';

  // NAN-1066: lazy-load the active user list when the assign dialog opens.
  // Avoids hitting /api/users on every alert detail render.
  useEffect(() => {
    if (!assignOpen || users.length > 0) return;
    let cancelled = false;
    api
      .listUsers()
      .then((res) => {
        if (cancelled) return;
        setUsers(res.users.filter((u) => u.status === 'active'));
      })
      .catch((err) => {
        // eslint-disable-next-line no-console
        console.error('Failed to load users for assign picker', err);
      });
    return () => {
      cancelled = true;
    };
  }, [assignOpen, users.length]);

  const acknowledge = useCallback(async () => {
    setBusy(true);
    try {
      await api.acknowledgeAlert(alertId);
      toast({ title: 'Acknowledged' });
      onActionComplete?.();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to acknowledge alert', err);
      toast({
        title: 'Could not acknowledge',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  }, [alertId, onActionComplete, toast]);

  const submitClose = useCallback(async () => {
    setBusy(true);
    setCloseOpen(false);
    try {
      await api.closeAlert(alertId, { disposition: closeDisposition });
      toast({ title: 'Closed' });
      onActionComplete?.();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to close alert', err);
      toast({
        title: 'Could not close',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  }, [alertId, closeDisposition, onActionComplete, toast]);

  const submitAssign = useCallback(async () => {
    if (!assignTo) {
      setAssignOpen(false);
      return;
    }
    const assignee = users.find((u) => u.id === assignTo);
    const displayName = assignee?.name ?? assignTo;
    setBusy(true);
    setAssignOpen(false);
    try {
      await api.assignAlert(alertId, assignTo);
      toast({ title: `Assigned to ${displayName}` });
      onActionComplete?.();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to assign alert', err);
      toast({
        title: 'Could not assign',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  }, [alertId, assignTo, onActionComplete, toast, users]);

  // NAN-1066: enterprise tenants have Cases; the single-alert lifecycle
  // (ack/close/assign) is the open-core triage workflow only.
  if (capabilities.cases) {
    return null;
  }

  // If everything is gated off / alert closed, render nothing — keeps
  // the page tidy when an analyst is just reviewing a closed alert.
  if (isClosed || (!canAck && !canClose && !canAssign)) {
    return null;
  }

  return (
    <>
      <div className="flex items-center gap-2 mt-2">
        {isOpen && canAck && (
          <button
            type="button"
            onClick={acknowledge}
            disabled={busy}
            className="h-7 px-2.5 rounded-md border border-border bg-card text-[11.5px] text-foreground hover:bg-foreground/5 inline-flex items-center gap-1.5 disabled:opacity-50"
            title="Acknowledge alert"
          >
            {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
            Acknowledge
          </button>
        )}
        {canAssign && (
          <button
            type="button"
            onClick={() => {
              setAssignTo('');
              setAssignOpen(true);
            }}
            disabled={busy}
            className="h-7 px-2.5 rounded-md border border-border bg-card text-[11.5px] text-foreground hover:bg-foreground/5 inline-flex items-center gap-1.5 disabled:opacity-50"
            title="Assign to an analyst"
          >
            <UserPlus className="h-3 w-3" />
            Assign{currentAssignee ? `: ${currentAssignee}` : '…'}
          </button>
        )}
        {canClose && (
          <button
            type="button"
            onClick={() => setCloseOpen(true)}
            disabled={busy}
            className="h-7 px-2.5 rounded-md border border-border bg-card text-[11.5px] text-foreground hover:bg-foreground/5 inline-flex items-center gap-1.5 disabled:opacity-50"
            title="Close with a disposition"
          >
            <CircleCheck className="h-3 w-3" />
            Close…
          </button>
        )}
      </div>

      {/* Close dialog — mirrors the dialog in /alerts (Alerts.tsx). */}
      <Dialog open={closeOpen} onOpenChange={setCloseOpen}>
        <DialogContent className="sm:max-w-[420px]">
          <DialogHeader>
            <DialogTitle className="text-[14px]">Close alert</DialogTitle>
            <DialogDescription className="text-[11.5px]">
              {ruleName ? (
                <span className="font-mono">{ruleName}</span>
              ) : (
                'Pick a disposition. The alert lifecycle records who closed it and how.'
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="alert-close-disposition" className="text-[11.5px]">
              Disposition
            </Label>
            <Select
              value={closeDisposition}
              onValueChange={(v) => setCloseDisposition(v as Disposition)}
            >
              <SelectTrigger id="alert-close-disposition" className="h-8 text-[11.5px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true_positive" className="text-[11.5px]">True positive</SelectItem>
                <SelectItem value="false_positive" className="text-[11.5px]">False positive</SelectItem>
                <SelectItem value="benign" className="text-[11.5px]">Benign</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCloseOpen(false)}
              className="h-8 text-[11.5px]"
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={submitClose}
              className="h-8 text-[11.5px]"
              disabled={busy}
            >
              Close alert
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Assign dialog — picks from active users. */}
      <Dialog open={assignOpen} onOpenChange={setAssignOpen}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader>
            <DialogTitle className="text-[14px]">Assign alert</DialogTitle>
            <DialogDescription className="text-[11.5px]">
              {ruleName ? (
                <span className="font-mono">{ruleName}</span>
              ) : (
                'Pick the analyst who owns this alert.'
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="alert-assign-to" className="text-[11.5px]">
              Assignee
            </Label>
            <Select value={assignTo} onValueChange={setAssignTo}>
              <SelectTrigger id="alert-assign-to" className="h-8 text-[11.5px]">
                <SelectValue placeholder={users.length === 0 ? 'Loading users…' : 'Select an analyst'} />
              </SelectTrigger>
              <SelectContent>
                {users.map((u) => (
                  <SelectItem key={u.id} value={u.id} className="text-[11.5px]">
                    {u.name}
                    <span className="ml-2 text-muted-foreground font-mono text-[10.5px]">
                      {u.email}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setAssignOpen(false)}
              className="h-8 text-[11.5px]"
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={submitAssign}
              className="h-8 text-[11.5px]"
              disabled={busy || !assignTo}
            >
              Assign
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
