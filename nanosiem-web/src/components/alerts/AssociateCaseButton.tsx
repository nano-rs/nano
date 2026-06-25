// SPDX-License-Identifier: AGPL-3.0-or-later

// AssociateCaseButton — opt-in "Add to case" affordance for an alert.
//
// The case_alerts link + backend route (POST is wrapped by api.addAlertToCase)
// already exist and were only reachable FROM a case ("pull an alert in"). This
// adds the reverse entry point FROM an alert, kind-agnostic: it just links
// `alert_id`, so it serves detection AND observability monitor alerts (a monitor
// alert has no rule/entities, which doesn't matter for a plain link).
//
// Cases is an enterprise capability — the component self-gates on
// `capabilities.cases` and renders nothing on open builds (where the backing
// route is 404 anyway). Manual association only links the alert; it does NOT
// trigger the security shadow-investigation (that fires on case creation /
// auto-grouping, not on a manual attach).

import { useCallback, useMemo, useState } from 'react';
import { FolderPlus, Loader2, Search as SearchIcon } from 'lucide-react';

import { api, type CaseSummary } from '@/lib/api';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

interface AssociateCaseButtonProps {
  alertId: string;
  /** Called after a successful association so the page can refetch. */
  onAssociated?: () => void;
}

const SEV_TONE: Record<CaseSummary['severity'], string> = {
  critical: 'text-destructive',
  high: 'text-warning',
  medium: 'text-warning',
  low: 'text-muted-foreground',
  informational: 'text-muted-foreground',
};

export function AssociateCaseButton({ alertId, onAssociated }: AssociateCaseButtonProps) {
  const { capabilities } = useCapabilities();
  const { toast } = useToast();

  const [open, setOpen] = useState(false);
  const [cases, setCases] = useState<CaseSummary[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);

  const loadCases = useCallback(async () => {
    setLoading(true);
    try {
      // Recent open cases are the common attach target; client-side filter
      // narrows the loaded slice.
      const mine = await api.getMyCases(50);
      setCases(mine);
    } catch {
      setCases([]);
      toast({ title: 'Could not load cases', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const onOpenChange = (next: boolean) => {
    setOpen(next);
    if (next && cases == null) loadCases();
    if (!next) setQuery('');
  };

  const associate = useCallback(
    async (c: CaseSummary) => {
      setBusyId(c.id);
      try {
        await api.addAlertToCase(c.id, { alert_id: alertId });
        toast({ title: `Added to case #${c.case_number}` });
        setOpen(false);
        onAssociated?.();
      } catch {
        toast({ title: 'Could not add to case', variant: 'destructive' });
      } finally {
        setBusyId(null);
      }
    },
    [alertId, onAssociated, toast],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = cases ?? [];
    if (!q) return list;
    return list.filter(
      (c) => c.title.toLowerCase().includes(q) || String(c.case_number).includes(q),
    );
  }, [cases, query]);

  // Enterprise-only — Cases doesn't exist on open builds.
  if (!capabilities.cases) return null;

  return (
    <>
      <button
        type="button"
        onClick={() => onOpenChange(true)}
        className="h-7 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 inline-flex items-center gap-1.5"
      >
        <FolderPlus className="w-3.5 h-3.5" strokeWidth={2} />
        Add to case
      </button>

      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-[460px]">
          <DialogHeader>
            <DialogTitle className="text-[14px]">Add alert to case</DialogTitle>
            <DialogDescription className="text-[11.5px]">
              Link this alert to an existing investigation. It stays a plain link — no
              auto-investigation is triggered.
            </DialogDescription>
          </DialogHeader>

          <div className="relative mt-1">
            <SearchIcon className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search cases…"
              className="h-8 w-full pl-8 pr-3 rounded-md border border-border bg-transparent text-[11.5px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/60"
            />
          </div>

          <div className="mt-2 max-h-[320px] overflow-y-auto rounded-md border border-border divide-y divide-border/60">
            {loading ? (
              <div className="py-8 flex items-center justify-center">
                <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
              </div>
            ) : filtered.length === 0 ? (
              <div className="py-8 text-center text-[11.5px] text-muted-foreground">
                {(cases ?? []).length === 0 ? 'No open cases.' : 'No cases match your search.'}
              </div>
            ) : (
              filtered.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  disabled={busyId != null}
                  onClick={() => associate(c)}
                  className="w-full text-left px-3 py-2 flex items-center gap-2.5 hover:bg-foreground/[0.03] disabled:opacity-50"
                >
                  <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums shrink-0">
                    #{c.case_number}
                  </span>
                  <span className="text-[12px] text-foreground truncate flex-1">{c.title}</span>
                  <span
                    className={cn(
                      'font-mono text-[9.5px] uppercase tracking-wider shrink-0',
                      SEV_TONE[c.severity],
                    )}
                  >
                    {c.severity}
                  </span>
                  {busyId === c.id && (
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground shrink-0" />
                  )}
                </button>
              ))
            )}
          </div>

          <div className="mt-1 flex justify-end">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setOpen(false)}
              className="h-8 text-[11.5px]"
            >
              Cancel
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default AssociateCaseButton;
