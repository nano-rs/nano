// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { History, Clock, Trash2 } from 'lucide-react';
import { formatUTCShort } from '@/lib/date-utils';
import type { SearchHistoryEntry } from '@/hooks/useSearchHistory';

interface SearchHistoryProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  searchHistory: SearchHistoryEntry[];
  historyEnabled: boolean;
  onToggleHistoryEnabled: (enabled: boolean) => void;
  onLoadFromHistory: (entry: SearchHistoryEntry) => void;
  onDeleteEntry: (id: string) => void;
  onClearAll: () => void;
}

export function SearchHistory({
  open,
  onOpenChange,
  searchHistory,
  historyEnabled,
  onToggleHistoryEnabled,
  onLoadFromHistory,
  onDeleteEntry,
  onClearAll,
}: SearchHistoryProps) {
  const [deleteEntryId, setDeleteEntryId] = useState<string | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  return (
    <>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button variant="outline" className="bg-card border-border text-foreground hover:bg-accent rounded-xl transition-all">
          <History className="w-4 h-4" />
          History
        </Button>
      </DialogTrigger>
      <DialogContent className="bg-card border-border text-foreground rounded-2xl max-w-lg p-0 overflow-hidden">
        <DialogHeader className="px-6 pt-6 pb-4 border-b border-border">
          <DialogTitle className="search-console-section-header"><History />Search History</DialogTitle>
          <DialogDescription className="search-console-section-meta">
            Recent query recall and local history settings
          </DialogDescription>
        </DialogHeader>
        
        <div className="px-6 py-4 flex items-center justify-between border-b border-border">
          <div className="flex items-center gap-2">
            <Label htmlFor="history-toggle" className="text-sm text-foreground">Enable search history</Label>
          </div>
          <Switch
            id="history-toggle"
            checked={historyEnabled}
            onCheckedChange={onToggleHistoryEnabled}
          />
        </div>
        
        <div className="px-6 py-4 space-y-2 max-h-80 overflow-y-auto">
          {searchHistory.length === 0 ? (
            <div className="text-muted-foreground py-8 text-center">
              <p className="search-console-section-header justify-center"><History />Search History</p>
              <p className="mt-3 text-sm text-foreground">
                {historyEnabled ? 'No history entries recorded yet' : 'History recall is disabled'}
              </p>
              <p className="text-xs mt-1">
                {historyEnabled ? 'Run a few searches to build local recall.' : 'Enable history to retain recent queries on this device.'}
              </p>
            </div>
          ) : (
            searchHistory.map(entry => (
              <div
                key={entry.id}
                className="group p-3 bg-accent/50 rounded-xl hover:bg-accent cursor-pointer transition-all"
                onClick={() => onLoadFromHistory(entry)}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono text-foreground truncate">{entry.query}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[10px] font-mono text-muted-foreground flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatUTCShort(entry.timestamp)}
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 bg-muted rounded text-muted-foreground uppercase tracking-[0.12em]">
                        {entry.queryMode}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setDeleteEntryId(entry.id);
                    }}
                    className="opacity-0 group-hover:opacity-100 p-1.5 hover:bg-red-500/20 rounded-lg transition-all"
                    title="Delete from history"
                  >
                    <Trash2 className="w-3.5 h-3.5 text-red-400" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
        
        {searchHistory.length > 0 && (
          <DialogFooter className="border-t border-border px-6 py-4">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowClearConfirm(true)}
              className="bg-transparent border-red-500/30 text-red-400 hover:bg-red-500/10 rounded-lg"
            >
              <Trash2 className="w-4 h-4" />
              Clear All History
            </Button>
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>

    {/* Delete Entry Confirmation */}
    <ConfirmDialog
      open={!!deleteEntryId}
      onOpenChange={() => setDeleteEntryId(null)}
      variant="danger"
      title="Delete history entry"
      description="Are you sure you want to remove this search from your history?"
      confirmLabel="Delete"
      onConfirm={() => {
        if (deleteEntryId) onDeleteEntry(deleteEntryId);
        setDeleteEntryId(null);
      }}
    />

    {/* Clear All Confirmation */}
    <ConfirmDialog
      open={showClearConfirm}
      onOpenChange={setShowClearConfirm}
      variant="danger"
      title="Clear all history"
      description={
        <>
          Are you sure you want to clear all search history? This will remove{' '}
          {searchHistory.length} {searchHistory.length === 1 ? 'entry' : 'entries'} and cannot be
          undone.
        </>
      }
      confirmLabel="Clear All"
      onConfirm={() => {
        onClearAll();
        setShowClearConfirm(false);
      }}
    />
    </>
  );
}
