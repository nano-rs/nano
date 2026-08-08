// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect } from 'react';
import { PivtIcon } from '@/components/icons/PivtIcon';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import changelog from '@/changelog.json';

const SEEN_VERSION_KEY = 'nanosiem-seen-version';

interface ChangelogEntry {
  version: string;
  date: string;
  title: string;
  changes: string[];
}

/**
 * "What's New" button with unread dot indicator.
 * Shows a dot when the running version is newer than the last version the user dismissed.
 * Renders in the top bar next to notifications.
 */
export function WhatsNew() {
  const [open, setOpen] = useState(false);
  const [hasNew, setHasNew] = useState(false);

  const { data: versionData } = useQuery({
    queryKey: ['version'],
    queryFn: () => api.getVersion(),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });

  const currentVersion = versionData?.version;

  useEffect(() => {
    if (!currentVersion) return;
    const seen = localStorage.getItem(SEEN_VERSION_KEY);
    if (seen !== currentVersion) {
      setHasNew(true);
    }
  }, [currentVersion]);

  function handleOpen(isOpen: boolean) {
    setOpen(isOpen);
    if (isOpen && currentVersion) {
      localStorage.setItem(SEEN_VERSION_KEY, currentVersion);
      setHasNew(false);
    }
  }

  const entries = changelog as ChangelogEntry[];

  return (
    <Dialog open={open} onOpenChange={handleOpen}>
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <DialogTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8 relative">
                <PivtIcon className="h-4 w-4" />
                {hasNew && (
                  <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-primary" />
                )}
              </Button>
            </DialogTrigger>
          </TooltipTrigger>
          <TooltipContent>What&apos;s new</TooltipContent>
        </Tooltip>
      </TooltipProvider>

      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>What&apos;s New</DialogTitle>
        </DialogHeader>
        <ScrollArea className="max-h-[60vh]">
          <div className="space-y-6 pr-4">
            {entries.map((entry) => (
              <div key={entry.version}>
                <div className="flex items-baseline gap-2 mb-2">
                  <span className="text-sm font-semibold">v{entry.version}</span>
                  <span className="text-xs text-muted-foreground">{entry.date}</span>
                </div>
                <p className="text-sm font-medium mb-1">{entry.title}</p>
                <ul className="text-sm text-muted-foreground space-y-1">
                  {entry.changes.map((change, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="text-primary mt-0.5">-</span>
                      {change}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
