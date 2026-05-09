// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Keyboard Shortcuts Help Component
 *
 * Shows available keyboard shortcuts in a popover.
 */

import { useState } from 'react';
import { Keyboard } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';

interface ShortcutGroup {
  title: string;
  shortcuts: {
    keys: string[];
    description: string;
  }[];
}

const GLOBAL_SHORTCUTS: ShortcutGroup[] = [
  {
    title: 'Global',
    shortcuts: [
      { keys: ['⌘', 'K'], description: 'Open command palette' },
      { keys: ['/'], description: 'Focus search' },
      { keys: ['?'], description: 'Show shortcuts' },
    ],
  },
  {
    title: 'Navigation',
    shortcuts: [
      { keys: ['G', 'C'], description: 'Go to Cases' },
      { keys: ['G', 'S'], description: 'Go to Search' },
      { keys: ['G', 'D'], description: 'Go to Rules' },
      { keys: ['G', 'A'], description: 'Go to Alerts' },
    ],
  },
  {
    title: 'Cases',
    shortcuts: [
      { keys: ['C'], description: 'Create new case' },
      { keys: ['V'], description: 'Toggle view mode' },
      { keys: ['R'], description: 'Refresh' },
      { keys: ['J', 'K'], description: 'Navigate up/down' },
      { keys: ['Enter'], description: 'Open selected' },
    ],
  },
];

function KeyboardKey({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="px-1.5 py-0.5 text-xs font-mono font-medium bg-muted border rounded min-w-[20px] text-center">
      {children}
    </kbd>
  );
}

export function KeyboardShortcutsHelp() {
  const [open, setOpen] = useState(false);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
          <Keyboard className="h-4 w-4" />
          <span className="sr-only">Keyboard shortcuts</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80" align="end">
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Keyboard className="h-4 w-4" />
            <h4 className="font-medium text-sm">Keyboard Shortcuts</h4>
          </div>
          {GLOBAL_SHORTCUTS.map((group) => (
            <div key={group.title} className="space-y-2">
              <h5 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                {group.title}
              </h5>
              <div className="space-y-1.5">
                {group.shortcuts.map((shortcut, i) => (
                  <div key={i} className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{shortcut.description}</span>
                    <div className="flex items-center gap-0.5">
                      {shortcut.keys.map((key, j) => (
                        <KeyboardKey key={j}>{key}</KeyboardKey>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
          <p className="text-xs text-muted-foreground pt-2 border-t">
            Press <KeyboardKey>⌘</KeyboardKey><KeyboardKey>K</KeyboardKey> for command palette
          </p>
        </div>
      </PopoverContent>
    </Popover>
  );
}
