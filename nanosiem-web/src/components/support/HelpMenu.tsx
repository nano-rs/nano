// SPDX-License-Identifier: AGPL-3.0-or-later

/** NAN-5253: the topbar Help menu (main shell and Settings shell). */

import { Book, Bug, CircleHelp, ExternalLink, LifeBuoy } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { openSupportDialog } from '@/lib/support-diagnostics';

const ITEM = 'text-[11.5px] py-1.5 gap-2';
const ICON = 'w-3.5 h-3.5';

export function HelpMenu() {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="h-[26px] w-[26px]" aria-label="Help" title="Help">
          <CircleHelp className="h-[15px] w-[15px]" strokeWidth={1.5} />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" sideOffset={6} className="w-48">
        <DropdownMenuLabel className="text-[10.5px] font-medium uppercase tracking-wide text-muted-foreground">
          Help
        </DropdownMenuLabel>
        <DropdownMenuItem className={ITEM} onSelect={() => openSupportDialog('bug')}>
          <Bug className={ICON} strokeWidth={1.5} />
          Report a bug
        </DropdownMenuItem>
        <DropdownMenuItem className={ITEM} onSelect={() => openSupportDialog('support')}>
          <LifeBuoy className={ICON} strokeWidth={1.5} />
          Get support
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild className={ITEM}>
          <a href="https://nano.rs/docs/" target="_blank" rel="noopener noreferrer">
            <Book className={ICON} strokeWidth={1.5} />
            Docs
            <ExternalLink className="ml-auto h-3 w-3 opacity-50" strokeWidth={1.5} />
          </a>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
