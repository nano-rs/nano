// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Command Palette Component
 *
 * Global command palette for quick navigation and actions (Cmd+K / Ctrl+K).
 * Inspired by Linear's command palette.
 */

import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command';
import {
  AlertTriangle,
  Briefcase,
  FileText,
  Home,
  Layers,
  Network,
  Plus,
  Search,
  Settings,
  Shield,
  User,
  Zap,
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities, type Capabilities } from '@/hooks/use-capabilities';

interface CommandItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  action: () => void;
  /** Every permission listed is required (a create command also needs the
      view permission of the page it lands on). */
  permission?: string | string[];
  /** Build capability the target page needs (open-core builds drop it). */
  capability?: keyof Capabilities;
  group: 'navigation' | 'actions' | 'settings';
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();

  // Toggle command palette with Cmd+K / Ctrl+K
  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((open) => !open);
      }
    };

    document.addEventListener('keydown', down);
    return () => document.removeEventListener('keydown', down);
  }, []);

  const runCommand = useCallback((command: () => void) => {
    setOpen(false);
    command();
  }, []);

  // Define all commands
  const commands: CommandItem[] = [
    // Navigation
    {
      id: 'home',
      label: 'Go to Dashboard',
      icon: Home,
      action: () => navigate('/'),
      group: 'navigation',
    },
    {
      id: 'cases',
      label: 'Go to Cases',
      icon: Briefcase,
      action: () => navigate('/inbox'),
      permission: 'cases:view',
      capability: 'cases',
      group: 'navigation',
    },
    {
      id: 'search',
      label: 'Go to Search',
      icon: Search,
      action: () => navigate('/search'),
      permission: 'search:view',
      group: 'navigation',
    },
    {
      id: 'detections',
      label: 'Go to Rules',
      icon: Shield,
      action: () => navigate('/rules'),
      permission: 'detections:view',
      group: 'navigation',
    },
    {
      id: 'alerts',
      label: 'Go to Alerts',
      icon: AlertTriangle,
      action: () => navigate('/alerts'),
      permission: 'alerts:view',
      group: 'navigation',
    },
    {
      id: 'risk',
      label: 'Go to Risk Scoring',
      icon: Zap,
      action: () => navigate('/risk'),
      permission: 'risk:view',
      capability: 'risk',
      group: 'navigation',
    },
    {
      id: 'prevalence',
      label: 'Go to Prevalence',
      icon: Network,
      action: () => navigate('/prevalence'),
      permission: 'prevalence:view',
      group: 'navigation',
    },
    {
      id: 'notebooks',
      label: 'Go to Notebooks',
      icon: FileText,
      action: () => navigate('/notebooks'),
      permission: 'notebooks:view',
      capability: 'notebooks',
      group: 'navigation',
    },
    {
      id: 'log-sources',
      label: 'Go to Log Sources',
      icon: Layers,
      action: () => navigate('/ingestion/log-sources'),
      permission: 'log_sources:view',
      group: 'navigation',
    },

    // Actions
    {
      id: 'new-case',
      label: 'Create New Case',
      icon: Plus,
      // The Signal Inbox opens its New investigation flyout on this state
      // (/cases is a redirect that drops navigation state, NAN-5864).
      action: () => navigate('/inbox', { state: { openNewCase: true } }),
      permission: ['cases:view', 'cases:create'],
      capability: 'cases',
      group: 'actions',
    },
    {
      id: 'new-detection',
      label: 'Create New Rule',
      icon: Plus,
      action: () => navigate('/rules/editor/new'),
      permission: 'detections:create',
      group: 'actions',
    },
    {
      id: 'new-notebook',
      label: 'Create New Notebook',
      icon: Plus,
      action: () => navigate('/notebooks', { state: { openNewNotebook: true } }),
      permission: ['notebooks:view', 'notebooks:create'],
      capability: 'notebooks',
      group: 'actions',
    },

    // Settings
    {
      id: 'case-settings',
      label: 'Case Settings',
      icon: Settings,
      action: () => navigate('/settings/cases'),
      permission: 'settings:system',
      capability: 'cases',
      group: 'settings',
    },
    {
      id: 'access-control',
      label: 'Access Control',
      icon: User,
      action: () => navigate('/settings/access-control'),
      permission: 'users:view',
      group: 'settings',
    },
    {
      id: 'storage-settings',
      label: 'Storage Settings',
      icon: Settings,
      action: () => navigate('/settings/storage'),
      permission: 'settings:retention',
      group: 'settings',
    },
  ];

  // Filter commands on permissions and on the build: an open-core build never
  // offers a command whose page it does not ship (NAN-5864).
  const filteredCommands = commands.filter(
    (cmd) => [cmd.permission ?? []].flat().every((p) => hasPermission(p))
      && (!cmd.capability || Boolean(capabilities[cmd.capability]))
  );

  const navigationCommands = filteredCommands.filter((cmd) => cmd.group === 'navigation');
  const actionCommands = filteredCommands.filter((cmd) => cmd.group === 'actions');
  const settingsCommands = filteredCommands.filter((cmd) => cmd.group === 'settings');

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Type a command or search..." />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>

        {navigationCommands.length > 0 && (
          <CommandGroup heading="Navigation">
            {navigationCommands.map((cmd) => (
              <CommandItem key={cmd.id} onSelect={() => runCommand(cmd.action)}>
                <cmd.icon className="mr-2 h-4 w-4" />
                <span>{cmd.label}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}

        {actionCommands.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Actions">
              {actionCommands.map((cmd) => (
                <CommandItem key={cmd.id} onSelect={() => runCommand(cmd.action)}>
                  <cmd.icon className="mr-2 h-4 w-4" />
                  <span>{cmd.label}</span>
                  </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {settingsCommands.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Settings">
              {settingsCommands.map((cmd) => (
                <CommandItem key={cmd.id} onSelect={() => runCommand(cmd.action)}>
                  <cmd.icon className="mr-2 h-4 w-4" />
                  <span>{cmd.label}</span>
                  </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  );
}
