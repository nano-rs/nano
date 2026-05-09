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
  CommandShortcut,
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

interface CommandItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  shortcut?: string;
  action: () => void;
  permission?: string;
  group: 'navigation' | 'actions' | 'settings';
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const { hasPermission } = useAuth();

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
      shortcut: 'G C',
      action: () => navigate('/cases'),
      permission: 'cases:view',
      group: 'navigation',
    },
    {
      id: 'search',
      label: 'Go to Search',
      icon: Search,
      shortcut: 'G S',
      action: () => navigate('/search'),
      permission: 'search:view',
      group: 'navigation',
    },
    {
      id: 'detections',
      label: 'Go to Rules',
      icon: Shield,
      shortcut: 'G D',
      action: () => navigate('/rules'),
      permission: 'detections:view',
      group: 'navigation',
    },
    {
      id: 'alerts',
      label: 'Go to Alerts',
      icon: AlertTriangle,
      shortcut: 'G A',
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
      shortcut: 'C',
      action: () => {
        // Navigate to cases and trigger new case dialog
        navigate('/cases', { state: { openNewCase: true } });
      },
      permission: 'cases:create',
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
      permission: 'notebooks:create',
      group: 'actions',
    },

    // Settings
    {
      id: 'case-settings',
      label: 'Case Settings',
      icon: Settings,
      action: () => navigate('/settings/cases'),
      permission: 'settings:system',
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

  // Filter commands based on permissions
  const filteredCommands = commands.filter(
    (cmd) => !cmd.permission || hasPermission(cmd.permission)
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
                {cmd.shortcut && <CommandShortcut>{cmd.shortcut}</CommandShortcut>}
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
                  {cmd.shortcut && <CommandShortcut>{cmd.shortcut}</CommandShortcut>}
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
                  {cmd.shortcut && <CommandShortcut>{cmd.shortcut}</CommandShortcut>}
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  );
}
