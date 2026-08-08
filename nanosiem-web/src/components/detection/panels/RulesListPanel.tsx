// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useMemo, useEffect, useLayoutEffect, useCallback, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from '@/components/ui/context-menu';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  Search,
  Plus,
  Loader2,
  FileCode,
  Copy,
  Pencil,
  Trash2,
  Eye,
  WandSparkles,
  Play,
  Archive,
  ArchiveRestore,
  MoreVertical,
  ChevronRight,
  ChevronDown,
  Network,
  UserCheck,
  Monitor,
  Cloud,
  Folder,
  FolderInput,
  X,
  Power,
  CircleCheck,
} from 'lucide-react';
import { DEFAULT_FOLDERS, UNCATEGORIZED_FOLDER, type FolderDefinition } from '@/lib/detection-folders';

export interface DetectionRule {
  id: string;
  name: string;
  severity: string;
  mode: string;
  archived?: boolean;
  folder?: string;
}

interface RulesListPanelProps {
  rules: DetectionRule[];
  selectedRuleId?: string;
  onSelectRule: (id: string) => void;
  onCreateNew: () => void;
  onDuplicateRule?: (id: string) => void;
  onDeleteRule?: (id: string) => void;
  onViewMatches?: (id: string) => void;
  onFormatRule?: (id: string) => void;
  onValidateRule?: (id: string) => void;
  onArchiveRule?: (id: string) => void;
  onUnarchiveRule?: (id: string) => void;
  onMoveToFolder?: (id: string, folder: string | null) => void;
  onTogglePause?: (id: string) => void;
  onSetMode?: (id: string, mode: string) => void;
  loading?: boolean;
}

const FolderIcon = ({ icon }: { icon: FolderDefinition['icon'] }) => {
  const iconClass = 'w-4 h-4';
  switch (icon) {
    case 'Network':
      return <Network className={iconClass} />;
    case 'UserCheck':
      return <UserCheck className={iconClass} />;
    case 'Monitor':
      return <Monitor className={iconClass} />;
    case 'Cloud':
      return <Cloud className={iconClass} />;
    case 'Archive':
      return <Archive className={iconClass} />;
    default:
      return <Folder className={iconClass} />;
  }
};

// Module-level state that survives component remounts (route changes)
let _persistedExpandedFolders: Set<string> | null = null;
let _persistedScrollTop = 0;

export function RulesListPanel({
  rules,
  selectedRuleId,
  onSelectRule,
  onCreateNew,
  onDuplicateRule,
  onDeleteRule,
  onViewMatches,
  onFormatRule,
  onValidateRule,
  onArchiveRule,
  onUnarchiveRule,
  onMoveToFolder,
  onTogglePause,
  onSetMode,
  loading,
}: RulesListPanelProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchMode, setSearchMode] = useState(false);
  const [showArchived, setShowArchived] = useState(false);
  const [expandedFolders, _setExpandedFolders] = useState<Set<string>>(
    () => _persistedExpandedFolders ?? new Set()
  );
  const setExpandedFolders = useCallback((update: Set<string> | ((prev: Set<string>) => Set<string>)) => {
    _setExpandedFolders(prev => {
      const next = typeof update === 'function' ? update(prev) : update;
      _persistedExpandedFolders = next;
      return next;
    });
  }, []);
  const [draggedRuleId, setDraggedRuleId] = useState<string | null>(null);
  const [dropTargetFolder, setDropTargetFolder] = useState<string | null>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchContainerRef = useRef<HTMLDivElement>(null);
  const scrollAreaRef = useRef<HTMLDivElement>(null);

  // Focus search input when entering search mode
  useEffect(() => {
    if (searchMode && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [searchMode]);

  // Handle click outside to close search
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (searchMode && searchContainerRef.current && !searchContainerRef.current.contains(e.target as Node)) {
        setSearchMode(false);
        setSearchQuery('');
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [searchMode]);

  const filteredRules = rules
    .filter((rule) => !rule.archived === !showArchived)
    .filter((rule) =>
      searchQuery
        ? rule.name.toLowerCase().includes(searchQuery.toLowerCase())
        : true
    );

  // Group rules by folder
  const rulesByFolder = useMemo(() => {
    const grouped = new Map<string, DetectionRule[]>();

    // Initialize all default folders
    DEFAULT_FOLDERS.forEach((f) => grouped.set(f.id, []));
    grouped.set('uncategorized', []);

    // Group rules
    filteredRules.forEach((rule) => {
      const folder = rule.folder || 'uncategorized';
      const existing = grouped.get(folder) || [];
      grouped.set(folder, [...existing, rule]);
    });

    // Also handle custom folders (folders not in DEFAULT_FOLDERS)
    filteredRules.forEach((rule) => {
      if (rule.folder && !DEFAULT_FOLDERS.some(f => f.id === rule.folder) && rule.folder !== 'uncategorized') {
        if (!grouped.has(rule.folder)) {
          grouped.set(rule.folder, []);
        }
      }
    });

    return grouped;
  }, [filteredRules]);

  // Get folder of selected rule
  const selectedRuleFolder = useMemo(() => {
    if (!selectedRuleId) return null;
    const selectedRule = rules.find(r => r.id === selectedRuleId);
    return selectedRule?.folder || 'uncategorized';
  }, [selectedRuleId, rules]);

  // Auto-expand folder containing selected rule
  useEffect(() => {
    if (selectedRuleFolder && !expandedFolders.has(selectedRuleFolder)) {
      setExpandedFolders(prev => new Set([...prev, selectedRuleFolder]));
    }
  }, [selectedRuleFolder]);

  // Auto-expand all folders with matches when searching
  useEffect(() => {
    if (searchQuery) {
      const foldersWithMatches = new Set<string>();
      rulesByFolder.forEach((rules, folderId) => {
        if (rules.length > 0) foldersWithMatches.add(folderId);
      });
      if (foldersWithMatches.size > 0) {
        setExpandedFolders(prev => new Set([...prev, ...foldersWithMatches]));
      }
    }
  }, [searchQuery, rulesByFolder]);

  // Persist scroll position across remounts
  useEffect(() => {
    const viewport = scrollAreaRef.current?.querySelector<HTMLElement>('[data-radix-scroll-area-viewport]');
    if (!viewport) return;
    const handleScroll = () => { _persistedScrollTop = viewport.scrollTop; };
    viewport.addEventListener('scroll', handleScroll);
    return () => viewport.removeEventListener('scroll', handleScroll);
  }, [loading]);

  // Restore scroll position after list renders
  useLayoutEffect(() => {
    if (!loading && filteredRules.length > 0 && _persistedScrollTop > 0) {
      const viewport = scrollAreaRef.current?.querySelector<HTMLElement>('[data-radix-scroll-area-viewport]');
      if (viewport) {
        viewport.scrollTop = _persistedScrollTop;
      }
    }
  }, [loading]);

  // Get all folders to display (default + custom), excluding stash if empty and not in archived view
  const foldersToDisplay = useMemo(() => {
    const customFolders: FolderDefinition[] = [];
    rulesByFolder.forEach((_, folderId) => {
      if (!DEFAULT_FOLDERS.some(f => f.id === folderId) && folderId !== 'uncategorized') {
        customFolders.push({
          id: folderId,
          name: folderId.charAt(0).toUpperCase() + folderId.slice(1),
          icon: 'Folder',
          description: 'Custom folder'
        });
      }
    });

    // Filter out stash if empty and not showing archived
    const defaultFoldersFiltered = DEFAULT_FOLDERS.filter(f => {
      if (f.id === 'stash') {
        const stashRules = rulesByFolder.get('stash') || [];
        return stashRules.length > 0 || showArchived;
      }
      return true;
    });

    return [...defaultFoldersFiltered, ...customFolders, UNCATEGORIZED_FOLDER];
  }, [rulesByFolder, showArchived]);

  const toggleFolder = (folderId: string) => {
    setExpandedFolders((prev) => {
      const next = new Set(prev);
      if (next.has(folderId)) {
        next.delete(folderId);
      } else {
        next.add(folderId);
      }
      return next;
    });
  };

  const getSevColor = (s: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-500/10 text-red-500',
      high: 'bg-orange-500/10 text-orange-500',
      medium: 'bg-yellow-500/10 text-yellow-500',
      low: 'bg-primary/10 text-primary',
    };
    return colors[s] || 'bg-gray-500/10 text-muted-foreground';
  };

  const getModeColor = (mode: string) => {
    if (mode === 'unsaved') return 'bg-purple-500/10 text-purple-400';
    if (mode === 'staging') return 'bg-gray-500/10 text-muted-foreground';
    if (mode === 'paused') return 'bg-amber-500/10 text-amber-400';
    return mode === 'live'
      ? 'bg-yellow-500/10 text-yellow-400'
      : 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400';
  };

  // Drag and drop handlers
  const handleDragStart = useCallback((e: React.DragEvent, ruleId: string) => {
    setDraggedRuleId(ruleId);
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', ruleId);
  }, []);

  const handleDragEnd = useCallback(() => {
    setDraggedRuleId(null);
    setDropTargetFolder(null);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent, folderId: string) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDropTargetFolder(folderId);
  }, []);

  const handleDragLeave = useCallback(() => {
    setDropTargetFolder(null);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent, folderId: string) => {
    e.preventDefault();
    const ruleId = e.dataTransfer.getData('text/plain');
    if (ruleId && onMoveToFolder) {
      onMoveToFolder(ruleId, folderId === 'uncategorized' ? null : folderId);
    }
    setDraggedRuleId(null);
    setDropTargetFolder(null);
  }, [onMoveToFolder]);

  const renderRuleItem = (rule: DetectionRule) => (
    <ContextMenu key={rule.id}>
      <ContextMenuTrigger asChild>
        <button
          draggable={!!onMoveToFolder}
          onDragStart={(e) => handleDragStart(e, rule.id)}
          onDragEnd={handleDragEnd}
          onClick={() => onSelectRule(rule.id)}
          className={`group w-full text-left p-2 rounded-lg transition-colors ${
            selectedRuleId === rule.id
              ? 'bg-muted/80 text-foreground'
              : 'text-muted-foreground hover:bg-accent/50 hover:text-primary'
          } ${draggedRuleId === rule.id ? 'opacity-50' : ''} ${onMoveToFolder ? 'cursor-grab active:cursor-grabbing' : ''}`}
        >
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 flex-shrink-0" />
            <span className="text-sm truncate flex-1">{rule.name}</span>
            <div
              className="p-0.5 rounded hover:bg-accent/80 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0"
              onContextMenu={(e) => e.stopPropagation()}
              onClick={(e) => {
                e.stopPropagation();
                const contextMenuEvent = new MouseEvent('contextmenu', {
                  bubbles: true,
                  cancelable: true,
                  clientX: e.clientX,
                  clientY: e.clientY,
                });
                e.currentTarget.parentElement?.dispatchEvent(contextMenuEvent);
              }}
            >
              <MoreVertical className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="flex items-center gap-1 mt-1 ml-6">
            <Badge
              variant="outline"
              className={`${getSevColor(rule.severity)} border-0 rounded text-[10px] px-1 py-0`}
            >
              {rule.severity}
            </Badge>
            <Badge
              variant="outline"
              className={`${getModeColor(rule.mode)} border-0 rounded text-[10px] px-1 py-0`}
            >
              {rule.mode}
            </Badge>
          </div>
        </button>
      </ContextMenuTrigger>
      <ContextMenuContent className="w-48">
        <ContextMenuItem onClick={() => onSelectRule(rule.id)}>
          <Pencil className="w-4 h-4 mr-2" />
          Edit Rule
        </ContextMenuItem>
        {onViewMatches && (
          <ContextMenuItem onClick={() => onViewMatches(rule.id)}>
            <Eye className="w-4 h-4 mr-2" />
            View Matches
          </ContextMenuItem>
        )}
        {onDuplicateRule && (
          <ContextMenuItem onClick={() => onDuplicateRule(rule.id)}>
            <Copy className="w-4 h-4 mr-2" />
            Duplicate Rule
          </ContextMenuItem>
        )}
        {onFormatRule && (
          <ContextMenuItem onClick={() => onFormatRule(rule.id)}>
            <WandSparkles className="w-4 h-4 mr-2" />
            Format Query
          </ContextMenuItem>
        )}
        {onValidateRule && (
          <ContextMenuItem onClick={() => onValidateRule(rule.id)}>
            <Play className="w-4 h-4 mr-2" />
            Validate
          </ContextMenuItem>
        )}
        {onMoveToFolder && (
          <>
            <ContextMenuSeparator />
            <ContextMenuSub>
              <ContextMenuSubTrigger>
                <FolderInput className="w-4 h-4 mr-2" />
                Move to Folder
              </ContextMenuSubTrigger>
              <ContextMenuSubContent className="w-40">
                {DEFAULT_FOLDERS.map((folder) => (
                  <ContextMenuItem
                    key={folder.id}
                    onClick={() => onMoveToFolder(rule.id, folder.id)}
                    disabled={rule.folder === folder.id}
                  >
                    <FolderIcon icon={folder.icon} />
                    <span className="ml-2">{folder.name}</span>
                  </ContextMenuItem>
                ))}
                <ContextMenuSeparator />
                <ContextMenuItem
                  onClick={() => onMoveToFolder(rule.id, null)}
                  disabled={!rule.folder}
                >
                  <Folder className="w-4 h-4 mr-2" />
                  Uncategorized
                </ContextMenuItem>
              </ContextMenuSubContent>
            </ContextMenuSub>
          </>
        )}
        {onSetMode && (
          <>
            <ContextMenuSeparator />
            <ContextMenuSub>
              <ContextMenuSubTrigger>
                <Power className="w-4 h-4 mr-2" />
                Rule Status
              </ContextMenuSubTrigger>
              <ContextMenuSubContent className="w-40">
                <ContextMenuItem
                  onClick={() => onSetMode(rule.id, 'staging')}
                  disabled={rule.mode === 'staging'}
                >
                  Staging
                  {rule.mode === 'staging' && <CircleCheck className="w-3 h-3 ml-auto" />}
                </ContextMenuItem>
                <ContextMenuItem
                  onClick={() => onSetMode(rule.id, 'live')}
                  disabled={rule.mode === 'live'}
                >
                  Live
                  {rule.mode === 'live' && <CircleCheck className="w-3 h-3 ml-auto" />}
                </ContextMenuItem>
                <ContextMenuItem
                  onClick={() => onSetMode(rule.id, 'alerting')}
                  disabled={rule.mode === 'alerting'}
                >
                  Alerting
                  {rule.mode === 'alerting' && <CircleCheck className="w-3 h-3 ml-auto" />}
                </ContextMenuItem>
                <ContextMenuSeparator />
                <ContextMenuItem
                  onClick={() => onSetMode(rule.id, 'paused')}
                  disabled={rule.mode === 'paused'}
                >
                  Paused
                  {rule.mode === 'paused' && <CircleCheck className="w-3 h-3 ml-auto" />}
                </ContextMenuItem>
              </ContextMenuSubContent>
            </ContextMenuSub>
          </>
        )}
        {!onSetMode && onTogglePause && (rule.mode === 'alerting' || rule.mode === 'live' || rule.mode === 'paused') && (
          <>
            <ContextMenuSeparator />
            <ContextMenuItem onClick={() => onTogglePause(rule.id)}>
              <Power className="w-4 h-4 mr-2" />
              {rule.mode === 'paused' ? 'Resume Rule' : 'Pause Rule'}
            </ContextMenuItem>
          </>
        )}
        <ContextMenuSeparator />
        {onArchiveRule && !rule.archived && (
          <ContextMenuItem onClick={() => onArchiveRule(rule.id)}>
            <Archive className="w-4 h-4 mr-2" />
            Archive Rule
          </ContextMenuItem>
        )}
        {onUnarchiveRule && rule.archived && (
          <ContextMenuItem onClick={() => onUnarchiveRule(rule.id)}>
            <ArchiveRestore className="w-4 h-4 mr-2" />
            Unarchive Rule
          </ContextMenuItem>
        )}
        {onDeleteRule && (
          <ContextMenuItem
            onClick={() => onDeleteRule(rule.id)}
            className="text-red-400 focus:text-red-400"
          >
            <Trash2 className="w-4 h-4 mr-2" />
            Delete Rule
          </ContextMenuItem>
        )}
      </ContextMenuContent>
    </ContextMenu>
  );

  return (
    <div className="h-full border-r border-border flex flex-col bg-muted/10">
      <div className="p-3 border-b border-border space-y-3">
        <Tabs value={showArchived ? 'archived' : 'active'} onValueChange={(v) => setShowArchived(v === 'archived')} className="w-full">
          <TabsList className="w-full grid grid-cols-2">
            <TabsTrigger value="active" className="text-xs">
              Active Rules
            </TabsTrigger>
            <TabsTrigger value="archived" className="text-xs">
              Archived
            </TabsTrigger>
          </TabsList>
        </Tabs>
        {/* Toggle between New Rule button and Search input */}
        <div ref={searchContainerRef}>
          {searchMode ? (
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                ref={searchInputRef}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search rules..."
                className="pl-9 pr-8 h-8 text-sm bg-transparent"
                onKeyDown={(e) => {
                  if (e.key === 'Escape') {
                    setSearchMode(false);
                    setSearchQuery('');
                  }
                }}
              />
              <button
                onClick={() => {
                  setSearchMode(false);
                  setSearchQuery('');
                }}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex gap-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={onCreateNew}
                className="flex-1 justify-start text-muted-foreground hover:text-primary hover:bg-transparent h-8"
              >
                <Plus className="w-4 h-4" />
                New Rule
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSearchMode(true)}
                className="text-muted-foreground hover:text-primary hover:bg-transparent h-8 px-2"
              >
                <Search className="w-4 h-4" />
              </Button>
            </div>
          )}
        </div>
      </div>
      <ScrollArea ref={scrollAreaRef} className="flex-1">
        <div className="p-2 space-y-1">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : filteredRules.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">
              No rules found
            </p>
          ) : (
            foldersToDisplay.map((folder) => {
              const folderRules = rulesByFolder.get(folder.id) || [];
              // When searching, hide ALL empty folders (not just custom ones)
              if (folderRules.length === 0 && searchQuery) {
                return null;
              }
              if (folderRules.length === 0 && !DEFAULT_FOLDERS.some(f => f.id === folder.id) && folder.id !== 'uncategorized') {
                return null; // Hide empty custom folders
              }

              const isExpanded = expandedFolders.has(folder.id);
              const isStash = folder.id === 'stash';
              const isDropTarget = dropTargetFolder === folder.id && draggedRuleId !== null;

              return (
                <Collapsible
                  key={folder.id}
                  open={isExpanded}
                  onOpenChange={() => toggleFolder(folder.id)}
                >
                  <CollapsibleTrigger asChild>
                    <button
                      onDragOver={(e) => handleDragOver(e, folder.id)}
                      onDragLeave={handleDragLeave}
                      onDrop={(e) => handleDrop(e, folder.id)}
                      className={`w-full flex items-center gap-2 p-2 rounded-lg text-sm transition-colors hover:bg-accent/50 text-muted-foreground ${
                        isStash ? 'opacity-60' : ''
                      } ${isDropTarget ? 'bg-primary/20 ring-2 ring-primary/50' : ''}`}
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 flex-shrink-0" />
                      ) : (
                        <ChevronRight className="w-4 h-4 flex-shrink-0" />
                      )}
                      <FolderIcon icon={folder.icon} />
                      <span className="flex-1 text-left">{folder.name}</span>
                      <Badge
                        variant="secondary"
                        className="text-[10px] px-1.5 py-0 h-4 bg-muted/50 text-foreground/70"
                      >
                        {folderRules.length}
                      </Badge>
                    </button>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <div className="ml-4 space-y-1 mt-1">
                      {folderRules.length === 0 ? (
                        <p className="text-xs text-muted-foreground/50 py-2 pl-6">
                          No rules
                        </p>
                      ) : (
                        folderRules.map(renderRuleItem)
                      )}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              );
            })
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
