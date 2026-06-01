// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useUserPreferences } from '@/contexts/UserPreferencesContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Checkbox } from '@/components/ui/checkbox';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { api, type SearchJobSummary, type AdminSearchJobsResponse } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import {
  Compass,
  Search,
  BookOpen,
  Star,
  Play,
  Copy,
  Check,
  Clock,
  Shield,
  Network,
  Key,
  Globe,
  Globe2,
  AlertTriangle,
  ChartColumn,
  FileText,
  Loader2,
  X,
  List,
  Table as TableIcon,
  Lock,
  Users,
  Share2,
  Pin,
  PinOff,
  Settings2,
  PanelRightOpen,
  Layers,
  Activity,
  CircleCheck,
  XCircle,
} from 'lucide-react';
import { useViewPreference } from '@/hooks/use-view-preference';
import { getAccessToken } from '@/lib/auth-token';
import { useIsMobile } from '@/hooks/use-mobile';

function getAuthHeaders(): HeadersInit {
  const token = getAccessToken();
  if (token) {
    return { 'Authorization': `Bearer ${token}` };
  }
  return {};
}

// localStorage keys
const STORAGE_KEYS = {
  pinnedSearches: 'nanosiem_pinned_searches',
};

interface LibraryQuery {
  id: number;
  name: string;
  description: string;
  query: string;
  category: string;
  tags: string[];
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  use_case: string | null;
  is_builtin: boolean;
}

interface CategoryCount {
  category: string;
  count: number;
}

interface SharedGroup {
  id: string;
  name: string;
}

interface SavedSearch {
  id: string;
  name: string;
  query: string;
  query_mode: 'piped' | 'sql';
  time_range?: { start: string; end: string };
  created_at: string;
  user_id?: string;
  visibility?: 'private' | 'public' | 'group';
  is_owner?: boolean;
  owner_name?: string;
  shared_groups?: SharedGroup[];
}

interface Group {
  id: string;
  name: string;
}

interface SearchHubProps {
  onSelectQuery: (query: string, mode?: 'piped' | 'sql') => void;
  onRunQuery?: (query: string, mode?: 'piped' | 'sql') => void; // Run immediately
  // Saved searches
  savedSearches?: SavedSearch[];
  sharedSearches?: SavedSearch[];
  onDeleteSavedSearch?: (id: string) => void;
  onShareSavedSearch?: (id: string, visibility: 'private' | 'public' | 'group', groupIds?: string[]) => void;
  availableGroups?: Group[];
  // Search jobs
  onLoadJob?: (jobId: string) => void;
  onCancelJob?: (jobId: string) => void;
  // External open control — when provided, SearchHub renders as a pure
  // overlay without its default trigger button. The parent can mount a
  // custom trigger (e.g. the redesigned "Saved queries" footer chip).
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  hideTrigger?: boolean;
}

const API_BASE = import.meta.env.VITE_API_URL ?? '';

const categoryIcons: Record<string, React.ReactNode> = {
  basics: <BookOpen className="h-4 w-4" />,
  filtering: <Search className="h-4 w-4" />,
  aggregation: <ChartColumn className="h-4 w-4" />,
  'time-analysis': <Clock className="h-4 w-4" />,
  risk: <Shield className="h-4 w-4" />,
  network: <Network className="h-4 w-4" />,
  authentication: <Key className="h-4 w-4" />,
  http: <Globe className="h-4 w-4" />,
  'threat-hunting': <AlertTriangle className="h-4 w-4" />,
  reporting: <FileText className="h-4 w-4" />,
};

const difficultyColors: Record<string, string> = {
  beginner: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/20',
  intermediate: 'bg-amber-50 dark:bg-yellow-500/10 text-amber-700 dark:text-yellow-400 border-amber-200 dark:border-yellow-500/20',
  advanced: 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 border-red-200 dark:border-red-500/20',
};

// Helper component for visibility icons
function VisibilityIcon({ visibility }: { visibility?: 'private' | 'public' | 'group' }) {
  switch (visibility) {
    case 'public':
      return <Globe2 className="h-3 w-3 text-green-500" />;
    case 'group':
      return <Users className="h-3 w-3 text-blue-500" />;
    case 'private':
    default:
      return <Lock className="h-3 w-3 text-muted-foreground" />;
  }
}

// Hook for localStorage-based preferences
function useLocalPreference<T>(key: string, defaultValue: T): [T, (value: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored ? JSON.parse(stored) : defaultValue;
    } catch {
      return defaultValue;
    }
  });

  const setStoredValue = useCallback((newValue: T) => {
    setValue(newValue);
    localStorage.setItem(key, JSON.stringify(newValue));
  }, [key]);

  return [value, setStoredValue];
}

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

const JOB_STATUS_CONFIG: Record<string, { icon: typeof Clock; label: string; color: string }> = {
  queued: { icon: Clock, label: 'Queued', color: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20' },
  running: { icon: Loader2, label: 'Running', color: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20' },
  completed: { icon: CircleCheck, label: 'Done', color: 'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20' },
  failed: { icon: XCircle, label: 'Failed', color: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20' },
  cancelled: { icon: X, label: 'Cancelled', color: 'bg-muted text-muted-foreground border-border' },
};

export function SearchHub({
  onSelectQuery,
  onRunQuery,
  savedSearches = [],
  sharedSearches = [],
  onDeleteSavedSearch,
  onShareSavedSearch,
  availableGroups = [],
  onLoadJob,
  onCancelJob,
  open: openProp,
  onOpenChange,
  hideTrigger,
}: SearchHubProps) {
  const isMobile = useIsMobile();
  const [openInternal, setOpenInternal] = useState(false);
  const isControlled = openProp !== undefined;
  const open = isControlled ? openProp : openInternal;
  const setOpen = (value: boolean) => {
    if (!isControlled) setOpenInternal(value);
    onOpenChange?.(value);
  };
  const [activeTab, setActiveTab] = useState('saved');
  const [searchTerm, setSearchTerm] = useState('');
  const [savedSearchTerm, setSavedSearchTerm] = useState('');
  const [sharedSearchTerm, setSharedSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('basics');
  const [copiedId, setCopiedId] = useState<number | string | null>(null);
  const [viewMode, setViewMode] = useViewPreference<'list' | 'table'>('search-hub', 'table');
  const [deleteConfirmSearch, setDeleteConfirmSearch] = useState<SavedSearch | null>(null);
  const [shareSearch, setShareSearch] = useState<SavedSearch | null>(null);
  const [shareVisibility, setShareVisibility] = useState<'private' | 'public' | 'group'>('private');
  const [shareGroupIds, setShareGroupIds] = useState<string[]>([]);

  // Search jobs state
  const [dismissedJobIds, setDismissedJobIds] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();
  const isJobsAdmin = hasPermission('settings:system');

  // Fetch user's own jobs (always — poll fast when active, slow background otherwise)
  const { data: userJobs } = useQuery({
    queryKey: ['search-jobs'],
    queryFn: () => api.listSearchJobs(),
    refetchInterval: (query) => {
      const data = query.state.data as SearchJobSummary[] | undefined;
      if (!data) return 15_000;
      const hasActive = data.some(j => j.status === 'queued' || j.status === 'running');
      return hasActive ? 3000 : 15_000;
    },
  });

  // Fetch all jobs (admin only, when Jobs tab is active)
  const { data: adminData } = useQuery<AdminSearchJobsResponse>({
    queryKey: ['admin-search-jobs'],
    queryFn: () => api.listAdminSearchJobs(),
    enabled: isJobsAdmin && activeTab === 'jobs',
    refetchInterval: (query) => {
      const result = query.state.data as AdminSearchJobsResponse | undefined;
      if (!result) return 10_000;
      const hasActive = result.jobs.some(j => j.status === 'queued' || j.status === 'running');
      return hasActive ? 3000 : 10_000;
    },
  });

  // For the badge count, always use user's own jobs
  // Note: elapsed_ms is the age since job creation (not an epoch timestamp)
  const userVisibleJobs = useMemo(() => {
    return (userJobs ?? []).filter(j => {
      if (j.status === 'queued' || j.status === 'running') return true;
      return j.elapsed_ms < 300_000;
    });
  }, [userJobs]);

  // For the Jobs tab content: admin sees all jobs, regular user sees own
  const adminJobs = adminData?.jobs ?? [];
  const admissionStats = adminData?.stats;

  const visibleJobs = useMemo(() => {
    const source = isJobsAdmin ? adminJobs : (userJobs ?? []);
    return source.filter((j: SearchJobSummary & { user_id?: string | null }) => {
      if (dismissedJobIds.has(j.job_id)) return false;
      if (j.status === 'queued' || j.status === 'running') return true;
      return j.elapsed_ms < 300_000;
    });
  }, [isJobsAdmin, adminJobs, userJobs, dismissedJobIds]);

  const activeJobCount = userVisibleJobs.length;

  const dismissJob = useCallback((jobId: string) => {
    setDismissedJobIds(prev => new Set(prev).add(jobId));
  }, []);

  // Keyboard navigation state
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const listRef = useRef<HTMLDivElement>(null);

  // User preferences from context (synced to backend)
  const { searchHubStyle, setSearchHubStyle } = useUserPreferences();
  // Force non-modal flyout on desktop; keep bottom sheet on mobile.
  // Older stored preferences may still say "popover", but we don't want
  // the desktop Search Hub to open as a modal anymore.
  const hubStyle = isMobile ? (searchHubStyle || 'drawer') : 'drawer';

  // localStorage-based preferences (local only)
  const [pinnedSearchIds, setPinnedSearchIds] = useLocalPreference<string[]>(STORAGE_KEYS.pinnedSearches, []);

  // Library state
  const [queries, setQueries] = useState<LibraryQuery[]>([]);
  const [categories, setCategories] = useState<CategoryCount[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Toggle pin
  const togglePin = useCallback((searchId: string) => {
    if (pinnedSearchIds.includes(searchId)) {
      setPinnedSearchIds(pinnedSearchIds.filter(id => id !== searchId));
    } else {
      setPinnedSearchIds([...pinnedSearchIds, searchId]);
    }
  }, [pinnedSearchIds, setPinnedSearchIds]);

  // Fetch queries
  const fetchQueries = useCallback(async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      if (searchTerm) params.set('search', searchTerm);
      if (selectedCategory) params.set('category', selectedCategory);
      const response = await fetch(`${API_BASE}/api/query-library?${params}`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setQueries(data.queries || []);
      }
    } catch (err) {
      console.error('Failed to fetch queries:', err);
    } finally {
      setIsLoading(false);
    }
  }, [searchTerm, selectedCategory]);

  // Fetch categories
  const fetchCategories = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/query-library/categories`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setCategories(data.categories || []);
      }
    } catch (err) {
      console.error('Failed to fetch categories:', err);
    }
  }, []);

  // Load data when drawer opens
  useEffect(() => {
    if (open && activeTab === 'library') {
      fetchQueries();
      fetchCategories();
    }
  }, [open, activeTab, fetchQueries, fetchCategories]);

  const handleCopy = async (query: string, id: number | string) => {
    await navigator.clipboard.writeText(query);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleUse = (query: string, mode?: 'piped' | 'sql') => {
    onSelectQuery(query, mode);
    setOpen(false);
  };

  const handleRun = (query: string, mode?: 'piped' | 'sql') => {
    if (onRunQuery) {
      onRunQuery(query, mode);
    } else {
      onSelectQuery(query, mode);
    }
    setOpen(false);
  };

  // Filter saved searches - pinned first, then rest
  const filteredSavedSearches = useMemo(() => {
    const filtered = savedSearches.filter(search =>
      search.name.toLowerCase().includes(savedSearchTerm.toLowerCase()) ||
      search.query.toLowerCase().includes(savedSearchTerm.toLowerCase())
    );
    // Sort: pinned first
    return filtered.sort((a, b) => {
      const aPinned = pinnedSearchIds.includes(a.id);
      const bPinned = pinnedSearchIds.includes(b.id);
      if (aPinned && !bPinned) return -1;
      if (!aPinned && bPinned) return 1;
      return 0;
    });
  }, [savedSearches, savedSearchTerm, pinnedSearchIds]);

  // Filter shared searches based on search term
  const filteredSharedSearches = sharedSearches.filter(search =>
    search.name.toLowerCase().includes(sharedSearchTerm.toLowerCase()) ||
    search.query.toLowerCase().includes(sharedSearchTerm.toLowerCase())
  );

  // Handle share save
  const handleShareSave = () => {
    if (shareSearch && onShareSavedSearch) {
      onShareSavedSearch(
        shareSearch.id,
        shareVisibility,
        shareVisibility === 'group' ? shareGroupIds : undefined
      );
      setShareSearch(null);
      setShareVisibility('private');
      setShareGroupIds([]);
    }
  };

  // Open share dialog for a search
  const openShareDialog = (search: SavedSearch) => {
    setShareSearch(search);
    setShareVisibility(search.visibility || 'private');
    setShareGroupIds(search.shared_groups?.map(g => g.id) || []);
  };

  // Keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent, items: Array<{ query: string; mode?: 'piped' | 'sql' }>) => {
    if (!items.length) return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setFocusedIndex(prev => Math.min(prev + 1, items.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setFocusedIndex(prev => Math.max(prev - 1, 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (focusedIndex >= 0 && focusedIndex < items.length) {
          const item = items[focusedIndex];
          if (e.metaKey || e.ctrlKey) {
            handleRun(item.query, item.mode);
          } else {
            handleUse(item.query, item.mode);
          }
        }
        break;
      case 'Escape':
        setOpen(false);
        break;
    }
  }, [focusedIndex, handleUse, handleRun]);

  // Reset focus when tab changes
  useEffect(() => {
    setFocusedIndex(-1);
  }, [activeTab]);

  // Hub content (shared between popover and drawer)
  const hubContent = (
    <>
      <Tabs value={activeTab} onValueChange={setActiveTab} className="px-4 pt-3">
        <TabsList>
          <TabsTrigger value="saved" className="gap-1.5">
            <Star className="h-4 w-4" />
            Saved
            {savedSearches.length > 0 && (
              <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-[10px]">
                {savedSearches.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="shared" className="gap-1.5">
            <Users className="h-4 w-4" />
            Shared
            {sharedSearches.length > 0 && (
              <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-[10px]">
                {sharedSearches.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="library" className="gap-1.5">
            <BookOpen className="h-4 w-4" />
            Library
            {categories.length > 0 && (
              <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-[10px]">
                {queries.length || '...'}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="jobs" className="gap-1.5">
            <Activity className="h-4 w-4" />
            Jobs
            {activeJobCount > 0 && (
              <Badge variant="default" className="ml-1 h-5 px-1.5 text-[10px] bg-blue-500 text-white">
                {activeJobCount}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        {/* Saved Tab */}
        <TabsContent value="saved" className="mt-4 space-y-4">
          {/* Search filter */}
          <div className="flex items-center justify-between gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search saved searches..."
                value={savedSearchTerm}
                onChange={(e) => setSavedSearchTerm(e.target.value)}
                onKeyDown={(e) => handleKeyDown(e, filteredSavedSearches.map(s => ({ query: s.query, mode: s.query_mode })))}
                className="pl-10 border-border rounded-xl"
              />
            </div>
            <ToggleGroup type="single" value={viewMode} onValueChange={(v) => { if (v) setViewMode(v as 'list' | 'table'); }} size="sm" variant="outline">
              <ToggleGroupItem value="list" aria-label="List view">
                <List className="w-4 h-4" />
              </ToggleGroupItem>
              <ToggleGroupItem value="table" aria-label="Table view">
                <TableIcon className="w-4 h-4" />
              </ToggleGroupItem>
            </ToggleGroup>
          </div>

          <ScrollArea className="h-[min(350px,calc(100vh-400px))]">
            {filteredSavedSearches.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                <Star className="h-8 w-8 mb-2 opacity-50" />
                <p>{savedSearchTerm ? 'No matching saved searches' : savedSearches.length === 0 ? 'No saved searches yet' : 'No matches found'}</p>
                {savedSearches.length === 0 && <p className="text-xs mt-1">Save a search from the search bar to see it here</p>}
              </div>
            ) : viewMode === 'table' ? (
              <div className="pr-4" ref={listRef}>
                <div className="rounded-lg border border-border overflow-hidden">
                  <Table>
                    <TableHeader className="bg-accent/50">
                      <TableRow className="border-b border-border hover:bg-transparent">
                        <TableHead className="text-muted-foreground w-8"></TableHead>
                        <TableHead className="text-muted-foreground">Name</TableHead>
                        <TableHead className="text-muted-foreground">Query</TableHead>
                        <TableHead className="text-muted-foreground w-24">Mode</TableHead>
                        <TableHead className="text-muted-foreground w-28 text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredSavedSearches.map((search, index) => (
                        <TableRow
                          key={search.id}
                          className={`group hover:bg-accent cursor-pointer transition-colors border-b border-border last:border-0 ${focusedIndex === index ? 'bg-accent' : ''}`}
                          onClick={() => handleUse(search.query, search.query_mode)}
                          onDoubleClick={() => handleRun(search.query, search.query_mode)}
                        >
                          <TableCell className="w-8 px-2">
                            {pinnedSearchIds.includes(search.id) && (
                              <Pin className="h-3 w-3 text-primary" />
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <VisibilityIcon visibility={search.visibility} />
                              <span className="text-sm text-foreground font-medium truncate max-w-[200px]">{search.name}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <code className="text-xs text-muted-foreground font-mono block truncate max-w-md">{search.query}</code>
                          </TableCell>
                          <TableCell>
                            {search.query_mode && (
                              <Badge variant="outline" className="text-[10px] h-4 px-1 border-border text-foreground">{search.query_mode}</Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center justify-end gap-1">
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={(e) => { e.stopPropagation(); togglePin(search.id); }}>
                                      {pinnedSearchIds.includes(search.id) ? <PinOff className="h-3 w-3" /> : <Pin className="h-3 w-3" />}
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent>{pinnedSearchIds.includes(search.id) ? 'Unpin' : 'Pin'}</TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={(e) => { e.stopPropagation(); handleCopy(search.query, search.id); }}>
                                      {copiedId === search.id ? <Check className="h-3 w-3 text-primary" /> : <Copy className="h-3 w-3" />}
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent>Copy</TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                              {search.is_owner && onShareSavedSearch && (
                                <TooltipProvider>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={(e) => { e.stopPropagation(); openShareDialog(search); }}>
                                        <Share2 className="h-3 w-3" />
                                      </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>Share</TooltipContent>
                                  </Tooltip>
                                </TooltipProvider>
                              )}
                              {search.is_owner && onDeleteSavedSearch && (
                                <TooltipProvider>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <Button variant="ghost" size="sm" className="h-6 w-6 p-0 text-destructive hover:text-destructive" onClick={(e) => { e.stopPropagation(); setDeleteConfirmSearch(search); }}>
                                        <X className="h-3 w-3" />
                                      </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>Delete</TooltipContent>
                                  </Tooltip>
                                </TooltipProvider>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            ) : (
              <div className="space-y-2 pr-4">
                {filteredSavedSearches.map((search, index) => (
                  <div
                    key={search.id}
                    className={`group flex items-center gap-3 p-3 rounded-lg border border-border bg-accent/50 hover:bg-accent cursor-pointer transition-colors ${focusedIndex === index ? 'bg-accent ring-2 ring-primary' : ''}`}
                    onClick={() => handleUse(search.query, search.query_mode)}
                    onDoubleClick={() => handleRun(search.query, search.query_mode)}
                  >
                    {pinnedSearchIds.includes(search.id) && (
                      <Pin className="h-3.5 w-3.5 text-primary flex-shrink-0" />
                    )}
                    <VisibilityIcon visibility={search.visibility} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm text-foreground font-medium truncate">{search.name}</p>
                        {!search.is_owner && search.owner_name && (
                          <span className="text-[10px] text-muted-foreground">by {search.owner_name}</span>
                        )}
                      </div>
                      <code className="text-xs text-muted-foreground font-mono block truncate mt-0.5">{search.query}</code>
                    </div>
                    {search.query_mode && (
                      <Badge variant="outline" className="text-[10px] h-4 px-1 border-border text-foreground flex-shrink-0">{search.query_mode}</Badge>
                    )}
                    <div className="flex items-center gap-1">
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={(e) => { e.stopPropagation(); togglePin(search.id); }}>
                              {pinnedSearchIds.includes(search.id) ? <PinOff className="h-3.5 w-3.5" /> : <Pin className="h-3.5 w-3.5" />}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{pinnedSearchIds.includes(search.id) ? 'Unpin' : 'Pin'}</TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={(e) => { e.stopPropagation(); handleCopy(search.query, search.id); }}>
                              {copiedId === search.id ? <Check className="h-3.5 w-3.5 text-primary" /> : <Copy className="h-3.5 w-3.5" />}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Copy</TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                      {search.is_owner && onShareSavedSearch && (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={(e) => { e.stopPropagation(); openShareDialog(search); }}>
                                <Share2 className="h-3.5 w-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Share</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                      {search.is_owner && onDeleteSavedSearch && (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-destructive hover:text-destructive" onClick={(e) => { e.stopPropagation(); setDeleteConfirmSearch(search); }}>
                                <X className="h-3.5 w-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Delete</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </TabsContent>

        {/* Shared Tab */}
        <TabsContent value="shared" className="mt-4 space-y-4">
          {/* Search filter */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search shared searches..."
              value={sharedSearchTerm}
              onChange={(e) => setSharedSearchTerm(e.target.value)}
              onKeyDown={(e) => handleKeyDown(e, filteredSharedSearches.map(s => ({ query: s.query, mode: s.query_mode })))}
              className="pl-10 border-border rounded-xl"
            />
          </div>

          <ScrollArea className="h-[min(350px,calc(100vh-400px))]">
            {filteredSharedSearches.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                <Users className="h-8 w-8 mb-2 opacity-50" />
                <p>{sharedSearchTerm ? 'No matching shared searches' : 'No searches shared with you'}</p>
                <p className="text-xs mt-1">Searches shared by others will appear here</p>
              </div>
            ) : (
              <div className="space-y-2 pr-4">
                {filteredSharedSearches.map((search, index) => (
                  <div
                    key={search.id}
                    className={`group flex items-center gap-3 p-3 rounded-lg border border-border bg-accent/50 hover:bg-accent cursor-pointer transition-colors ${focusedIndex === index ? 'bg-accent ring-2 ring-primary' : ''}`}
                    onClick={() => handleUse(search.query, search.query_mode)}
                    onDoubleClick={() => handleRun(search.query, search.query_mode)}
                  >
                    <VisibilityIcon visibility={search.visibility} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm text-foreground font-medium truncate">{search.name}</p>
                        {search.owner_name && (
                          <span className="text-[10px] text-muted-foreground">by {search.owner_name}</span>
                        )}
                      </div>
                      <code className="text-xs text-muted-foreground font-mono block truncate mt-0.5">{search.query}</code>
                    </div>
                    {search.query_mode && (
                      <Badge variant="outline" className="text-[10px] h-4 px-1 border-border text-foreground flex-shrink-0">{search.query_mode}</Badge>
                    )}
                    <div className="flex items-center gap-1">
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={(e) => { e.stopPropagation(); handleCopy(search.query, search.id); }}>
                              {copiedId === search.id ? <Check className="h-3.5 w-3.5 text-primary" /> : <Copy className="h-3.5 w-3.5" />}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Copy</TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </TabsContent>

        {/* Library Tab */}
        <TabsContent value="library" className="mt-4 space-y-4">
          {/* Search and filters */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search queries..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 border-border rounded-xl"
              />
            </div>
          </div>

          {/* Category pills */}
          <div className="flex flex-wrap gap-1">
            {categories.map((cat) => (
              <Button
                key={cat.category}
                variant={selectedCategory === cat.category ? "secondary" : "ghost"}
                size="sm"
                className={`h-7 text-xs gap-1 ${selectedCategory === cat.category ? 'text-foreground' : 'text-foreground hover:text-primary'}`}
                onClick={() => setSelectedCategory(cat.category)}
              >
                {categoryIcons[cat.category]}
                <span className="capitalize">{cat.category.replace('-', ' ')}</span>
              </Button>
            ))}
          </div>

          {/* Query list */}
          <ScrollArea className="h-[min(350px,calc(100vh-400px))]">
            {isLoading ? (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin mr-2" />
                Loading...
              </div>
            ) : queries.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                <BookOpen className="h-8 w-8 mb-2 opacity-50" />
                <p>No queries found</p>
              </div>
            ) : (
              <div className="grid gap-2 pr-4">
                {queries.map((q) => (
                  <LibraryQueryCard
                    key={q.id}
                    query={q}
                    copiedId={copiedId}
                    onCopy={handleCopy}
                    onUse={handleUse}
                    onRun={handleRun}
                  />
                ))}
              </div>
            )}
          </ScrollArea>
        </TabsContent>

        {/* Jobs Tab */}
        <TabsContent value="jobs" className="mt-4 space-y-4">
          {/* Admin stats bar */}
          {isJobsAdmin && admissionStats && (
            <div className="flex items-center gap-4 px-1 text-xs text-muted-foreground">
              <span>Active: <strong className="text-foreground">{admissionStats.active_adhoc}</strong></span>
              <span>Queued: <strong className="text-foreground">{admissionStats.queued}</strong></span>
              <span>Total: <strong className="text-foreground">{visibleJobs.length}</strong></span>
              {admissionStats.per_user_counts.length > 0 && (
                <span className="ml-auto">{admissionStats.per_user_counts.length} users</span>
              )}
            </div>
          )}
          <ScrollArea className="h-[min(350px,calc(100vh-400px))]">
            {visibleJobs.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                <Activity className="h-8 w-8 mb-2 opacity-50" />
                <p>No active or recent search jobs</p>
                <p className="text-xs mt-1">Jobs appear here when you run searches</p>
              </div>
            ) : (
              <div className="space-y-1 pr-4">
                {visibleJobs.map((job) => {
                  const config = JOB_STATUS_CONFIG[job.status] || JOB_STATUS_CONFIG.cancelled;
                  const Icon = config.icon;
                  const isActive = job.status === 'queued' || job.status === 'running';
                  const isClickable = job.status === 'completed';
                  const isDismissable = !isActive;
                  const jobUserId = (job as { user_id?: string | null }).user_id;

                  return (
                    <div
                      key={job.job_id}
                      className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm border border-border ${
                        isClickable ? 'cursor-pointer hover:bg-accent' : 'bg-accent/30'
                      }`}
                      onClick={isClickable ? () => { onLoadJob?.(job.job_id); setOpen(false); } : undefined}
                    >
                      <Icon className={`w-4 h-4 flex-shrink-0 ${
                        job.status === 'running' ? 'animate-spin' : ''
                      }`} />
                      <div className="flex-1 min-w-0">
                        <p className="truncate text-foreground font-mono text-xs">{job.query || 'Search query'}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 border ${config.color}`}>
                            {config.label}
                          </Badge>
                          {isJobsAdmin && jobUserId && (
                            <span className="text-[10px] text-muted-foreground font-mono" title={jobUserId}>
                              {jobUserId.slice(0, 8)}
                            </span>
                          )}
                          {job.queue_position != null && job.status === 'queued' && (
                            <span className="text-xs font-mono text-muted-foreground">
                              Pos {job.queue_position}
                            </span>
                          )}
                          <span className="text-xs font-mono text-muted-foreground">
                            {formatElapsed(job.elapsed_ms)}
                          </span>
                        </div>
                      </div>
                      {isActive && (isJobsAdmin ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 p-0 flex-shrink-0 text-destructive hover:text-destructive"
                          onClick={(e) => {
                            e.stopPropagation();
                            api.adminCancelSearchJob(job.job_id).then(() => {
                              queryClient.invalidateQueries({ queryKey: ['admin-search-jobs'] });
                              queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
                            });
                          }}
                        >
                          <X className="w-3.5 h-3.5" />
                        </Button>
                      ) : onCancelJob && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 p-0 flex-shrink-0"
                          onClick={(e) => {
                            e.stopPropagation();
                            onCancelJob(job.job_id);
                            queryClient.invalidateQueries({ queryKey: ['search-jobs'] });
                          }}
                        >
                          <X className="w-3.5 h-3.5" />
                        </Button>
                      ))}
                      {isDismissable && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 p-0 flex-shrink-0 text-muted-foreground hover:text-foreground"
                          onClick={(e) => {
                            e.stopPropagation();
                            dismissJob(job.job_id);
                          }}
                        >
                          <X className="w-3.5 h-3.5" />
                        </Button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </ScrollArea>
        </TabsContent>
      </Tabs>

      <div className="p-3 pt-2 border-t border-border flex items-center justify-between">
        <p className="search-console-section-meta">click loads · double-click or ⌘↵ executes</p>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
              <Settings2 className="h-3.5 w-3.5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="bg-card border-border rounded-xl">
            <DropdownMenuItem
              onClick={() => setSearchHubStyle('popover')}
              className={`text-foreground cursor-pointer rounded-lg ${hubStyle === 'popover' ? 'bg-accent' : ''}`}
            >
              <Layers className="h-4 w-4 mr-2" />
              Popover mode
              {hubStyle === 'popover' && <Check className="h-4 w-4 ml-auto" />}
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => setSearchHubStyle('drawer')}
              className={`text-foreground cursor-pointer rounded-lg ${hubStyle === 'drawer' ? 'bg-accent' : ''}`}
            >
              <PanelRightOpen className="h-4 w-4 mr-2" />
              Flyout mode
              {hubStyle === 'drawer' && <Check className="h-4 w-4 ml-auto" />}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </>
  );

  return (
    <>
      {/* Search Hub Button — hidden when parent provides a custom trigger */}
      {!hideTrigger && (
        <Button
          variant="ghost"
          size="sm"
          className="text-muted-foreground hover:text-primary hover:bg-accent/50 rounded-lg h-7 px-2 text-xs gap-1.5 relative"
          onClick={() => setOpen(true)}
        >
          <Compass className="h-3.5 w-3.5" />
          Search Hub
          {activeJobCount > 0 && (
            <span className="absolute -top-1 -right-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-blue-500 text-[10px] font-medium text-white px-1">
              {activeJobCount}
            </span>
          )}
        </Button>
      )}

      {/* Dialog Mode (formerly Popover) */}
      {hubStyle === 'popover' && (
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogContent className="max-w-[800px] w-[calc(100vw-40px)] p-0 bg-card border-border gap-0">
            <DialogHeader className="p-4 border-b border-border">
              <div className="flex items-center gap-2">
                <DialogTitle className="search-console-section-header text-foreground"><Compass />Search Hub</DialogTitle>
              </div>
              <DialogDescription className="search-console-section-meta mt-1">
                Query library, recall history, and saved searches in one place
              </DialogDescription>
            </DialogHeader>
            {hubContent}
          </DialogContent>
        </Dialog>
      )}

      {/* Flyout mode: right sheet on desktop, bottom sheet on mobile */}
      {hubStyle === 'drawer' && (
        <Sheet open={open} onOpenChange={setOpen}>
          <SheetContent
            side={isMobile ? 'bottom' : 'right'}
            className={isMobile
              ? 'h-[50vh] max-h-[50vh] p-0 bg-card border-border rounded-t-xl'
              : 'w-[760px] max-w-[min(760px,calc(100vw-32px))] p-0 bg-card border-border'}
          >
            <SheetHeader className="p-4 border-b border-border">
              <div className="flex items-center gap-2">
                <SheetTitle className="search-console-section-header text-foreground"><Compass />Search Hub</SheetTitle>
              </div>
              <SheetDescription className="search-console-section-meta mt-1">
                Query library, recall history, and saved searches in one place
              </SheetDescription>
            </SheetHeader>
            {hubContent}
          </SheetContent>
        </Sheet>
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteConfirmSearch}
        onOpenChange={(open) => !open && setDeleteConfirmSearch(null)}
        variant="danger"
        title="Delete saved search"
        description={
          <>
            Are you sure you want to delete "
            <span className="text-foreground font-medium">{deleteConfirmSearch?.name}</span>"? This
            action cannot be undone.
          </>
        }
        confirmLabel="Delete"
        onConfirm={() => {
          if (deleteConfirmSearch && onDeleteSavedSearch) {
            onDeleteSavedSearch(deleteConfirmSearch.id);
          }
          setDeleteConfirmSearch(null);
        }}
      />

      {/* Share Dialog */}
      <AlertDialog open={!!shareSearch} onOpenChange={(open) => !open && setShareSearch(null)}>
        <AlertDialogContent className="max-w-md">
          <AlertDialogHeader>
            <AlertDialogTitle>Share "{shareSearch?.name}"</AlertDialogTitle>
            <AlertDialogDescription>
              Choose who can see this saved search.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-4 py-4">
            <RadioGroup value={shareVisibility} onValueChange={(v) => setShareVisibility(v as 'private' | 'public' | 'group')} className="space-y-3">
              <label className="flex items-center gap-3 p-3 rounded-lg border border-border cursor-pointer hover:bg-accent/50 transition-colors">
                <RadioGroupItem value="private" />
                <Lock className="h-4 w-4 text-muted-foreground" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Private</p>
                  <p className="text-xs text-muted-foreground">Only you can see this search</p>
                </div>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg border border-border cursor-pointer hover:bg-accent/50 transition-colors">
                <RadioGroupItem value="public" />
                <Globe2 className="h-4 w-4 text-green-500" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Public</p>
                  <p className="text-xs text-muted-foreground">Everyone in your organization can see this</p>
                </div>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg border border-border cursor-pointer hover:bg-accent/50 transition-colors">
                <RadioGroupItem value="group" />
                <Users className="h-4 w-4 text-blue-500" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Specific Groups</p>
                  <p className="text-xs text-muted-foreground">Only members of selected groups can see this</p>
                </div>
              </label>
            </RadioGroup>

            {shareVisibility === 'group' && availableGroups.length > 0 && (
              <div className="space-y-2 pl-6">
                <p className="text-sm font-medium">Select groups:</p>
                <div className="space-y-2 max-h-32 overflow-y-auto">
                  {availableGroups.map((group) => (
                    <label key={group.id} className="flex items-center gap-2 cursor-pointer">
                      <Checkbox
                        checked={shareGroupIds.includes(group.id)}
                        onCheckedChange={(checked) => {
                          if (checked) {
                            setShareGroupIds([...shareGroupIds, group.id]);
                          } else {
                            setShareGroupIds(shareGroupIds.filter(id => id !== group.id));
                          }
                        }}
                      />
                      <span className="text-sm">{group.name}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {shareVisibility === 'group' && availableGroups.length === 0 && (
              <p className="text-sm text-muted-foreground pl-6">No groups available</p>
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleShareSave}>
              Save
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

// Library query card component
function LibraryQueryCard({
  query,
  copiedId,
  onCopy,
  onUse,
  onRun,
}: {
  query: LibraryQuery;
  copiedId: number | string | null;
  onCopy: (query: string, id: number) => void;
  onUse: (query: string) => void;
  onRun: (query: string) => void;
}) {
  return (
    <div
      className="rounded-lg border border-border bg-accent/50 p-2.5 space-y-2 hover:bg-accent transition-colors cursor-pointer"
      onClick={() => onUse(query.query)}
      onDoubleClick={() => onRun(query.query)}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-sm text-foreground">{query.name}</span>
            <Badge variant="outline" className={`text-[10px] ${difficultyColors[query.difficulty]}`}>
              {query.difficulty}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{query.description}</p>
        </div>
      </div>

      <div className="rounded bg-muted/30 p-2 font-mono text-xs overflow-x-auto">
        <code className="text-emerald-700 dark:text-emerald-400 whitespace-pre-wrap break-all">{query.query}</code>
      </div>

      <div className="flex items-center justify-between">
        <div className="flex flex-wrap gap-1">
          {query.tags.slice(0, 3).map((tag) => (
            <Badge key={tag} variant="outline" className="text-[10px] px-1 py-0 text-muted-foreground border-border">
              {tag}
            </Badge>
          ))}
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={(e) => { e.stopPropagation(); onCopy(query.query, query.id); }}>
            {copiedId === query.id ? <Check className="h-3 w-3 mr-1" /> : <Copy className="h-3 w-3 mr-1" />}
            {copiedId === query.id ? 'Copied' : 'Copy'}
          </Button>
          <Button size="sm" className="h-6 px-2 text-xs bg-primary hover:bg-primary/90" onClick={(e) => { e.stopPropagation(); onRun(query.query); }}>
            <Play className="h-3 w-3 mr-1" />
            Run
          </Button>
        </div>
      </div>
    </div>
  );
}

export default SearchHub;
