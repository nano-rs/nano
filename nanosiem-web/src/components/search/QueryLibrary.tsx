// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useMemo, useEffect, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  BookOpen,
  Search,
  ChevronRight,
  ChevronDown,
  Play,
  Copy,
  Check,
  Shield,
  Network,
  Key,
  Globe,
  AlertTriangle,
  ChartColumn,
  Clock,
  FileText,
  Loader2,
} from 'lucide-react';

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

interface QueryLibraryProps {
  onSelectQuery: (query: string) => void;
}

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
  beginner: 'bg-green-500/10 text-green-500 border-emerald-200 dark:border-emerald-500/20',
  intermediate: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  advanced: 'bg-red-500/10 text-red-500 border-red-500/20',
};

const API_BASE = import.meta.env.VITE_API_URL ?? '';

export function QueryLibrary({ onSelectQuery }: QueryLibraryProps) {
  const [open, setOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set(['basics']));
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [queries, setQueries] = useState<LibraryQuery[]>([]);
  const [categories, setCategories] = useState<CategoryCount[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Fetch queries
  const fetchQueries = useCallback(async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      if (searchTerm) params.set('search', searchTerm);
      if (selectedCategory) params.set('category', selectedCategory);
      const response = await fetch(`${API_BASE}/api/query-library?${params}`);
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
      const response = await fetch(`${API_BASE}/api/query-library/categories`);
      if (response.ok) {
        const data = await response.json();
        setCategories(data.categories || []);
      }
    } catch (err) {
      console.error('Failed to fetch categories:', err);
    }
  }, []);

  // Load data when sheet opens
  useEffect(() => {
    if (open) {
      fetchQueries();
      fetchCategories();
    }
  }, [open, fetchQueries, fetchCategories]);

  // Group queries by category
  const queriesByCategory = useMemo(() => {
    const grouped: Record<string, LibraryQuery[]> = {};
    for (const query of queries) {
      if (!grouped[query.category]) {
        grouped[query.category] = [];
      }
      grouped[query.category].push(query);
    }
    return grouped;
  }, [queries]);

  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  const handleCopy = async (query: LibraryQuery) => {
    await navigator.clipboard.writeText(query.query);
    setCopiedId(query.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleUse = (query: LibraryQuery) => {
    onSelectQuery(query.query);
    setOpen(false);
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-primary hover:bg-accent/50 rounded-lg h-7 px-2 text-xs">
          <BookOpen className="h-3.5 w-3.5" />
          Query Library
        </Button>
      </SheetTrigger>
      <SheetContent side="right" className="w-[550px] sm:max-w-[550px] bg-card border-border p-0">
        <SheetHeader className="p-4 border-b border-border">
          <SheetTitle className="flex items-center gap-2 text-foreground">
            <span className="search-console-section-header"><BookOpen />Query Library</span>
          </SheetTitle>
          <SheetDescription className="search-console-section-meta">
            Example searches for learning the language and pivoting faster.
          </SheetDescription>
        </SheetHeader>

        <div className="space-y-4 px-4 pt-4 pb-6">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search library..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 bg-muted/50 border-border text-foreground"
            />
          </div>

          {/* Category filter */}
          <div className="flex flex-wrap gap-1">
            <Button
              variant={selectedCategory === null ? "secondary" : "ghost"}
              size="sm"
              className="h-7 text-xs"
              onClick={() => setSelectedCategory(null)}
            >
              All
            </Button>
            {categories.slice(0, 8).map((cat) => (
              <Button
                key={cat.category}
                variant={selectedCategory === cat.category ? "secondary" : "ghost"}
                size="sm"
                className="h-7 text-xs gap-1"
                onClick={() => setSelectedCategory(cat.category)}
              >
                {categoryIcons[cat.category]}
                <span className="capitalize">{cat.category.replace('-', ' ')}</span>
                <Badge variant="outline" className="ml-1 h-4 px-1 text-[10px]">
                  {cat.count}
                </Badge>
              </Button>
            ))}
          </div>

          {/* Query list */}
          <ScrollArea className="h-[calc(100vh-280px)]">
            {isLoading ? (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin mr-2" />
                Loading library entries...
              </div>
            ) : queries.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                <Search className="h-8 w-8 mb-2 opacity-50" />
                <p className="search-console-section-header justify-center"><BookOpen />Query Library</p>
                <p className="mt-3 text-sm text-foreground">No library entries returned</p>
                <p className="text-xs mt-1">Seed the query library or clear the current library filter.</p>
              </div>
            ) : selectedCategory ? (
              <div className="space-y-2 pr-4">
                {queries.map((query) => (
                  <QueryCard
                    key={query.id}
                    query={query}
                    copiedId={copiedId}
                    onCopy={handleCopy}
                    onUse={handleUse}
                  />
                ))}
              </div>
            ) : (
              <div className="space-y-2 pr-4">
                {Object.entries(queriesByCategory).map(([category, categoryQueries]) => (
                  <Collapsible
                    key={category}
                    open={expandedCategories.has(category)}
                    onOpenChange={() => toggleCategory(category)}
                  >
                    <CollapsibleTrigger className="flex w-full items-center gap-2 rounded-lg border border-border bg-accent/50 p-3 hover:bg-accent transition-colors text-foreground">
                      {expandedCategories.has(category) ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                      {categoryIcons[category] || <FileText className="h-4 w-4" />}
                      <span className="font-medium capitalize">{category.replace('-', ' ')}</span>
                      <Badge variant="secondary" className="ml-auto">
                        {categoryQueries.length}
                      </Badge>
                    </CollapsibleTrigger>
                    <CollapsibleContent className="mt-2 space-y-2 pl-4">
                      {categoryQueries.map((query) => (
                        <QueryCard
                          key={query.id}
                          query={query}
                          copiedId={copiedId}
                          onCopy={handleCopy}
                          onUse={handleUse}
                        />
                      ))}
                    </CollapsibleContent>
                  </Collapsible>
                ))}
              </div>
            )}
          </ScrollArea>
        </div>
      </SheetContent>
    </Sheet>
  );
}

interface QueryCardProps {
  query: LibraryQuery;
  copiedId: number | null;
  onCopy: (query: LibraryQuery) => void;
  onUse: (query: LibraryQuery) => void;
}

function QueryCard({ query, copiedId, onCopy, onUse }: QueryCardProps) {
  return (
    <div className="rounded-lg border border-border bg-accent/50 p-3 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-sm text-foreground">{query.name}</span>
            <Badge variant="outline" className={`text-[10px] ${difficultyColors[query.difficulty]}`}>
              {query.difficulty}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-1">{query.description}</p>
        </div>
      </div>

      {/* Query preview */}
      <div className="rounded bg-muted/30 p-2 font-mono text-xs overflow-x-auto">
        <code className="text-foreground whitespace-pre-wrap break-all">{query.query}</code>
      </div>

      {/* Tags */}
      {query.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {query.tags.slice(0, 5).map((tag) => (
            <Badge key={tag} variant="outline" className="text-[10px] px-1.5 py-0 text-muted-foreground border-border">
              {tag}
            </Badge>
          ))}
          {query.tags.length > 5 && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-muted-foreground border-border">
              +{query.tags.length - 5}
            </Badge>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 pt-1">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs gap-1 border-border"
                onClick={() => onCopy(query)}
              >
                {copiedId === query.id ? (
                  <>
                    <Check className="h-3 w-3" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" />
                    Copy
                  </>
                )}
              </Button>
            </TooltipTrigger>
            <TooltipContent>Copy query to clipboard</TooltipContent>
          </Tooltip>
        </TooltipProvider>

        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="sm"
                className="h-7 text-xs gap-1 bg-primary hover:bg-primary/90"
                onClick={() => onUse(query)}
              >
                <Play className="h-3 w-3" />
                Use Query
              </Button>
            </TooltipTrigger>
            <TooltipContent>Load this query into the search bar</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>
    </div>
  );
}

export default QueryLibrary;
