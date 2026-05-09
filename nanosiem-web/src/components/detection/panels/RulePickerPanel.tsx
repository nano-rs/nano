// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Simplified rule repository browser for the rule editor right panel.
 *
 * Shows synced repositories, lets users search and browse rules,
 * and load one directly into the editor with a single click.
 */

import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Search,
  Loader2,
  ChevronRight,
  ChevronLeft,
  FileCode,
  ArrowDownToLine,
  BookOpen,
} from 'lucide-react';
import { api } from '@/lib/api';
import type { RepositoryRule } from '@/lib/api/rule-repositories';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

const PAGE_SIZE = 10;

/**
 * Convert YAML array fields in frontmatter to comma-separated values.
 *
 * Repo rules store fields like:
 *   mitre_tactics:
 *     - TA0009
 *     - TA0010
 *
 * Editor expects:
 *   mitre_tactics: TA0009, TA0010
 *
 * Also strips ai_triage_hints block (handled via the Hints tab separately).
 */
function normalizeYamlArrays(content: string): string {
  const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/);
  if (!frontmatterMatch) return content;

  const [, frontmatter, query] = frontmatterMatch;
  const lines = frontmatter.split('\n');
  const result: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // Check if this line is a key with no inline value (array or object follows)
    const keyMatch = trimmed.match(/^(\w[\w_]*):$/);
    if (keyMatch) {
      const key = keyMatch[1];
      const items: string[] = [];
      let j = i + 1;
      let isSimpleArray = true;

      // Collect consecutive "  - value" lines
      while (j < lines.length) {
        const nextTrimmed = lines[j].trim();
        if (nextTrimmed.startsWith('- ')) {
          items.push(nextTrimmed.slice(2).replace(/^["']|["']$/g, ''));
          j++;
        } else if (nextTrimmed === '') {
          j++;
        } else if (nextTrimmed.match(/^\w/) || nextTrimmed === '---') {
          // Hit next top-level key or end of frontmatter
          break;
        } else {
          // Indented non-array content (nested object)
          isSimpleArray = false;
          break;
        }
      }

      if (isSimpleArray && items.length > 0) {
        const joined = items.join(', ');
        const needsQuotes = joined.includes(':') || joined.includes('#');
        result.push(needsQuotes ? `${key}: "${joined}"` : `${key}: ${joined}`);
        i = j;
        continue;
      }

      // For nested objects like ai_triage_hints — skip the whole block
      if (!isSimpleArray) {
        let k = j;
        while (k < lines.length) {
          const kTrimmed = lines[k].trim();
          // Stop at next top-level key or empty line followed by top-level key
          if (kTrimmed.length > 0 && !lines[k].startsWith(' ') && !lines[k].startsWith('\t')) break;
          k++;
        }
        // Don't emit the nested block (ai_triage_hints etc.)
        i = k;
        continue;
      }
    }

    result.push(line);
    i++;
  }

  return `---\n${result.join('\n')}\n---\n${query}`;
}

interface RulePickerPanelProps {
  /** Called when a rule is selected — passes the normalized rule content to load into the editor */
  onLoadRule: (rawContent: string, ruleName: string) => void;
}

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'informational';

export function RulePickerPanel({ onLoadRule }: RulePickerPanelProps) {
  const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [page, setPage] = useState(0);

  // Fetch repositories
  const { data: reposData, isLoading: loadingRepos } = useQuery({
    queryKey: ['rule-repositories'],
    queryFn: () => api.ruleRepositories.listRepositories(),
  });

  const repos = reposData?.repositories?.filter(r => r.rule_count > 0) ?? [];
  const activeRepoId = selectedRepoId ?? repos[0]?.id ?? null;

  // Fetch rules for selected repo
  const { data: rules, isLoading: loadingRules } = useQuery({
    queryKey: ['rule-picker-rules', activeRepoId, search, severityFilter],
    queryFn: () => api.ruleRepositories.listRules(activeRepoId!, {
      search: search || undefined,
      severity: severityFilter !== 'all' ? severityFilter : undefined,
      limit: 200,
    }),
    enabled: !!activeRepoId,
  });

  const filteredRules = useMemo(() => {
    if (!rules) return [];
    return rules.filter(r => !r.is_imported);
  }, [rules]);

  const paginatedRules = useMemo(() => {
    return filteredRules.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  }, [filteredRules, page]);

  const totalPages = Math.max(1, Math.ceil(filteredRules.length / PAGE_SIZE));

  // Reset page on filter change
  useMemo(() => setPage(0), [search, severityFilter, activeRepoId]);

  const handleUseRule = (rule: RepositoryRule) => {
    const content = rule.raw_content;
    if (!content) {
      toast.error('Rule has no content');
      return;
    }
    const normalized = normalizeYamlArrays(content);
    const name = rule.title || rule.file_path.split('/').pop()?.replace(/\.(yml|yaml|toml)$/, '') || 'rule';
    onLoadRule(normalized, name);
    toast.success(`Loaded "${name}" into editor`);
  };

  const severityColor = (severity: string | null) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'low': return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
      default: return 'text-muted-foreground bg-muted border-border';
    }
  };

  if (loadingRepos) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (repos.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center space-y-3">
        <BookOpen className="w-10 h-10 text-muted-foreground opacity-40" />
        <div>
          <p className="text-sm text-muted-foreground">No rule repositories synced</p>
          <p className="text-xs text-muted-foreground mt-1">
            Add and sync a repository in{' '}
            <a href="/rules/repositories" className="text-primary hover:underline">
              Rules &gt; Repositories
            </a>
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {repos.length > 1 && (
        <Select value={activeRepoId ?? ''} onValueChange={setSelectedRepoId}>
          <SelectTrigger className="border-border rounded-xl h-8 text-sm">
            <SelectValue placeholder="Select repository" />
          </SelectTrigger>
          <SelectContent>
            {repos.map(r => (
              <SelectItem key={r.id} value={r.id}>
                {r.name} ({r.rule_count} rules)
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules..."
            className="pl-8 border-border rounded-xl h-8 text-sm"
          />
        </div>
        <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as SeverityFilter)}>
          <SelectTrigger className="w-[100px] border-border rounded-xl h-8 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-1.5">
        {loadingRules ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : paginatedRules.length === 0 ? (
          <div className="text-center py-8">
            <FileCode className="w-8 h-8 mx-auto text-muted-foreground opacity-30 mb-2" />
            <p className="text-xs text-muted-foreground">
              {search ? 'No matching rules found' : 'No importable rules available'}
            </p>
          </div>
        ) : (
          paginatedRules.map((rule) => (
            <div
              key={rule.id}
              className="group p-2.5 rounded-xl bg-muted/30 hover:bg-accent/50 transition-colors border border-transparent hover:border-border"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">
                    {rule.title || rule.file_path.split('/').pop()?.replace(/\.(yml|yaml|toml)$/, '')}
                  </p>
                  {rule.description && (
                    <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                      {rule.description}
                    </p>
                  )}
                  <div className="flex items-center gap-1.5 mt-1.5">
                    {rule.severity && (
                      <Badge className={cn('text-[10px] px-1.5 py-0 rounded', severityColor(rule.severity))}>
                        {rule.severity}
                      </Badge>
                    )}
                    {rule.mitre_tactics && rule.mitre_tactics.length > 0 && (
                      <span className="text-[10px] text-muted-foreground">
                        {rule.mitre_tactics.join(', ')}
                      </span>
                    )}
                  </div>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 px-2 text-xs opacity-0 group-hover:opacity-100 transition-opacity text-primary hover:text-primary hover:bg-primary/10"
                  onClick={() => handleUseRule(rule)}
                >
                  <ArrowDownToLine className="w-3.5 h-3.5 mr-1" />
                  Use
                </Button>
              </div>
            </div>
          ))
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-1">
          <p className="text-[10px] text-muted-foreground">
            {filteredRules.length} rules
          </p>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPage(p => p - 1)}
              disabled={page === 0}
              className="h-6 w-6 p-0"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </Button>
            <span className="text-[10px] text-muted-foreground px-1">
              {page + 1}/{totalPages}
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPage(p => p + 1)}
              disabled={page >= totalPages - 1}
              className="h-6 w-6 p-0"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
