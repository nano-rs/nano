// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Cybersecurity News Feed Component
 *
 * Displays aggregated cybersecurity news from multiple sources.
 */

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Loader2, Newspaper, ExternalLink, RefreshCw, CircleAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useNews } from '@/hooks/use-api';
import type { NewsItem } from '@/lib/api';
import { formatRelativeCompact } from '@/lib/date-utils';

// Source colors for visual distinction
const SOURCE_COLORS: Record<string, string> = {
  cisa: 'bg-primary/10 text-primary border-blue-500/20',
  hackernews: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  bleeping: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  krebs: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/20',
};

function NewsItemCard({ item }: { item: NewsItem }) {
  const colorClass = SOURCE_COLORS[item.source_id] || 'bg-gray-500/10 text-muted-foreground border-gray-500/20';

  return (
    <a
      href={item.link}
      target="_blank"
      rel="noopener noreferrer"
      className="block p-3 bg-muted/50 rounded-xl hover:bg-accent/50 transition-all group"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <Badge className={`${colorClass} rounded-lg text-[10px] px-1.5 py-0`}>
              {item.source}
            </Badge>
            {item.published && (
              <span className="text-[10px] text-muted-foreground">
                {formatRelativeCompact(item.published)}
              </span>
            )}
          </div>
          <h4 className="text-sm font-medium text-foreground group-hover:text-primary transition-colors line-clamp-2">
            {item.title}
          </h4>
          {item.summary && (
            <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
              {item.summary}
            </p>
          )}
        </div>
        <ExternalLink className="w-3.5 h-3.5 text-muted-foreground group-hover:text-muted-foreground flex-shrink-0 mt-1" />
      </div>
    </a>
  );
}

export function CyberNewsFeed() {
  const { data: news, loading, error, refetch } = useNews();

  return (
    <Card className="bg-card border-0 rounded-2xl shadow-lg">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-foreground flex items-center gap-2">
            <Newspaper className="w-5 h-5" />
            Security News
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => refetch()}
            disabled={loading}
            className="h-8 w-8 p-0 hover:bg-accent/50"
          >
            <RefreshCw className={`w-4 h-4 text-muted-foreground ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
        {news?.last_updated && (
          <p className="text-[10px] text-muted-foreground mt-1">
            Updated {formatRelativeCompact(news.last_updated)}
          </p>
        )}
      </CardHeader>
      <CardContent>
        {loading && !news ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <CircleAlert className="w-8 h-8 text-red-400 mb-2" />
            <p className="text-sm text-muted-foreground">Failed to load news feed</p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              className="mt-3 rounded-xl border-border"
            >
              Try Again
            </Button>
          </div>
        ) : news?.items.length === 0 ? (
          <p className="text-muted-foreground text-sm py-8 text-center">No news available</p>
        ) : (
          <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1 custom-scrollbar">
            {news?.items.map((item, index) => (
              <NewsItemCard key={`${item.source_id}-${index}`} item={item} />
            ))}
          </div>
        )}

        {/* Source status indicators */}
        {news?.sources && news.sources.length > 0 && (
          <div className="mt-4 pt-3 border-t border-border">
            <div className="flex flex-wrap gap-2">
              {news.sources.map((source) => (
                <div
                  key={source.id}
                  className={`flex items-center gap-1.5 text-[10px] ${
                    source.status === 'ok' ? 'text-muted-foreground' : 'text-red-400'
                  }`}
                  title={source.error || `${source.item_count} items`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    source.status === 'ok' ? 'bg-green-500' : 'bg-red-500'
                  }`} />
                  {source.name}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
