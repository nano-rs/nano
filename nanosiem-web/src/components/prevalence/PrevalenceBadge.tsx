// SPDX-License-Identifier: AGPL-3.0-or-later

import { Badge } from '@/components/ui/badge';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { Activity, AlertTriangle, Eye } from 'lucide-react';
import { formatUTCCompact } from '@/lib/date-utils';

export interface PrevalenceData {
  artifact: string;
  artifact_type: 'hash_md5' | 'hash_sha256' | 'hash_unknown' | 'domain' | 'subdomain' | 'ip_address' | 'ip_address_private';
  host_count: number;
  total_occurrences: number;
  first_seen: string;
  last_seen: string;
  is_rare: boolean;
  prevalence_score: number;
}

interface PrevalenceBadgeProps {
  data: PrevalenceData;
  showLabel?: boolean;
  size?: 'sm' | 'md';
  onClick?: () => void;
}

/**
 * Get color classes based on prevalence score
 * Lower score = rarer = more suspicious (red/orange)
 * Higher score = more common = less suspicious (green/blue)
 */
function getPrevalenceColor(score: number, isRare: boolean): string {
  if (isRare || score <= 10) {
    return 'bg-red-500/20 text-red-400 border-red-500/30';
  }
  if (score <= 25) {
    return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
  }
  if (score <= 50) {
    return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  }
  if (score <= 75) {
    return 'bg-primary/20 text-primary border-blue-500/30';
  }
  return 'bg-green-500/20 text-green-400 border-green-500/30';
}

/**
 * Get rarity label based on prevalence score
 */
function getRarityLabel(score: number, isRare: boolean): string {
  if (isRare || score <= 10) return 'Very Rare';
  if (score <= 25) return 'Rare';
  if (score <= 50) return 'Uncommon';
  if (score <= 75) return 'Common';
  return 'Very Common';
}

/**
 * Format artifact type for display
 */
function formatArtifactType(type: PrevalenceData['artifact_type']): string {
  switch (type) {
    case 'hash_md5':
      return 'MD5 Hash';
    case 'hash_sha256':
      return 'SHA256 Hash';
    case 'hash_unknown':
      return 'Hash';
    case 'domain':
      return 'Domain';
    case 'subdomain':
      return 'Subdomain';
    default:
      return 'Unknown';
  }
}

/**
 * PrevalenceBadge component displays a color-coded rarity indicator
 * with detailed prevalence information on hover.
 * 
 * Requirements: 5.5 - Display prevalence as a visual indicator (color-coded rarity badge)
 */
export function PrevalenceBadge({
  data,
  showLabel = false,
  size = 'sm',
  onClick,
}: PrevalenceBadgeProps) {
  const colorClasses = getPrevalenceColor(data.prevalence_score, data.is_rare);
  const rarityLabel = getRarityLabel(data.prevalence_score, data.is_rare);
  const sizeClasses = size === 'sm' ? 'text-xs px-1.5 py-0.5' : 'text-sm px-2 py-1';

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="outline"
            className={`${colorClasses} ${sizeClasses} cursor-pointer transition-all hover:opacity-80 ${onClick ? 'hover:ring-1 hover:ring-white/20' : ''}`}
            onClick={onClick}
          >
            {data.is_rare ? (
              <AlertTriangle className="w-3 h-3 mr-1" />
            ) : data.prevalence_score > 75 ? (
              <Eye className="w-3 h-3 mr-1" />
            ) : (
              <Activity className="w-3 h-3 mr-1" />
            )}
            {showLabel ? rarityLabel : data.host_count}
          </Badge>
        </TooltipTrigger>
        <TooltipContent
          side="top"
          className="bg-card border-border text-xs max-w-xs p-3"
        >
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-4">
              <span className="font-semibold text-foreground">{rarityLabel}</span>
              <span className={`font-mono ${colorClasses} px-1.5 py-0.5 rounded`}>
                Score: {data.prevalence_score}
              </span>
            </div>
            
            <div className="border-t border-border pt-2 space-y-1">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Type:</span>
                <span className="text-foreground">{formatArtifactType(data.artifact_type)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Hosts seen:</span>
                <span className="text-foreground font-mono">{data.host_count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total occurrences:</span>
                <span className="text-foreground font-mono">{data.total_occurrences}</span>
              </div>
            </div>
            
            <div className="border-t border-border pt-2 space-y-1">
              <div className="flex justify-between">
                <span className="text-muted-foreground">First seen:</span>
                <span className="text-foreground">{formatUTCCompact(data.first_seen)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last seen:</span>
                <span className="text-foreground">{formatUTCCompact(data.last_seen)}</span>
              </div>
            </div>
            
            {data.is_rare && (
              <div className="border-t border-border pt-2">
                <div className="flex items-center gap-1 text-red-400">
                  <AlertTriangle className="w-3 h-3" />
                  <span className="text-xs">Below rarity threshold - potentially suspicious</span>
                </div>
              </div>
            )}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

/**
 * Compact version of PrevalenceBadge for inline use
 */
export function PrevalenceBadgeCompact({
  hostCount,
  isRare,
  prevalenceScore,
}: {
  hostCount: number;
  isRare: boolean;
  prevalenceScore: number;
}) {
  const colorClasses = getPrevalenceColor(prevalenceScore, isRare);

  return (
    <span
      className={`inline-flex items-center ${colorClasses} text-xs px-1 py-0.5 rounded font-mono`}
      title={`${hostCount} hosts, score: ${prevalenceScore}`}
    >
      {isRare && <AlertTriangle className="w-2.5 h-2.5 mr-0.5" />}
      {hostCount}
    </span>
  );
}
