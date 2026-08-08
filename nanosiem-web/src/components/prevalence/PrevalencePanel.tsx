// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useMemo, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ChevronDown, ChevronRight, Activity, Loader2, AlertTriangle, RefreshCw } from 'lucide-react';
import { PrevalenceScatterPlot, type PrevalenceScatterData } from './PrevalenceScatterPlot';
import { usePrevalenceScatterData } from '@/hooks/use-api';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface PrevalencePanelProps {
  results: SearchResult[];
  hasSearched: boolean;
  onArtifactFilter?: (artifact: string, artifactType: 'hash' | 'domain') => void;
  onSelectionFilter?: (artifacts: string[]) => void;
  timeWindow?: string;
}

/**
 * Artifact occurrence with event timestamp from search results
 */
interface ArtifactOccurrence {
  artifact: string;
  eventTimestamp: Date;
  occurrenceCount: number; // How many times this artifact appeared at this timestamp
}

/**
 * Parse timestamp string as UTC (handles database format without Z suffix)
 */
function parseTimestampAsUTC(timestamp: string | Date | undefined): Date {
  if (!timestamp) return new Date();
  if (timestamp instanceof Date) return timestamp;

  // If it already has timezone info (Z or +/-), parse directly
  if (timestamp.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(timestamp)) {
    return new Date(timestamp);
  }

  // Database format: "YYYY-MM-DD HH:MM:SS.ffffff" - append Z to treat as UTC
  const isoString = timestamp.replace(' ', 'T') + 'Z';
  return new Date(isoString);
}

/**
 * Extract unique hashes and domains from search results WITH their event timestamps.
 * This ensures the chart shows artifacts at the time they appeared in the search results,
 * not at the global first/last seen times from prevalence aggregation.
 */
function extractArtifactsWithTimestamps(results: SearchResult[]): {
  hashes: string[];
  domains: string[];
  hashOccurrences: ArtifactOccurrence[];
  domainOccurrences: ArtifactOccurrence[];
} {
  const hashes = new Set<string>();
  const domains = new Set<string>();

  // Per-event occurrences — one dot per event, no deduplication.
  // This lets users click individual dots to navigate to the underlying event.
  const hashOccurrences: ArtifactOccurrence[] = [];
  const domainOccurrences: ArtifactOccurrence[] = [];

  // Handle asset view: events are nested in _asset_events
  let eventsToProcess: Array<{ timestamp: Date; fields: Record<string, unknown> }> = [];

  if (results.length === 1 && results[0]?.fields?._display_type === 'asset') {
    // Asset view - extract from individual _asset_events so each event gets its own dot
    const assetEvents = results[0].fields._asset_events as Array<{ timestamp: string; details?: Record<string, unknown> }> | undefined;
    if (assetEvents) {
      eventsToProcess = assetEvents.map(e => ({
        timestamp: parseTimestampAsUTC(e.timestamp),
        fields: e.details || (e as unknown as Record<string, unknown>),
      }));
    }
  } else {
    // Normal search results
    eventsToProcess = results.map(r => ({
      timestamp: r.timestamp,
      fields: r.fields || {},
    }));
  }

  for (const event of eventsToProcess) {
    const fields = event.fields;
    if (!fields) continue;

    const eventTimestamp = event.timestamp;
    // Dedup within the same event (same artifact extracted from multiple fields)
    const seenInEvent = new Set<string>();

    // Helper to add hash with timestamp
    const addHash = (hash: unknown) => {
      if (hash && typeof hash === 'string' && hash.length >= 32 && /^[a-fA-F0-9]{32,64}$/.test(hash)) {
        const normalizedHash = hash.toLowerCase();
        hashes.add(normalizedHash);

        const eventKey = `h_${normalizedHash}`;
        if (!seenInEvent.has(eventKey)) {
          seenInEvent.add(eventKey);
          hashOccurrences.push({
            artifact: normalizedHash,
            eventTimestamp,
            occurrenceCount: 1,
          });
        }
      }
    };

    // Helper to add domain with timestamp
    const addDomain = (domain: unknown) => {
      if (domain && typeof domain === 'string' && domain.includes('.') &&
          !domain.includes(' ') && !/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
        const normalizedDomain = domain.toLowerCase();
        domains.add(normalizedDomain);

        const eventKey = `d_${normalizedDomain}`;
        if (!seenInEvent.has(eventKey)) {
          seenInEvent.add(eventKey);
          domainOccurrences.push({
            artifact: normalizedDomain,
            eventTimestamp,
            occurrenceCount: 1,
          });
        }
      }
    };

    // Extract file hashes
    addHash(fields.file_hash);
    addHash(fields.process_hash);

    // Also check for hashes in metadata
    const metadata = fields.metadata as Record<string, unknown> | undefined;
    if (metadata) {
      addHash(metadata.file_hash);
      addHash(metadata.process_hash);
    }

    // Helper to extract domain from URL
    const extractDomainFromUrl = (url: unknown) => {
      if (!url || typeof url !== 'string') return;
      try {
        // Handle URLs with protocol
        if (url.startsWith('http://') || url.startsWith('https://')) {
          const urlObj = new URL(url);
          addDomain(urlObj.hostname);
        }
      } catch {
        // Not a valid URL, ignore
      }
    };

    // Extract domains from various fields
    addDomain(fields.dest_host);
    addDomain(fields.dest_domain);
    addDomain(fields.domain);
    addDomain(fields.query);       // DNS queries (Sysmon Event 22)
    addDomain(fields.url_domain);  // Proxy/web logs
    addDomain(fields.http_host);   // HTTP Host header

    // Extract domains from URL fields
    extractDomainFromUrl(fields.url);
    extractDomainFromUrl(fields.http_referrer);
    extractDomainFromUrl(fields.file_path);  // Sometimes contains URLs
  }

  return {
    hashes: Array.from(hashes).slice(0, 50),
    domains: Array.from(domains).slice(0, 50),
    hashOccurrences,
    domainOccurrences,
  };
}

/**
 * PrevalencePanel component displays a collapsible scatter plot
 * showing prevalence data for artifacts found in search results.
 * 
 * Requirements: 10.8 - Integrate scatter plot into Search page
 */
export function PrevalencePanel({
  results,
  hasSearched,
  onArtifactFilter,
  onSelectionFilter,
  timeWindow = '30d',
}: PrevalencePanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [scatterData, setScatterData] = useState<PrevalenceScatterData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastFetchedKey, setLastFetchedKey] = useState<string | null>(null);

  const { mutate: fetchScatterData } = usePrevalenceScatterData();

  // Extract artifacts WITH timestamps from search results
  const extractedData = useMemo(() => extractArtifactsWithTimestamps(results), [results]);

  const hasArtifacts = extractedData.hashes.length > 0 || extractedData.domains.length > 0;

  // Fetch scatter data when panel is opened and artifacts change
  const loadScatterData = useCallback(async () => {
    if (!hasArtifacts) {
      setScatterData(null);
      return;
    }

    // Check if artifacts have changed
    const currentKey = JSON.stringify({
      hashes: extractedData.hashes,
      domains: extractedData.domains,
    });
    if (currentKey === lastFetchedKey && scatterData) {
      return; // Already have data for these artifacts
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetchScatterData({
        artifacts: {
          hashes: extractedData.hashes,
          domains: extractedData.domains,
          ips: [], // IPs not extracted from events yet
        },
        window: timeWindow,
      });

      // Build lookup maps for prevalence data (host_count, is_rare, etc.)
      const hashPrevalenceMap = new Map<string, {
        hostCount: number;
        isRare: boolean;
        prevalenceScore: number;
        globalFirstSeen: Date;
        globalLastSeen: Date;
        totalOccurrences: number;
      }>();
      for (const p of response.hash_points) {
        hashPrevalenceMap.set(p.artifact.toLowerCase(), {
          hostCount: p.host_count,
          isRare: p.is_rare,
          prevalenceScore: p.prevalence_score,
          globalFirstSeen: new Date(p.first_seen),
          globalLastSeen: new Date(p.last_seen),
          totalOccurrences: p.total_occurrences,
        });
      }

      const domainPrevalenceMap = new Map<string, {
        hostCount: number;
        isRare: boolean;
        prevalenceScore: number;
        globalFirstSeen: Date;
        globalLastSeen: Date;
        totalOccurrences: number;
      }>();
      for (const p of response.domain_points) {
        domainPrevalenceMap.set(p.artifact.toLowerCase(), {
          hostCount: p.host_count,
          isRare: p.is_rare,
          prevalenceScore: p.prevalence_score,
          globalFirstSeen: new Date(p.first_seen),
          globalLastSeen: new Date(p.last_seen),
          totalOccurrences: p.total_occurrences,
        });
      }

      // Build scatter points using EVENT TIMESTAMPS from search results,
      // combined with prevalence data from the API
      const hashPoints = extractedData.hashOccurrences
        .map((occ) => {
          const prevalence = hashPrevalenceMap.get(occ.artifact);
          if (!prevalence) return null;
          return {
            artifact: occ.artifact,
            artifactType: 'hash' as const,
            hostCount: prevalence.hostCount,
            // Use event timestamp from search results, NOT global first/last seen
            firstSeen: occ.eventTimestamp,
            lastSeen: occ.eventTimestamp,
            totalOccurrences: occ.occurrenceCount,
            isRare: prevalence.isRare,
            prevalenceScore: prevalence.prevalenceScore,
          };
        })
        .filter((p): p is NonNullable<typeof p> => p !== null);

      const domainPoints = extractedData.domainOccurrences
        .map((occ) => {
          const prevalence = domainPrevalenceMap.get(occ.artifact);
          if (!prevalence) return null;
          return {
            artifact: occ.artifact,
            artifactType: 'domain' as const,
            hostCount: prevalence.hostCount,
            // Use event timestamp from search results, NOT global first/last seen
            firstSeen: occ.eventTimestamp,
            lastSeen: occ.eventTimestamp,
            totalOccurrences: occ.occurrenceCount,
            isRare: prevalence.isRare,
            prevalenceScore: prevalence.prevalenceScore,
          };
        })
        .filter((p): p is NonNullable<typeof p> => p !== null);

      const transformedData: PrevalenceScatterData = {
        hashPoints,
        domainPoints,
        rarityThreshold: response.rarity_threshold,
      };

      setScatterData(transformedData);
      setLastFetchedKey(currentKey);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load prevalence data');
    } finally {
      setIsLoading(false);
    }
  }, [extractedData, hasArtifacts, timeWindow, fetchScatterData, lastFetchedKey, scatterData]);

  // Load data when panel is opened
  useEffect(() => {
    if (isOpen && hasArtifacts) {
      loadScatterData();
    }
  }, [isOpen, hasArtifacts, loadScatterData]);

  // Handle artifact click - filter search results
  const handleArtifactClick = useCallback(
    (artifact: string, artifactType: 'hash' | 'domain') => {
      if (onArtifactFilter) {
        onArtifactFilter(artifact, artifactType);
      }
    },
    [onArtifactFilter]
  );

  // Handle selection change - filter to selected artifacts
  const handleSelectionChange = useCallback(
    (selectedArtifacts: string[]) => {
      if (onSelectionFilter) {
        onSelectionFilter(selectedArtifacts);
      }
    },
    [onSelectionFilter]
  );

  // Count rare artifacts
  const rareCount = useMemo(() => {
    if (!scatterData) return 0;
    return (
      scatterData.hashPoints.filter((p) => p.isRare).length +
      scatterData.domainPoints.filter((p) => p.isRare).length
    );
  }, [scatterData]);

  // Don't show if no search has been performed or no artifacts found
  if (!hasSearched || !hasArtifacts) {
    return null;
  }

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <Card className="bg-card border-0 rounded-2xl shadow-lg">
        <CollapsibleTrigger asChild>
          <CardHeader className="cursor-pointer hover:bg-accent/50 transition-colors rounded-t-2xl py-3 px-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {isOpen ? (
                  <ChevronDown className="w-4 h-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-muted-foreground" />
                )}
                <Activity className="w-4 h-4 text-primary" />
                <CardTitle className="text-sm font-semibold text-foreground">
                  Prevalence Analysis
                </CardTitle>
                <Badge variant="outline" className="border-border text-muted-foreground text-xs">
                  {extractedData.hashes.length + extractedData.domains.length} artifacts
                </Badge>
                {rareCount > 0 && (
                  <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30 text-xs">
                    <AlertTriangle className="w-3 h-3 mr-1" />
                    {rareCount} rare
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                {isLoading && <Loader2 className="w-3 h-3 animate-spin" />}
                <span>Click to {isOpen ? 'collapse' : 'expand'}</span>
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <CardContent className="p-5 pt-0">
            {error ? (
              <div className="flex items-center justify-center py-8 text-red-400 text-sm">
                <AlertTriangle className="w-4 h-4 mr-2" />
                {error}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={loadScatterData}
                  className="ml-4 text-muted-foreground hover:text-primary"
                >
                  <RefreshCw className="w-3 h-3" />
                  Retry
                </Button>
              </div>
            ) : isLoading && !scatterData ? (
              <div className="flex items-center justify-center py-8 text-muted-foreground text-sm">
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Loading prevalence data...
              </div>
            ) : scatterData ? (
              <PrevalenceScatterPlot
                data={scatterData}
                onArtifactClick={handleArtifactClick}
                onSelectionChange={handleSelectionChange}
                height={280}
                loading={isLoading}
              />
            ) : (
              <div className="flex items-center justify-center py-8 text-muted-foreground text-sm">
                No prevalence data available
              </div>
            )}
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
