// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Quick Entity Search Component
 *
 * Simple search bar for looking up IPs, hostnames, emails, or users.
 * Navigates to the search page with a pre-filled query.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ArrowRight } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { useSchemaFieldMap } from '@/hooks/useSchemaFieldMap';
import { buildMultiFieldFilter, type SchemaProfileId, type SemanticField } from '@/lib/schema-fields';

// Concepts searched for each detection bucket (NAN-4903: resolved through the
// profile-aware field map, so OCSF installs hit `src_endpoint.ip`, …).
const IP_KEYS: readonly SemanticField[] = ['srcIp', 'destIp'];
const EMAIL_KEYS: readonly SemanticField[] = ['user', 'email'];
const HOSTNAME_KEYS: readonly SemanticField[] = ['srcHost', 'destHost', 'domain'];
const GENERIC_KEYS: readonly SemanticField[] = ['user', 'srcHost', 'destHost'];


/** Classify the input (IP / email / hostname / generic) and build the nPL. */
export function buildEntitySearchQuery(profile: SchemaProfileId, input: string): string {
  const trimmed = input.trim();
  if (/^[\d.]+$/.test(trimmed) || (trimmed.includes(':') && !trimmed.includes(' '))) {
    return buildMultiFieldFilter(profile, IP_KEYS, trimmed);
  }
  if (trimmed.includes('@')) return buildMultiFieldFilter(profile, EMAIL_KEYS, trimmed);
  if (trimmed.includes('.') && !trimmed.includes(' ')) return buildMultiFieldFilter(profile, HOSTNAME_KEYS, trimmed);
  return buildMultiFieldFilter(profile, GENERIC_KEYS, trimmed);
}

export function QuickEntitySearch() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  // NAN-4903: no query is built until the tenant's schema profile is known.
  const { profile, ready, guard, unresolvedReason } = useSchemaFieldMap();

  const runSearch = guard(() => {
    const searchQuery = buildEntitySearchQuery(profile, query);
    navigate(`/search#q=${encodeURIComponent(searchQuery)}`);
  });
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    runSearch();
  };

  return (
    <form onSubmit={handleSearch} className="flex gap-2">
      <div className="relative flex-1">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          type="text"
          placeholder="Search IP, hostname, email, or user..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="pl-10 border-border rounded-xl h-11 text-foreground placeholder:text-muted-foreground"
        />
      </div>
      <Button
        type="submit"
        disabled={!query.trim() || !ready}
        title={unresolvedReason ?? undefined}
        className="bg-primary hover:bg-primary/90 rounded-xl h-11 px-4"
      >
        <ArrowRight className="w-4 h-4" />
      </Button>
    </form>
  );
}
