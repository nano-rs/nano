// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Quick Entity Search Component
 *
 * Simple search bar for looking up IPs, hostnames, emails, or users.
 * Navigates to the search page with a pre-filled query.
 */

import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ArrowRight } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { useSchemaEntityMap } from '@/hooks/useSchemaEntityMap';
import type { SchemaFieldsResponse } from '@/lib/api/types';

// UDM defaults for each detection bucket. Under UDM (or when the schema response
// is unavailable) these are used verbatim so the generated nPL is byte-identical
// to the pre-OCSF behavior (NAN-1241).
const UDM_IP_FIELDS = ['src_ip', 'dest_ip'] as const;
const UDM_EMAIL_FIELDS = ['user', 'email'] as const;
const UDM_HOSTNAME_FIELDS = ['src_host', 'dest_host', 'domain'] as const;
const UDM_GENERIC_FIELDS = ['user', 'src_host', 'dest_host'] as const;

/** Collect the active schema's column names for the given backend entity types,
 *  in manifest order, deduped. Empty when the schema is UDM / unavailable. */
function schemaFieldsForEntities(
  schemaFields: SchemaFieldsResponse | undefined,
  entityTypes: readonly string[],
  extraCategories: readonly string[] = [],
): string[] {
  if (!schemaFields || schemaFields.schema === 'udm') return [];
  const wantEntity = new Set(entityTypes);
  const wantCategory = new Set(extraCategories);
  const out: string[] = [];
  for (const f of schemaFields.fields) {
    const hit =
      (f.entity_type != null && wantEntity.has(f.entity_type)) ||
      wantCategory.has(f.category);
    if (hit && !out.includes(f.name)) out.push(f.name);
  }
  return out;
}

/** Build an OR-clause over `fields` for `value`; UDM `fallback` when the schema
 *  contributes nothing (keeps UDM output byte-identical). */
function orClause(fields: string[], fallback: readonly string[], value: string): string {
  const cols = fields.length > 0 ? fields : fallback;
  return cols.map((c) => `${c} = "${value}"`).join(' OR ');
}

export function QuickEntitySearch() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const { schemaFields } = useSchemaEntityMap();

  // Schema-correct field sets per detection bucket. Empty arrays under UDM →
  // orClause() falls back to the UDM_* defaults (byte-identical). Under OCSF
  // these resolve to the promoted columns (`src_endpoint.ip`, `url.hostname`,
  // `email.from`, …) so the generated nPL hits real columns instead of silently
  // empty UDM names.
  const ipFields = useMemo(() => schemaFieldsForEntities(schemaFields, ['ip']), [schemaFields]);
  const emailFields = useMemo(
    () => schemaFieldsForEntities(schemaFields, ['user'], ['Email']),
    [schemaFields],
  );
  const hostnameFields = useMemo(
    () => schemaFieldsForEntities(schemaFields, ['host', 'domain']),
    [schemaFields],
  );
  const genericFields = useMemo(
    () => schemaFieldsForEntities(schemaFields, ['user', 'host']),
    [schemaFields],
  );

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    // Build a search query based on the input
    // Detect if it's an IP, email, or generic term
    const trimmed = query.trim();
    let searchQuery = '';

    if (/^[\d.]+$/.test(trimmed) || (trimmed.includes(':') && !trimmed.includes(' '))) {
      // Looks like an IP address (v4 or v6)
      searchQuery = orClause(ipFields, UDM_IP_FIELDS, trimmed);
    } else if (trimmed.includes('@')) {
      // Looks like an email
      searchQuery = orClause(emailFields, UDM_EMAIL_FIELDS, trimmed);
    } else if (trimmed.includes('.') && !trimmed.includes(' ')) {
      // Looks like a hostname/domain
      searchQuery = orClause(hostnameFields, UDM_HOSTNAME_FIELDS, trimmed);
    } else {
      // Generic search - could be username or anything
      searchQuery = orClause(genericFields, UDM_GENERIC_FIELDS, trimmed);
    }

    // Navigate to search with the query
    navigate(`/search?q=${encodeURIComponent(searchQuery)}`);
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
        disabled={!query.trim()}
        className="bg-primary hover:bg-primary/90 rounded-xl h-11 px-4"
      >
        <ArrowRight className="w-4 h-4" />
      </Button>
    </form>
  );
}
