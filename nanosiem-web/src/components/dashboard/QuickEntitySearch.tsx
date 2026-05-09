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

export function QuickEntitySearch() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    // Build a search query based on the input
    // Detect if it's an IP, email, or generic term
    const trimmed = query.trim();
    let searchQuery = '';

    if (/^[\d.]+$/.test(trimmed) || (trimmed.includes(':') && !trimmed.includes(' '))) {
      // Looks like an IP address (v4 or v6)
      searchQuery = `src_ip = "${trimmed}" OR dest_ip = "${trimmed}"`;
    } else if (trimmed.includes('@')) {
      // Looks like an email
      searchQuery = `user = "${trimmed}" OR email = "${trimmed}"`;
    } else if (trimmed.includes('.') && !trimmed.includes(' ')) {
      // Looks like a hostname/domain
      searchQuery = `src_host = "${trimmed}" OR dest_host = "${trimmed}" OR domain = "${trimmed}"`;
    } else {
      // Generic search - could be username or anything
      searchQuery = `user = "${trimmed}" OR src_host = "${trimmed}" OR dest_host = "${trimmed}"`;
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
