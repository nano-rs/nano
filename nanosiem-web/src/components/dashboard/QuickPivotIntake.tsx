// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-core dashboard intake. Replaces the AI-driven HeroIntake when melod
// isn't available. Takes a raw IOC (IP, domain, hash, user, URL) or free-text
// search term, classifies it, builds the appropriate nPL query, and lands the
// user on /search with run=true so the result executes immediately.
//
// The point isn't to be clever — analysts already know how to write
// `src_ip="..." OR dest_ip="..."`. The point is "paste-and-pivot" speed for
// the common triage move where someone hands you an IOC and you want it
// queried across both src/dest fields without typing it out.

import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search as SearchIcon, ArrowRight } from 'lucide-react';
import { buildFieldFilter, type SchemaProfileId, type SemanticField } from '@/lib/schema-fields';
import { useSchemaFieldMap } from '@/hooks/useSchemaFieldMap';
import { isInternalName } from '@/lib/internal-domains';
import { useInternalDomains } from '@/hooks/use-internal-domains';

export type IocKind = 'ipv4' | 'ipv6' | 'sha256' | 'sha1' | 'md5' | 'email' | 'url' | 'domain' | 'host' | 'text';

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const IPV6 = /^(?=.*:)[0-9a-fA-F:]+$/;
const SHA256 = /^[a-fA-F0-9]{64}$/;
const SHA1 = /^[a-fA-F0-9]{40}$/;
const MD5 = /^[a-fA-F0-9]{32}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const URL_RE = /^https?:\/\//i;
const DOMAIN = /^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{2,63})+$/;

/**
 * `internalSuffixes` (NAN-3226): dotted names under an internal suffix are
 * internal hosts, not internet domains. The query is the same hostname pivot;
 * only the label changes.
 */
export function classify(raw: string, internalSuffixes: readonly string[] = []): IocKind {
  const v = raw.trim();
  if (!v) return 'text';
  if (IPV4.test(v)) return 'ipv4';
  if (IPV6.test(v) && v.includes(':')) return 'ipv6';
  if (SHA256.test(v)) return 'sha256';
  if (SHA1.test(v)) return 'sha1';
  if (MD5.test(v)) return 'md5';
  if (URL_RE.test(v)) return 'url';
  if (EMAIL.test(v)) return 'email';
  if (DOMAIN.test(v)) return isInternalName(v, internalSuffixes) ? 'host' : 'domain';
  return 'text';
}

const KIND_LABEL: Record<IocKind, string> = {
  ipv4: 'IPv4 address',
  ipv6: 'IPv6 address',
  sha256: 'SHA-256 hash',
  sha1: 'SHA-1 hash',
  md5: 'MD5 hash',
  email: 'email / user',
  url: 'URL',
  domain: 'domain',
  host: 'internal host',
  text: 'free text',
};

/** Build the pivot nPL for a classified IOC under the active schema profile
 *  (NAN-4903: column names come from the profile-aware field map). */
export function buildQuery(kind: IocKind, raw: string, profile: SchemaProfileId): string {
  const v = raw.trim();
  const either = (a: SemanticField, b: SemanticField) =>
    `${buildFieldFilter(profile, a, v)} OR ${buildFieldFilter(profile, b, v)}`;
  switch (kind) {
    case 'ipv4':
    case 'ipv6':
      return either('srcIp', 'destIp');
    case 'sha256':
    case 'sha1':
    case 'md5':
      return either('processHash', 'fileHash');
    case 'email':
      return buildFieldFilter(profile, 'user', v);
    case 'url':
      return buildFieldFilter(profile, 'url', v);
    case 'domain':
    case 'host':
      return either('destHost', 'srcHost');
    case 'text':
      return v;
  }
}

export function QuickPivotIntake() {
  const navigate = useNavigate();
  const [input, setInput] = useState('');
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const t = setTimeout(() => inputRef.current?.focus(), 100);
    return () => clearTimeout(t);
  }, []);

  // NAN-4903: no query is built until the tenant's schema profile is known.
  const { profile, ready, guard, unresolvedReason } = useSchemaFieldMap();
  const internalSuffixes = useInternalDomains();
  const kind = useMemo(() => classify(input, internalSuffixes), [input, internalSuffixes]);
  const trimmed = input.trim();

  const run = guard(() => {
    const q = buildQuery(kind, trimmed, profile);
    navigate(`/search#q=${encodeURIComponent(q)}&run=true`);
  });
  const submit = () => {
    if (!trimmed) return;
    run();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  };

  return (
    <div className="flex flex-col items-center gap-2 py-4">
      <div className="text-[12.5px] text-muted-foreground">
        Pivot from an IOC into search.
      </div>
      <div className="w-full max-w-[640px]">
        <div className="rounded-md border border-border bg-card overflow-hidden">
          <div className="px-3 py-1.5 border-b border-border flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-[0.12em] font-medium text-foreground">Quick pivot</span>
            <span className="text-muted-foreground/60">::</span>
            <span className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">IP, domain, hash, user, URL</span>
            <span className="ml-auto text-[10px] font-mono text-muted-foreground/60">↵</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-2.5">
            <div className="w-6 h-6 rounded-md bg-muted flex items-center justify-center shrink-0">
              <SearchIcon className="h-3 w-3 text-muted-foreground" strokeWidth={1.75} />
            </div>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder="Paste an IP, domain, hash, user, or URL — or type a search term"
              rows={1}
              className="flex-1 bg-transparent text-foreground text-[13.5px] placeholder:text-muted-foreground/60 resize-none outline-none min-h-[20px] max-h-[120px] leading-5"
              style={{ fieldSizing: 'content' } as React.CSSProperties}
            />
            <button
              onClick={submit}
              disabled={!trimmed || !ready}
              title={unresolvedReason ?? undefined}
              aria-label="Run search"
              className="w-7 h-7 rounded-md bg-muted hover:bg-muted/70 flex items-center justify-center transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ArrowRight className="h-3.5 w-3.5 text-foreground" strokeWidth={1.75} />
            </button>
          </div>
          {trimmed && (
            <div className="px-3 py-1.5 border-t border-border bg-muted/30 flex items-center gap-2 text-[10.5px] font-mono">
              <span className="text-muted-foreground uppercase tracking-[0.08em]">{KIND_LABEL[kind]}</span>
              <span className="text-muted-foreground/60">→</span>
              <span className="text-foreground/80 truncate">{buildQuery(kind, trimmed, profile)}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
