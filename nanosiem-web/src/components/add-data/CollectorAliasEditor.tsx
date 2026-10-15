// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { X } from 'lucide-react';

import { aliasProblem, aliasesBySlug, type SourceAliases } from '@/lib/collector-sources';
import { cn } from '@/lib/utils';

/**
 * The collector allowlist with alias chips (NAN-2597). Each row is one
 * allowlisted slug; its chips are the extra names an event may declare for it
 * (a vendor sourcetype such as `pan:traffic`). Vendor conventions are
 * prefilled by the caller (`syncAliases`) and stay removable.
 */
export function CollectorAliasEditor({
  slugs,
  aliases,
  onChange,
  disabled,
}: {
  slugs: string[];
  aliases: SourceAliases;
  onChange: (next: SourceAliases) => void;
  disabled?: boolean;
}) {
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [errors, setErrors] = useState<Record<string, string | null>>({});

  const add = (slug: string) => {
    const name = (drafts[slug] ?? '').trim();
    if (!name) return;
    const problem = aliasProblem(name, slug, aliases, slugs);
    if (problem) {
      setErrors((e) => ({ ...e, [slug]: problem }));
      return;
    }
    onChange({ ...aliases, [name]: slug });
    setDrafts((d) => ({ ...d, [slug]: '' }));
    setErrors((e) => ({ ...e, [slug]: null }));
  };

  const remove = (name: string) => {
    const next = { ...aliases };
    delete next[name];
    onChange(next);
  };

  return (
    <div className="rounded-md border border-border overflow-hidden" data-testid="collector-alias-editor">
      <div className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,2fr)] gap-2 px-2.5 h-6 items-center border-b border-border bg-card/60 text-[9.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground">
        <span>Source</span>
        <span>Also accepted as (aliases)</span>
      </div>
      <div className="max-h-[240px] overflow-auto scrollbar-thin">
        {aliasesBySlug(aliases, slugs).map(({ slug, aliases: names }) => (
          <div
            key={slug}
            className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,2fr)] gap-2 px-2.5 py-1 min-h-7 items-center border-b border-border/60 last:border-b-0"
            data-testid={`collector-source-${slug}`}
          >
            <span className="font-mono text-[11.5px] text-foreground truncate">{slug}</span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-1">
                {names.map((name) => (
                  <span
                    key={name}
                    className="inline-flex items-center gap-0.5 h-5 pl-1.5 pr-0.5 rounded-sm border border-border font-mono text-[10.5px] text-foreground/80"
                  >
                    {name}
                    <button
                      type="button"
                      disabled={disabled}
                      aria-label={`Remove alias ${name}`}
                      onClick={() => remove(name)}
                      className="w-4 h-4 inline-flex items-center justify-center rounded-sm text-muted-foreground hover:text-foreground"
                    >
                      <X className="w-3 h-3" strokeWidth={1.5} />
                    </button>
                  </span>
                ))}
                <input
                  value={drafts[slug] ?? ''}
                  disabled={disabled}
                  aria-label={`Add alias for ${slug}`}
                  placeholder="add sourcetype…"
                  maxLength={128}
                  onChange={(e) => {
                    const value = e.target.value;
                    setDrafts((d) => ({ ...d, [slug]: value }));
                    if (errors[slug]) setErrors((er) => ({ ...er, [slug]: null }));
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ',') {
                      e.preventDefault();
                      add(slug);
                    }
                  }}
                  onBlur={() => add(slug)}
                  className={cn(
                    'h-5 w-[140px] min-w-0 rounded-sm border bg-background px-1.5 font-mono text-[10.5px] text-foreground focus:outline-none',
                    errors[slug] ? 'border-red-500/60' : 'border-input focus:border-primary',
                  )}
                />
              </div>
              {errors[slug] && (
                <div className="text-[10.5px] text-red-500 mt-0.5" role="alert">
                  {errors[slug]}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
