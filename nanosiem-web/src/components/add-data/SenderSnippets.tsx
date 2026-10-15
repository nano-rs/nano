// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';

import type { SenderTemplateCatalog, TenantIngestEndpoint } from '@/lib/api/types';
import { declaredSources, type SourceAliases } from '@/lib/collector-sources';
import { renderSenderTemplate, senderValuesFromEndpoint, templatesForCredential } from '@/lib/sender-config';
import { cn } from '@/lib/utils';
import { CopyButton } from './CopyButton';

/**
 * Copy-paste sender configurations for one credential, filled in the browser
 * from the server templates (NAN-2592). `token` is the plaintext token when it
 * is on screen, or omitted to render the `{{token}}` marker as `<token>`.
 * A collector credential (NAN-2597) gets the collector templates, which
 * declare the source per event; `sources` fills their allowlist.
 */
export function SenderSnippets({
  catalog,
  endpoint,
  protocol,
  label,
  token,
  kind = 'source',
  sources,
}: {
  catalog: SenderTemplateCatalog | undefined;
  endpoint: TenantIngestEndpoint;
  protocol: string;
  label: string;
  token?: string;
  kind?: 'source' | 'collector';
  /** Collector: the allowlist and its aliases. */
  sources?: { slugs: string[]; aliases: SourceAliases };
}) {
  const templates = useMemo(() => templatesForCredential(catalog, protocol, kind), [catalog, protocol, kind]);
  const [selected, setSelected] = useState<string | null>(null);
  const active = templates.find((t) => t.id === selected) ?? templates[0];
  const declared = sources ? declaredSources(sources.slugs, sources.aliases) : '';
  const example = sources?.slugs[0] ?? '';
  const body = useMemo(
    () =>
      active
        ? renderSenderTemplate(
            active,
            senderValuesFromEndpoint(endpoint, { token: token ?? '<token>', label, sources: declared, exampleSource: example }),
          )
        : '',
    [active, endpoint, label, token, declared, example],
  );

  if (!catalog) {
    return <div className="text-[11px] text-muted-foreground">Loading sender templates…</div>;
  }
  if (!active) {
    return <div className="text-[11px] text-muted-foreground">No sender templates for this protocol.</div>;
  }
  return (
    <div className="rounded-md border border-border bg-card" data-testid="sender-snippets">
      <div className="flex items-center gap-0.5 px-1.5 h-8 border-b border-border overflow-x-auto" role="tablist" aria-label="Sender">
        {templates.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={t.id === active.id}
            onClick={() => setSelected(t.id)}
            className={cn(
              'h-6 px-2 rounded text-[11.5px] whitespace-nowrap',
              t.id === active.id ? 'bg-accent text-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-accent/50',
            )}
          >
            {t.sender_name}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2 px-3 h-7 border-b border-border/60">
        <span className="text-[11.5px] text-foreground">{active.title}</span>
        <span className="font-mono text-[10.5px] text-muted-foreground/70">{active.format}</span>
        <span className="flex-1" />
        <CopyButton text={body} aria-label={`Copy ${active.sender_name} config`} />
      </div>
      <div className="px-3 py-2">
        <div className="text-[11px] text-muted-foreground mb-1.5">{active.description}</div>
        <pre
          className="max-h-[260px] overflow-auto scrollbar-thin font-mono text-[11px] leading-[1.55] text-foreground/90 bg-background border border-border rounded p-2 whitespace-pre"
          data-testid="sender-snippet-body"
        >
          {body}
        </pre>
      </div>
    </div>
  );
}
