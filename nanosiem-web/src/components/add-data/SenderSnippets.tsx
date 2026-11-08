// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import type { IngestEndpoint } from '@/lib/api/types';
import { renderSenderTemplate, senderValuesFromEndpoint, templatesForProtocol } from '@/lib/sender-config';
import { cn } from '@/lib/utils';
import { CopyButton } from './CopyButton';

/**
 * Copy-paste sender configurations for one ingest token, filled in the
 * browser (main's NAN-2592 component; NAN-4922 uses the static catalog in
 * `lib/sender-config`). `token` is the plaintext token while it is on screen,
 * or omitted to render `<token>`. The token decides the source, so no
 * snippet declares a source type.
 */
export function SenderSnippets({
  linear = false,
  endpoint,
  protocol,
  label,
  token,
}: {
  linear?: boolean;
  endpoint: IngestEndpoint;
  protocol: string;
  label: string;
  token?: string;
}) {
  const templates = useMemo(() => templatesForProtocol(protocol), [protocol]);
  const [selected, setSelected] = useState<string | null>(null);
  const active = templates.find((t) => t.id === selected) ?? templates[0];
  const body = useMemo(
    () => (active ? renderSenderTemplate(active, senderValuesFromEndpoint(endpoint, { token: token ?? '<token>', label })) : ''),
    [active, endpoint, label, token],
  );
  if (!active) {
    return <div className="text-[11px] text-muted-foreground">No sender templates for this protocol.</div>;
  }
  return (
    <div className="rounded-md border border-border bg-card" data-testid="sender-snippets">
      {(!linear || templates.length > 1) && (
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
      )}
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
