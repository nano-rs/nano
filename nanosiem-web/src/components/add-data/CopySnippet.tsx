// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { Check, Copy } from 'lucide-react';

import { Button } from '@/components/ui/button';

/** A titled, copyable code block (sender snippets on Ingest tokens and Add data). */
export function Snippet({ title, body, testId }: { title: string; body: string; testId: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="border border-border">
      <div className="flex items-center h-7 px-2 border-b border-border">
        <span className="font-mono text-[10.5px] uppercase tracking-wide text-muted-foreground">{title}</span>
        <span className="flex-1" />
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 gap-1 text-[11px]"
          onClick={() => {
            void navigator.clipboard
              .writeText(body)
              .then(() => setCopied(true))
              .catch(() => setCopied(false));
          }}
        >
          {copied ? <Check className="w-3 h-3" strokeWidth={1.5} /> : <Copy className="w-3 h-3" strokeWidth={1.5} />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <pre className="overflow-x-auto px-2 py-1.5 font-mono text-[11px] leading-[1.5] text-foreground" data-testid={testId}>
        {body}
      </pre>
    </div>
  );
}
