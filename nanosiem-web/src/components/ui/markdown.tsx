// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useMemo, type ComponentPropsWithoutRef, type ReactNode } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { highlightCode, langLabel, isQueryLang } from '@/lib/syntax-highlight-md';
import {
  useMarkdownTransform,
  type MarkdownTransform,
} from '@/components/ui/markdown-transform-context';

interface MarkdownProps {
  children: string;
  className?: string;
  /** When provided, nPL/search code blocks show a "Run" button */
  onRunQuery?: (query: string) => void;
  /**
   * Generic children-transform hook. When set, runs over the children of
   * each text-bearing element before render. Case-investigate uses this to
   * wrap entity mentions in chips; the primitive itself stays domain-free.
   * If omitted, the nearest `MarkdownTransformProvider` in context is used.
   */
  transformChildren?: MarkdownTransform | null;
}

/**
 * Markdown renderer that outputs React elements instead of raw HTML.
 * Replaces the old renderMarkdown() + dangerouslySetInnerHTML pattern.
 */
export function Markdown({ children, className, onRunQuery, transformChildren }: MarkdownProps) {
  const codeComponent = useCallback(
    (props: ComponentPropsWithoutRef<'code'>) => <CodeBlock {...props} onRunQuery={onRunQuery} />,
    [onRunQuery],
  );

  // Explicit prop wins, otherwise pick up the transform from context.
  // Markdown rendered outside a provider sees null and renders unchanged.
  const contextTransform = useMarkdownTransform();
  const activeTransform = transformChildren ?? contextTransform;

  const wrap = useMemo(() => {
    if (!activeTransform) return (c: ReactNode) => c;
    return activeTransform;
  }, [activeTransform]);

  return (
    <div className={className}>
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <h2 className="text-base font-bold text-foreground mt-4 mb-1.5">{wrap(children)}</h2>,
        h2: ({ children }) => <><hr className="my-2 border-border/30" /><h3 className="text-sm font-bold text-foreground mb-1">{wrap(children)}</h3></>,
        h3: ({ children }) => <h4 className="text-sm font-semibold text-foreground mt-2.5 mb-1">{wrap(children)}</h4>,
        h4: ({ children }) => <h4 className="text-xs font-semibold text-foreground mt-2 mb-0.5">{wrap(children)}</h4>,
        p: ({ children }) => <p className="my-1 leading-relaxed">{wrap(children)}</p>,
        strong: ({ children }) => <strong className="font-semibold text-foreground">{wrap(children)}</strong>,
        a: ({ href, children }) => {
          // Only allow relative URLs and https. Skip entity tokenization
          // inside the anchor body — EntityChip renders its own <a>, and
          // nesting anchors is an HTML validity error (React warns in dev).
          if (href && (href.startsWith('/') || href.startsWith('https://'))) {
            return <a href={href} className="text-primary hover:underline">{children}</a>;
          }
          return <span>{wrap(children)}</span>;
        },
        ul: ({ children }) => <ul className="my-1.5 space-y-0.5">{children}</ul>,
        ol: ({ children }) => <ol className="my-1.5 space-y-0.5">{children}</ol>,
        li: ({ children }) => (
          <li className="flex gap-1.5 list-none text-foreground text-xs leading-normal">
            <span className="shrink-0">•</span>
            <span>{wrap(children)}</span>
          </li>
        ),
        hr: () => <hr className="my-2 border-border" />,
        code: codeComponent,
        pre: ({ children }) => <>{children}</>,
        table: ({ children }) => (
          <div className="overflow-x-auto my-1">
            <table className="text-xs border-collapse w-full">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="border-b border-border">{children}</thead>,
        th: ({ children }) => <th className="text-left px-2 py-1 text-xs font-semibold text-muted-foreground">{children}</th>,
        td: ({ children }) => <td className="px-2 py-1 text-xs border-t border-border/50">{wrap(children)}</td>,
      }}
    >
      {children}
    </ReactMarkdown>
    </div>
  );
}

/** Code block / inline code component */
function CodeBlock({
  children,
  className,
  onRunQuery,
  ...props
}: ComponentPropsWithoutRef<'code'> & { onRunQuery?: (query: string) => void }) {
  const text = extractText(children);
  const langMatch = className?.match(/language-(\w+)/);
  const lang = langMatch?.[1] ?? '';
  const isBlock = Boolean(lang) || text.includes('\n');
  const showRun = onRunQuery && isQueryLang(lang);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text);
  }, [text]);

  const handleRun = useCallback(() => {
    onRunQuery?.(text);
  }, [onRunQuery, text]);

  if (!isBlock) {
    return (
      <code className="bg-muted/50 px-1.5 py-0.5 rounded border border-border/30 text-purple-700 dark:text-purple-300 font-mono text-xs" {...props}>
        {children}
      </code>
    );
  }

  const highlighted = highlightCode(text, lang);

  return (
    <pre className="bg-muted/50 rounded-lg mt-1 mb-1 overflow-x-auto border border-border/50">
      {lang && (
        <div className="flex items-center justify-between px-3 py-1 border-b border-border/50">
          <span className="text-[10px] font-medium text-muted-foreground tracking-wider">
            {langLabel(lang)}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="text-[10px] text-muted-foreground hover:text-foreground transition-colors"
            >
              Copy
            </button>
            {showRun && (
              <button
                onClick={handleRun}
                className="text-[10px] text-primary hover:text-primary/80 font-medium transition-colors"
              >
                Run ▶
              </button>
            )}
          </div>
        </div>
      )}
      <code
        className="block px-3 py-2 text-xs font-mono leading-relaxed"
        dangerouslySetInnerHTML={{ __html: highlighted }}
      />
    </pre>
  );
}

/** Extract plain text from React children (handles nested elements) */
function extractText(children: React.ReactNode): string {
  if (typeof children === 'string') return children;
  if (typeof children === 'number') return String(children);
  if (Array.isArray(children)) return children.map(extractText).join('');
  if (children && typeof children === 'object' && 'props' in children) {
    return extractText((children as { props: { children?: React.ReactNode } }).props.children);
  }
  return '';
}
