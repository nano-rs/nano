// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4586 — CodeMirror JSON editor for run-test inputs (lazy-loaded by
 * FlowRunDialog). Key autocomplete and lint both come from soar-fields.ts.
 */
import { useEffect, useRef } from 'react';
import { EditorState } from '@codemirror/state';
import { EditorView, keymap, placeholder as cmPlaceholder } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { bracketMatching, indentOnInput, syntaxHighlighting } from '@codemirror/language';
import { autocompletion, closeBrackets, closeBracketsKeymap, completionKeymap, type CompletionContext, type CompletionResult } from '@codemirror/autocomplete';
import { linter, type Diagnostic } from '@codemirror/lint';
import { json } from '@codemirror/lang-json';
import { editorTheme, syntaxTheme } from '@/components/editor/codemirror-theme';
import { checkInputsJson, jsonKeyContext, jsonKeyOptions } from './soar-fields';

function inputsCompletion(on: string) {
  return (ctx: CompletionContext): CompletionResult | null => {
    const text = ctx.state.doc.toString();
    const k = jsonKeyContext(text, ctx.pos);
    if (!k) return null;
    if (!k.quoted && !k.partial && !ctx.explicit) return null;
    const opts = jsonKeyOptions(on, k.path);
    if (!opts.length) return null;
    return {
      from: k.from,
      options: opts.map((o) => ({
        label: o.key,
        detail: o.detail,
        type: 'property',
        apply: k.quoted ? o.key : `"${o.key}": `,
      })),
      validFor: /^\w*$/,
    };
  };
}

export default function FlowInputsJsonEditor({ value, onChange, on, label }: { value: string; onChange: (v: string) => void; on: string; label: string }) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const change = useRef(onChange);
  change.current = onChange;

  useEffect(() => {
    if (!host.current) return;
    const lint = linter((v): Diagnostic[] => {
      const text = v.state.doc.toString();
      return checkInputsJson(text, on).issues.map((i) => {
        const from = Math.min(i.at, text.length);
        return { from, to: Math.min(text.length, from + 1), severity: i.severity, message: i.message };
      });
    }, { delay: 300 });
    view.current = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: value,
        extensions: [
          history(),
          bracketMatching(),
          closeBrackets(),
          indentOnInput(),
          keymap.of([...closeBracketsKeymap, ...completionKeymap, ...defaultKeymap, ...historyKeymap]),
          json(),
          lint,
          autocompletion({ override: [inputsCompletion(on)], activateOnTyping: true }),
          editorTheme,
          syntaxHighlighting(syntaxTheme),
          cmPlaceholder('{ }'),
          EditorView.contentAttributes.of({ 'aria-label': label }),
          EditorView.updateListener.of((u) => { if (u.docChanged) change.current(u.state.doc.toString()); }),
        ],
      }),
    });
    return () => { view.current?.destroy(); view.current = null; };
    // The editor owns its document; external edits are synced below.
  }, [on]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const v = view.current;
    if (!v) return;
    const cur = v.state.doc.toString();
    if (cur !== value) v.dispatch({ changes: { from: 0, to: cur.length, insert: value } });
  }, [value]);

  return <div ref={host} className="max-h-[300px] min-h-[160px] overflow-auto rounded-md border border-border-2 bg-background font-mono text-[11.5px]" />;
}
