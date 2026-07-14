import { useEffect, useRef } from 'react';
import { acceptCompletion, completionStatus, startCompletion } from '@codemirror/autocomplete';
import { history, historyKeymap } from '@codemirror/commands';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { EditorState, Prec, type Extension } from '@codemirror/state';
import { EditorView, keymap, placeholder, tooltips } from '@codemirror/view';
import { tags } from '@lezer/highlight';

import { queryLanguage } from '@/components/editor/query-language';
import { searchAutocomplete } from '@/components/editor/search-autocomplete';

/**
 * The nPL query bar.
 *
 * The language definition is the web app's — reusing it means the desktop
 * highlights the same tokens as the same things (pipe commands, UDM fields,
 * eval functions, regex literals) instead of drifting into its own dialect.
 * Only the colours are ours, and they resolve from the --syntax-* variables in
 * styles.css.
 */
const syntax = HighlightStyle.define([
  { tag: tags.comment, color: 'var(--syntax-comment)', fontStyle: 'italic' },
  { tag: tags.lineComment, color: 'var(--syntax-comment)', fontStyle: 'italic' },
  { tag: tags.string, color: 'var(--syntax-string)' },
  { tag: tags.regexp, color: 'var(--syntax-regex)', fontWeight: '500' },
  { tag: tags.number, color: 'var(--syntax-number)' },
  { tag: tags.bool, color: 'var(--syntax-keyword)', fontWeight: '600' },
  { tag: tags.atom, color: 'var(--syntax-keyword)' },
  { tag: tags.keyword, color: 'var(--syntax-keyword)', fontWeight: '600' },
  { tag: tags.operatorKeyword, color: 'var(--syntax-keyword)', fontWeight: '600' },
  { tag: tags.function(tags.variableName), color: 'var(--syntax-function)', fontWeight: '500' },
  { tag: tags.operator, color: 'var(--syntax-operator)' },
  { tag: tags.compareOperator, color: 'var(--syntax-operator)' },
  { tag: tags.arithmeticOperator, color: 'var(--syntax-operator)' },
  { tag: tags.separator, color: 'var(--syntax-pipe)', fontWeight: '700' },
  { tag: tags.punctuation, color: 'var(--syntax-operator)' },
  { tag: tags.propertyName, color: 'var(--syntax-field)', fontWeight: '500' },
  { tag: tags.special(tags.propertyName), color: 'var(--syntax-udm-field)', fontWeight: '600' },
  { tag: tags.variableName, color: 'var(--color-t1)' },
  { tag: tags.meta, color: 'var(--syntax-comment)' },
]);

const theme = EditorView.theme({
  // Fill the resizable shell, so dragging its handle actually grows the editor.
  '&': { backgroundColor: 'transparent', color: 'var(--color-t1)', height: '100%' },
  '&.cm-focused': { outline: 'none' },
  '.cm-content': {
    padding: 0,
    fontFamily: "ui-monospace, 'SF Mono', Menlo, monospace",
    fontSize: '13px',
    caretColor: 'var(--color-accent)',
  },
  '.cm-line': { padding: 0 },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--color-accent)' },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection': {
    backgroundColor: 'color-mix(in srgb, var(--color-accent) 28%, transparent)',
  },
  '.cm-placeholder': { color: 'var(--color-t4)' },
  // overflowX hidden: wrapping is on, so there is nothing to scroll sideways to.
  '.cm-scroller': { fontFamily: 'inherit', lineHeight: '1.5', overflowX: 'hidden' },
  // The completion popup is styled globally in styles.css, not here: it renders
  // into document.body (to escape clipping), where this theme's class scoping
  // would not reach it.
});

interface Props {
  value: string;
  onChange: (value: string) => void;
  onRun: () => void;
}

export function QueryBar({ value, onChange, onRun }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  // The editor is created once; a stale closure here would run last render's query.
  const runRef = useRef(onRun);
  runRef.current = onRun;
  const changeRef = useRef(onChange);
  changeRef.current = onChange;

  useEffect(() => {
    const element = host.current;
    if (!element) return;

    const extensions: Extension[] = [
      history(),
      // Prec.highest so these beat the completion keymap, which otherwise binds
      // Enter to "accept suggestion" — Enter must always run the query.
      Prec.highest(
        keymap.of([
          {
            key: 'Tab',
            run: (view) => {
              // Tab accepts the highlighted suggestion; with none open it asks
              // for one, so Tab on an empty bar reveals what's available.
              if (completionStatus(view.state) === 'active') return acceptCompletion(view);
              return startCompletion(view);
            },
          },
          {
            // A query bar is one line: Enter runs it rather than inserting a newline.
            key: 'Enter',
            run: () => {
              runRef.current();
              return true;
            },
          },
        ])
      ),
      keymap.of(historyKeymap),
      searchAutocomplete(),
      // Paste of a multi-line query collapses to one line rather than growing
      // the bar into a text area.
      EditorState.transactionFilter.of((tr) => {
        if (!tr.docChanged) return tr;
        const text = tr.newDoc.toString();
        if (!text.includes('\n')) return tr;
        return {
          changes: { from: 0, to: tr.startState.doc.length, insert: text.replace(/\n/g, ' ') },
        };
      }),
      // The query bar clips its own overflow (rounded corners), and the window
      // root clips again — so a tooltip parented to the editor is invisible.
      // Render it into the body, positioned fixed, where nothing can clip it.
      tooltips({ parent: document.body, position: 'fixed' }),
      queryLanguage,
      syntaxHighlighting(syntax),
      // A long pipeline should wrap into view, not run off to the right where
      // the analyst has to scroll horizontally to read their own query.
      EditorView.lineWrapping,
      placeholder('source_type=aws_cloudtrail | stats count by user'),
      theme,
      EditorView.updateListener.of((update) => {
        if (update.docChanged) changeRef.current(update.state.doc.toString());
      }),
    ];

    const editor = new EditorView({
      state: EditorState.create({ doc: value, extensions }),
      parent: element,
    });
    view.current = editor;
    editor.focus();

    return () => {
      editor.destroy();
      view.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Reflect programmatic changes (query history, "use this query") without
  // clobbering what the user is typing.
  useEffect(() => {
    const editor = view.current;
    if (!editor) return;
    const current = editor.state.doc.toString();
    if (current === value) return;
    editor.dispatch({ changes: { from: 0, to: current.length, insert: value } });
  }, [value]);

  return (
    <div
      ref={host}
      onClick={() => view.current?.focus()}
      // `resize-y` gives the native drag handle (the web app's search input does
      // the same). It grows with the query up to max-h, then scrolls — so a long
      // pipeline is readable without the bar swallowing the results.
      className="max-h-[240px] min-h-[42px] min-w-0 flex-1 cursor-text resize-y overflow-auto rounded-[9px] border border-line-strong bg-input px-3.5 py-2.5 focus-within:border-accent"
    />
  );
}
