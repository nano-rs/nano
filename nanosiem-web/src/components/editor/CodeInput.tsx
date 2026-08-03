// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Lightweight CodeMirror input for structured text (JSON, shell, plain)
 * Used for API response samples, curl examples, documentation snippets
 */
import { useRef, useEffect } from 'react';
import { EditorState, Extension, Compartment } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, placeholder as cmPlaceholder } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { bracketMatching, foldGutter, indentOnInput } from '@codemirror/language';
import { closeBrackets, closeBracketsKeymap } from '@codemirror/autocomplete';
import { javascript } from '@codemirror/lang-javascript';
import { json } from '@codemirror/lang-json';
import { syntaxHighlighting } from '@codemirror/language';
import { editorTheme, syntaxTheme } from './codemirror-theme';

export interface CodeInputProps {
  value: string;
  onChange: (value: string) => void;
  language?: 'json' | 'shell' | 'plain';
  placeholder?: string;
  maxLength?: number;
  height?: string;
  minHeight?: string;
  className?: string;
}

export function CodeInput({
  value,
  onChange,
  language = 'plain',
  placeholder,
  maxLength,
  height,
  minHeight = '80px',
  className = '',
}: CodeInputProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  const isInternalChange = useRef(false);
  const readOnlyCompartment = useRef(new Compartment());

  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => {
    if (!containerRef.current) return;

    const extensions: Extension[] = [
      lineNumbers(),
      history(),
      bracketMatching(),
      closeBrackets(),
      indentOnInput(),
      foldGutter(),
      keymap.of([
        ...closeBracketsKeymap,
        ...defaultKeymap,
        ...historyKeymap,
      ]),
      editorTheme,
      syntaxHighlighting(syntaxTheme),
      EditorView.updateListener.of((update) => {
        if (update.docChanged && !isInternalChange.current) {
          let text = update.state.doc.toString();
          if (maxLength && text.length > maxLength) {
            text = text.slice(0, maxLength);
          }
          onChangeRef.current(text);
        }
      }),
      readOnlyCompartment.current.of(EditorState.readOnly.of(false)),
    ];

    // Language support
    if (language === 'json') {
      extensions.push(json());
    } else if (language === 'shell') {
      // Use JavaScript highlighting as a reasonable approximation for curl commands
      extensions.push(javascript());
    }

    // Placeholder
    if (placeholder) {
      extensions.push(cmPlaceholder(placeholder));
    }

    const state = EditorState.create({
      doc: value,
      extensions,
    });

    const view = new EditorView({
      state,
      parent: containerRef.current,
    });

    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Sync external value changes
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;

    const currentValue = view.state.doc.toString();
    if (currentValue !== value) {
      isInternalChange.current = true;
      view.dispatch({
        changes: { from: 0, to: currentValue.length, insert: value },
      });
      isInternalChange.current = false;
    }
  }, [value]);

  return (
    <div
      ref={containerRef}
      className={`cm-editor-container w-full overflow-hidden rounded-lg border border-border bg-background ${className}`}
      style={{ height, minHeight: height ?? minHeight }}
    />
  );
}

export default CodeInput;
