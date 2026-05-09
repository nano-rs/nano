// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * VRL Editor - CodeMirror 6 based editor for Vector Remap Language
 * Simple, reliable editor without the buggy transparent textarea overlay
 */
import React, { useRef, useEffect, useImperativeHandle, useCallback } from 'react';
import { EditorState, Extension, Compartment } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
import { bracketMatching, foldGutter, indentOnInput } from '@codemirror/language';
import { closeBrackets, closeBracketsKeymap } from '@codemirror/autocomplete';
import { highlightSelectionMatches, searchKeymap, search } from '@codemirror/search';
import { rust } from '@codemirror/lang-rust';

import { editorTheme, syntaxTheme } from './codemirror-theme';
import { syntaxHighlighting } from '@codemirror/language';

export interface VrlEditorRef {
  focus: () => void;
  getValue: () => string;
  setValue: (value: string) => void;
}

export interface VrlEditorProps {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  className?: string;
  placeholder?: string;
}

/**
 * VRL Editor Component using CodeMirror 6
 * Uses Rust syntax highlighting as VRL is Rust-like
 */
export function VrlEditor({
  value,
  onChange,
  readOnly = false,
  className = '',
  placeholder,
  ref,
}: VrlEditorProps & { ref?: React.Ref<VrlEditorRef> }) {
    const containerRef = useRef<HTMLDivElement>(null);
    const viewRef = useRef<EditorView | null>(null);
    const onChangeRef = useRef(onChange);
    const isInternalChange = useRef(false);
    const readOnlyCompartment = useRef(new Compartment());

    // Keep onChange ref updated
    useEffect(() => {
      onChangeRef.current = onChange;
    }, [onChange]);

    // Create update listener
    const createUpdateListener = useCallback(() => {
      return EditorView.updateListener.of((update) => {
        if (update.docChanged && !isInternalChange.current) {
          const newValue = update.state.doc.toString();
          onChangeRef.current(newValue);
        }
      });
    }, []);

    // Build extensions
    const getExtensions = useCallback((): Extension[] => {
      return [
        lineNumbers(),
        highlightActiveLine(),
        highlightActiveLineGutter(),
        history(),
        bracketMatching(),
        closeBrackets(),
        indentOnInput(),
        foldGutter(),
        highlightSelectionMatches(),
        search({ top: true }),

        // Keymaps
        keymap.of([
          indentWithTab,
          ...closeBracketsKeymap,
          ...defaultKeymap,
          ...historyKeymap,
          ...searchKeymap,
        ]),

        // Use Rust syntax highlighting (VRL is Rust-like)
        rust(),

        // Theme (editor + syntax)
        editorTheme,
        syntaxHighlighting(syntaxTheme),

        // Update listener
        createUpdateListener(),

        // Placeholder
        placeholder ? EditorView.contentAttributes.of({ 'aria-placeholder': placeholder }) : [],

        // Read-only mode
        readOnlyCompartment.current.of(EditorState.readOnly.of(readOnly)),
      ];
    }, [readOnly, placeholder, createUpdateListener]);

    // Initialize editor
    useEffect(() => {
      if (!containerRef.current) return;

      const state = EditorState.create({
        doc: value,
        extensions: getExtensions(),
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
    }, []); // Only run once on mount

    // Handle external value changes
    useEffect(() => {
      const view = viewRef.current;
      if (!view) return;

      const currentValue = view.state.doc.toString();
      if (currentValue !== value) {
        isInternalChange.current = true;
        view.dispatch({
          changes: {
            from: 0,
            to: currentValue.length,
            insert: value,
          },
        });
        isInternalChange.current = false;
      }
    }, [value]);

    // Handle readOnly changes
    useEffect(() => {
      const view = viewRef.current;
      if (!view) return;

      view.dispatch({
        effects: readOnlyCompartment.current.reconfigure(EditorState.readOnly.of(readOnly)),
      });
    }, [readOnly]);

    // Expose ref methods
    useImperativeHandle(ref, () => ({
      focus: () => {
        viewRef.current?.focus();
      },
      getValue: () => {
        return viewRef.current?.state.doc.toString() ?? '';
      },
      setValue: (newValue: string) => {
        const view = viewRef.current;
        if (!view) return;

        isInternalChange.current = true;
        view.dispatch({
          changes: {
            from: 0,
            to: view.state.doc.length,
            insert: newValue,
          },
        });
        isInternalChange.current = false;
      },
    }), []);

  return (
    <div
      ref={containerRef}
      className={`cm-editor-container h-full w-full overflow-hidden rounded-lg bg-background ${className}`}
    />
  );
}

export default VrlEditor;
