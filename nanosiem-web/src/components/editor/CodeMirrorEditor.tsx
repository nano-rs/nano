// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 React wrapper for detection rule editor
 * Provides controlled component with value/onChange props
 */
import React, { useRef, useEffect, useImperativeHandle, useCallback } from 'react';
import { EditorState, Extension, Compartment } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, type ViewUpdate } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { bracketMatching, indentOnInput } from '@codemirror/language';
import { closeBrackets, closeBracketsKeymap } from '@codemirror/autocomplete';
import { highlightSelectionMatches, searchKeymap } from '@codemirror/search';

import { detectionTheme } from './codemirror-theme';
import { detectionLanguage } from './detection-language';
import { detectionAutocomplete } from './detection-autocomplete';
import { createClickableFieldPlugin, createEmptyFieldHintsPlugin } from './yaml-helper-plugins';
import { detectionLinter, resetValidationCache, markValidationStale, type ValidationState, getValidationState } from './detection-linter';

/**
 * Editor ref methods
 */
export interface CodeMirrorEditorRef {
  focus: () => void;
  getCursor: () => number;
  insertText: (text: string, at?: number) => void;
  getValue: () => string;
  getEditorView: () => EditorView | null;
}

/**
 * Editor props
 */
export interface CodeMirrorEditorProps {
  value: string;
  onChange: (value: string) => void;
  onValidationChange?: (validation: ValidationState | null) => void;
  readOnly?: boolean;
  className?: string;
}

/**
 * CodeMirror 6 Editor Component
 */
export function CodeMirrorEditor({
  value,
  onChange,
  onValidationChange,
  readOnly = false,
  className = '',
  ref,
}: CodeMirrorEditorProps & { ref?: React.Ref<CodeMirrorEditorRef> }) {
    const containerRef = useRef<HTMLDivElement>(null);
    const viewRef = useRef<EditorView | null>(null);
    const onChangeRef = useRef(onChange);
    const isInternalChange = useRef(false);
    const readOnlyCompartment = useRef(new Compartment());
    const validationDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const lastValidationRef = useRef<ValidationState | null>(null);

    // Keep onChange ref updated
    useEffect(() => {
      onChangeRef.current = onChange;
    }, [onChange]);

    // Debounced validation state update (300ms delay to reduce flickering)
    const updateValidationState = useCallback((state: ValidationState | null) => {
      if (!onValidationChange) return;

      // Clear any pending update
      if (validationDebounceRef.current) {
        clearTimeout(validationDebounceRef.current);
      }

      // If state is null (stale), wait before clearing to avoid flicker
      // If state has value, also debounce to batch rapid updates
      validationDebounceRef.current = setTimeout(() => {
        // Only update if actually changed
        if (JSON.stringify(state) !== JSON.stringify(lastValidationRef.current)) {
          lastValidationRef.current = state;
          onValidationChange(state);
        }
      }, state === null ? 400 : 200); // Longer delay for clearing, shorter for showing results
    }, [onValidationChange]);

    // Create update listener extension
    const createUpdateListener = useCallback(() => {
      return EditorView.updateListener.of((update: ViewUpdate) => {
        if (update.docChanged) {
          // Mark validation as stale immediately when document changes
          markValidationStale();

          if (!isInternalChange.current) {
            const newValue = update.state.doc.toString();
            onChangeRef.current(newValue);
          }
        }

        // Check validation state after lint updates (debounced)
        const validationState = getValidationState(update.state.doc);
        updateValidationState(validationState);
      });
    }, [updateValidationState]);

    // Build extensions array
    const getExtensions = useCallback((): Extension[] => {
      return [
        // Basic editor features
        lineNumbers(),
        highlightActiveLine(),
        highlightActiveLineGutter(),
        history(),
        bracketMatching(),
        closeBrackets(),
        indentOnInput(),
        highlightSelectionMatches(),

        // Keymaps
        keymap.of([
          ...closeBracketsKeymap,
          ...defaultKeymap,
          ...historyKeymap,
          ...searchKeymap,
        ]),

        // Detection-specific extensions
        detectionLanguage,
        detectionTheme,
        detectionAutocomplete(),
        detectionLinter(),

        // Clickable fields
        createClickableFieldPlugin(),

        // Empty field hints (ghost text showing available options)
        createEmptyFieldHintsPlugin(),

        // Update listener
        createUpdateListener(),

        // Placeholder
        EditorView.contentAttributes.of({
          'aria-label': 'Detection rule editor',
        }),

        // Read-only mode (using compartment for dynamic updates)
        readOnlyCompartment.current.of(EditorState.readOnly.of(readOnly)),
      ];
    }, [readOnly, createUpdateListener]);

    // Initialize editor
    useEffect(() => {
      if (!containerRef.current) return;

      // Reset validation cache when initializing
      resetValidationCache();

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
        // Clear any pending validation debounce
        if (validationDebounceRef.current) {
          clearTimeout(validationDebounceRef.current);
        }
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
      getCursor: () => {
        return viewRef.current?.state.selection.main.head ?? 0;
      },
      insertText: (text: string, at?: number) => {
        const view = viewRef.current;
        if (!view) return;

        const pos = at ?? view.state.selection.main.head;
        view.dispatch({
          changes: { from: pos, insert: text },
          selection: { anchor: pos + text.length },
        });
      },
      getValue: () => {
        return viewRef.current?.state.doc.toString() ?? '';
      },
      getEditorView: () => {
        return viewRef.current;
      },
    }), []);

  return (
    <div
      ref={containerRef}
      className={`cm-editor-container h-full w-full overflow-hidden rounded-xl bg-background ${className}`}
    />
  );
}

export default CodeMirrorEditor;
