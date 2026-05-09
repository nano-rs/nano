// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror-based search query editor
 * Designed to replace the textarea+overlay in SearchQueryInput
 * with CodeMirror syntax highlighting while maintaining visual parity
 */
import React, { useRef, useEffect, useImperativeHandle, useCallback, useLayoutEffect } from 'react';
import { EditorState, Extension, Compartment, Prec } from '@codemirror/state';
import { EditorView, keymap, placeholder as placeholderExt } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap, insertNewlineAndIndent } from '@codemirror/commands';
import { bracketMatching } from '@codemirror/language';
import { closeBrackets, closeBracketsKeymap, completionStatus, startCompletion, acceptCompletion } from '@codemirror/autocomplete';
import { syntaxHighlighting, HighlightStyle } from '@codemirror/language';
import { tags } from '@lezer/highlight';

import { sql, StandardSQL } from '@codemirror/lang-sql';
import { queryLanguage } from './query-language';
import { searchBarTheme, searchBarSyntaxTheme } from './search-bar-theme';
import { searchAutocomplete } from './search-autocomplete';

/**
 * Plain highlight style that neutralizes all syntax coloring for AI mode.
 * Every token renders in the default foreground with normal weight/style.
 */
const plainHighlightStyle = HighlightStyle.define([
  { tag: tags.comment, color: 'inherit', fontStyle: 'normal' },
  { tag: tags.lineComment, color: 'inherit', fontStyle: 'normal' },
  { tag: tags.blockComment, color: 'inherit', fontStyle: 'normal' },
  { tag: tags.string, color: 'inherit' },
  { tag: tags.number, color: 'inherit' },
  { tag: tags.keyword, color: 'inherit', fontWeight: 'normal' },
  { tag: tags.operatorKeyword, color: 'inherit', fontWeight: 'normal' },
  { tag: tags.function(tags.variableName), color: 'inherit', fontWeight: 'normal' },
  { tag: tags.operator, color: 'inherit' },
  { tag: tags.compareOperator, color: 'inherit' },
  { tag: tags.arithmeticOperator, color: 'inherit' },
  { tag: tags.separator, color: 'inherit', fontWeight: 'normal' },
  { tag: tags.regexp, color: 'inherit', fontWeight: 'normal' },
  { tag: tags.propertyName, color: 'inherit', fontWeight: 'normal' },
  { tag: tags.special(tags.propertyName), color: 'inherit', fontWeight: 'normal' },
  { tag: tags.variableName, color: 'inherit' },
  { tag: tags.bool, color: 'inherit', fontWeight: 'normal' },
]);

/**
 * Cursor coordinates for dropdown positioning
 */
export interface CursorCoords {
  x: number;
  y: number;
  lineHeight: number;
}

/**
 * Editor ref methods
 */
export interface SearchQueryEditorRef {
  focus: () => void;
  getValue: () => string;
  setValue: (value: string) => void;
  getCursorCoords: () => CursorCoords | null;
  getCursorPosition: () => number;
  setCursorPosition: (pos: number) => void;
}

/**
 * Editor props
 */
export interface SearchQueryEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  aiMode?: boolean;
  /** When true, use SQL syntax highlighting instead of nPL */
  sqlMode?: boolean;
  /** Called for keyboard events - return true to prevent CodeMirror from handling */
  onKeyDown?: (event: KeyboardEvent, view: EditorView) => boolean;
  /** Called when cursor position changes */
  onCursorChange?: (position: number, coords: CursorCoords | null) => void;
  onFocus?: () => void;
  onBlur?: () => void;
  /** Called when Enter is pressed (without modifiers) */
  onSubmit?: () => void;
  /** Called when Tab is pressed */
  onTabPress?: () => void;
  /** Enable CodeMirror-native autocomplete. 'auto' = as-you-type, 'manual' = Ctrl+Space only, false = off */
  autocomplete?: 'auto' | 'manual' | false;
}

/**
 * CodeMirror-based Search Query Editor
 */
export function SearchQueryEditor({
  value,
  onChange,
  placeholder = '',
  aiMode = false,
  sqlMode = false,
  onKeyDown,
  onCursorChange,
  onFocus,
  onBlur,
  onSubmit,
  onTabPress,
  autocomplete: autocompleteProp = false,
  ref,
}: SearchQueryEditorProps & { ref?: React.Ref<SearchQueryEditorRef> }) {
    const containerRef = useRef<HTMLDivElement>(null);
    const viewRef = useRef<EditorView | null>(null);
    const isInternalChange = useRef(false);
    const aiModeCompartment = useRef(new Compartment());
    const languageCompartment = useRef(new Compartment());
    const keymapCompartment = useRef(new Compartment());
    const autocompleteCompartment = useRef(new Compartment());

    // Store callbacks in refs - updated synchronously via useLayoutEffect
    const callbacksRef = useRef({
      onChange,
      onKeyDown,
      onCursorChange,
      onFocus,
      onBlur,
      onSubmit,
      onTabPress,
    });

    // Update refs synchronously before paint using useLayoutEffect
    useLayoutEffect(() => {
      callbacksRef.current = {
        onChange,
        onKeyDown,
        onCursorChange,
        onFocus,
        onBlur,
        onSubmit,
        onTabPress,
      };
    });

    // Get cursor coordinates relative to container
    const getCursorCoords = useCallback((): CursorCoords | null => {
      const view = viewRef.current;
      if (!view) return null;

      const pos = view.state.selection.main.head;
      const coords = view.coordsAtPos(pos);
      if (!coords) return null;

      const containerRect = containerRef.current?.getBoundingClientRect();
      if (!containerRect) return null;

      return {
        x: coords.left - containerRect.left,
        y: coords.bottom - containerRect.top,
        lineHeight: coords.bottom - coords.top,
      };
    }, []);

    // Create update listener
    const createUpdateListener = useCallback(() => {
      return EditorView.updateListener.of((update) => {
        if (update.docChanged && !isInternalChange.current) {
          callbacksRef.current.onChange(update.state.doc.toString());
        }
        // Notify cursor position changes
        if (update.selectionSet || update.docChanged) {
          const pos = update.state.selection.main.head;
          const coords = getCursorCoords();
          callbacksRef.current.onCursorChange?.(pos, coords);
        }
      });
    }, [getCursorCoords]);

    // Create focus/blur handlers
    const createFocusHandlers = useCallback(() => {
      return EditorView.domEventHandlers({
        focus: () => {
          callbacksRef.current.onFocus?.();
          return false;
        },
        blur: () => {
          // Delay blur to allow click handlers on dropdowns to fire
          setTimeout(() => {
            callbacksRef.current.onBlur?.();
          }, 150);
          return false;
        },
      });
    }, []);

    // Create high-precedence keymap for our custom key handling
    // When CodeMirror autocomplete is active, defer Tab/Enter/Arrows to it
    const createCustomKeymap = useCallback(() => {
      return Prec.highest(keymap.of([
        // Tab - accept completion if open, trigger it if not, then fall back to parent
        {
          key: 'Tab',
          run: (view) => {
            // If autocomplete dropdown is open, accept the selected completion
            if (completionStatus(view.state) === 'active') {
              return acceptCompletion(view);
            }
            // Let parent handle (e.g. close history dropdown)
            const event = new KeyboardEvent('keydown', { key: 'Tab', shiftKey: false });
            if (callbacksRef.current.onKeyDown?.(event, view)) return true;
            // If autocomplete extension is loaded, trigger it
            startCompletion(view);
            return true;
          },
        },
        // Enter - if autocomplete open, let CM handle. Otherwise parent → submit.
        {
          key: 'Enter',
          run: (view) => {
            if (completionStatus(view.state) === 'active') return false; // let CM accept completion
            const event = new KeyboardEvent('keydown', { key: 'Enter', shiftKey: false, metaKey: false });
            if (callbacksRef.current.onKeyDown?.(event, view)) return true;
            callbacksRef.current.onSubmit?.();
            return true;
          },
        },
        // Shift+Enter - insert newline
        {
          key: 'Shift-Enter',
          run: insertNewlineAndIndent,
        },
        // Cmd+Shift+Enter - let parent handle (AI search shortcut)
        {
          key: 'Mod-Shift-Enter',
          run: (view) => {
            const event = new KeyboardEvent('keydown', { key: 'Enter', shiftKey: true, metaKey: true });
            return callbacksRef.current.onKeyDown?.(event, view) ?? false;
          },
        },
        // Arrow keys - if autocomplete open, let CM handle. Otherwise parent.
        {
          key: 'ArrowDown',
          run: (view) => {
            if (completionStatus(view.state) === 'active') return false;
            const event = new KeyboardEvent('keydown', { key: 'ArrowDown' });
            return callbacksRef.current.onKeyDown?.(event, view) ?? false;
          },
        },
        {
          key: 'ArrowUp',
          run: (view) => {
            if (completionStatus(view.state) === 'active') return false;
            const event = new KeyboardEvent('keydown', { key: 'ArrowUp' });
            return callbacksRef.current.onKeyDown?.(event, view) ?? false;
          },
        },
        // Escape - if autocomplete open, let CM close it. Otherwise parent.
        {
          key: 'Escape',
          run: (view) => {
            if (completionStatus(view.state) === 'active') return false;
            const event = new KeyboardEvent('keydown', { key: 'Escape' });
            return callbacksRef.current.onKeyDown?.(event, view) ?? false;
          },
        },
      ]));
    }, []);

    // Build extensions
    const getExtensions = useCallback((): Extension[] => {
      return [
        // Custom keymap with highest precedence (before default keymaps)
        keymapCompartment.current.of(createCustomKeymap()),

        // Minimal features
        history(),
        bracketMatching(),
        closeBrackets(),

        // Keymaps
        keymap.of([
          ...closeBracketsKeymap,
          ...defaultKeymap,
          ...historyKeymap,
        ]),

        // Language (switchable between nPL and SQL via compartment)
        languageCompartment.current.of(
          sqlMode
            ? sql({ dialect: StandardSQL, upperCaseKeywords: true })
            : queryLanguage
        ),
        searchBarTheme,
        syntaxHighlighting(searchBarSyntaxTheme),

        // Placeholder
        placeholder ? placeholderExt(placeholder) : [],

        // Update listener
        createUpdateListener(),

        // Focus/blur handlers
        createFocusHandlers(),

        // AI mode compartment (empty by default, reconfigured when aiMode changes)
        aiModeCompartment.current.of([]),

        // Autocomplete compartment
        autocompleteCompartment.current.of(
          autocompleteProp ? searchAutocomplete(autocompleteProp === 'auto') : []
        ),

        // Allow line wrapping for multi-line queries
        EditorView.lineWrapping,
      ].flat();
    }, [placeholder, createUpdateListener, createFocusHandlers, createCustomKeymap]);

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
    }, []); // Only on mount

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

    // Handle aiMode changes - override syntax highlighting with plain style
    useEffect(() => {
      const view = viewRef.current;
      if (!view) return;

      view.dispatch({
        effects: aiModeCompartment.current.reconfigure(
          aiMode ? Prec.highest(syntaxHighlighting(plainHighlightStyle)) : []
        ),
      });
    }, [aiMode]);

    // Handle autocomplete prop changes
    useEffect(() => {
      const view = viewRef.current;
      if (!view) return;

      view.dispatch({
        effects: autocompleteCompartment.current.reconfigure(
          autocompleteProp ? searchAutocomplete(autocompleteProp === 'auto') : []
        ),
      });
    }, [autocompleteProp]);

    // Handle sqlMode changes - swap between nPL and SQL language
    useEffect(() => {
      const view = viewRef.current;
      if (!view) return;

      view.dispatch({
        effects: languageCompartment.current.reconfigure(
          sqlMode
            ? sql({ dialect: StandardSQL, upperCaseKeywords: true })
            : queryLanguage
        ),
      });
    }, [sqlMode]);

    // Expose ref methods
    useImperativeHandle(ref, () => ({
      focus: () => viewRef.current?.focus(),
      getValue: () => viewRef.current?.state.doc.toString() ?? '',
      setValue: (newValue: string) => {
        const view = viewRef.current;
        if (!view) return;
        isInternalChange.current = true;
        view.dispatch({
          changes: { from: 0, to: view.state.doc.length, insert: newValue },
        });
        isInternalChange.current = false;
      },
      getCursorCoords,
      getCursorPosition: () => viewRef.current?.state.selection.main.head ?? 0,
      setCursorPosition: (pos: number) => {
        const view = viewRef.current;
        if (!view) return;
        view.dispatch({
          selection: { anchor: pos },
        });
      },
    }), [getCursorCoords]);

  return (
    <div
      ref={containerRef}
      className="w-full h-full"
      data-ai-mode={aiMode}
    />
  );
}

export default SearchQueryEditor;
