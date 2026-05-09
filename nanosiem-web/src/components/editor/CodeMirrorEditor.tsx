// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CodeMirror 6 React wrapper for detection rule editor
 * Provides controlled component with value/onChange props
 */
import React, { useRef, useEffect, useImperativeHandle, useCallback } from 'react';
import { EditorState, Extension, Compartment } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, WidgetType } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { bracketMatching, indentOnInput } from '@codemirror/language';
import { closeBrackets, closeBracketsKeymap } from '@codemirror/autocomplete';
import { highlightSelectionMatches, searchKeymap } from '@codemirror/search';
import { Decoration, DecorationSet, ViewPlugin, ViewUpdate } from '@codemirror/view';

import { detectionTheme } from './codemirror-theme';
import { detectionLanguage, isInYamlSection } from './detection-language';
import { detectionAutocomplete, YAML_FIELD_OPTIONS } from './detection-autocomplete';
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

// Placeholder values that should be styled as faded and cleared on click
const PLACEHOLDER_VALUES: Record<string, string> = {
  tags: 'tag1, tag2',
};

/**
 * Create click handlers for special YAML fields (placeholder clearing)
 */
function createClickableFieldPlugin() {
  // Create decoration mark for placeholder values (faded, click to clear)
  const placeholderMark = Decoration.mark({
    class: 'cm-placeholder-value',
  });

  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;

      constructor(view: EditorView) {
        this.decorations = this.buildDecorations(view);
      }

      update(update: ViewUpdate) {
        if (update.docChanged || update.viewportChanged) {
          this.decorations = this.buildDecorations(update.view);
        }
      }

      buildDecorations(view: EditorView): DecorationSet {
        const decorations: { from: number; to: number; decoration: Decoration }[] = [];
        const text = view.state.doc.toString();

        // Only process YAML section
        const yamlStart = text.indexOf('---');
        const yamlEnd = text.indexOf('---', yamlStart + 3);
        if (yamlStart === -1 || yamlEnd === -1) return Decoration.none;

        // Find placeholder values (e.g., tags: tag1, tag2)
        for (const [field, placeholder] of Object.entries(PLACEHOLDER_VALUES)) {
          const regex = new RegExp(`^${field}:\\s*${placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'm');
          const match = text.match(regex);
          if (match && match.index !== undefined) {
            const lineStart = match.index;
            const valueStart = lineStart + field.length + 1; // +1 for colon
            const valueEnd = lineStart + match[0].length;

            if (valueStart < yamlEnd) {
              decorations.push({
                from: valueStart,
                to: valueEnd,
                decoration: placeholderMark,
              });
            }
          }
        }

        return Decoration.set(
          decorations
            .sort((a, b) => a.from - b.from)
            .map(d => d.decoration.range(d.from, d.to))
        );
      }
    },
    {
      decorations: v => v.decorations,
      eventHandlers: {
        click(event, view) {
          const pos = view.posAtCoords({ x: event.clientX, y: event.clientY });
          if (pos === null) return false;

          const doc = view.state.doc.toString();

          // Check if we're in YAML section
          if (!isInYamlSection(doc, pos)) return false;

          // Get the line at click position
          const line = view.state.doc.lineAt(pos);
          const lineText = line.text;

          // Check if this line has a field we handle
          const fieldMatch = lineText.match(/^(\w+):\s*/);
          if (!fieldMatch) return false;

          const fieldName = fieldMatch[1];

          // Check if this is a placeholder value - clear it on click
          const placeholder = PLACEHOLDER_VALUES[fieldName];
          if (placeholder) {
            const valueMatch = lineText.match(/^(\w+):\s*(.*)$/);
            if (valueMatch && valueMatch[2].trim() === placeholder) {
              event.preventDefault();
              // Clear the placeholder value
              const valueStart = line.from + fieldMatch[0].length;
              const valueEnd = line.to;
              view.dispatch({
                changes: { from: valueStart, to: valueEnd, insert: '' },
                selection: { anchor: valueStart },
              });
              return true;
            }
          }

          return false;
        },
      },
    }
  );
}

/**
 * Widget that displays hint text for empty YAML field values
 * Each option is individually clickable to populate that value
 */
class EmptyFieldHintWidget extends WidgetType {
  constructor(
    readonly options: Array<{ value: string; label?: string }>,
    readonly fieldName: string,
    readonly linePos: number,
    readonly view: EditorView
  ) {
    super();
  }

  toDOM(): HTMLElement {
    const container = document.createElement('span');
    container.className = 'cm-empty-field-hint';

    this.options.forEach((opt, index) => {
      if (index > 0) {
        const separator = document.createElement('span');
        separator.className = 'cm-hint-separator';
        separator.textContent = ' | ';
        container.appendChild(separator);
      }

      const optSpan = document.createElement('span');
      optSpan.className = 'cm-hint-option';
      optSpan.textContent = opt.value;
      if (opt.label && opt.label !== opt.value) {
        optSpan.title = opt.label;
      }

      // Add click handler directly to the option
      optSpan.addEventListener('mousedown', (e) => {
        e.preventDefault();
        e.stopPropagation();

        // Insert the value at the stored position
        this.view.dispatch({
          changes: { from: this.linePos, to: this.linePos, insert: opt.value },
          selection: { anchor: this.linePos + opt.value.length },
        });
        this.view.focus();
      });

      container.appendChild(optSpan);
    });

    return container;
  }

  ignoreEvent(): boolean {
    return false;
  }
}

/**
 * Get clickable options for a YAML field
 */
function getFieldOptions(fieldName: string): Array<{ value: string; label?: string }> | null {
  const options = YAML_FIELD_OPTIONS[fieldName];
  if (!options) return null;

  // For fields with reasonable number of options, show them all
  if (options.length <= 6) {
    return options.map(o => ({ value: o.value, label: o.label }));
  }

  // For MITRE fields, show abbreviated hints (not clickable individual items)
  return null;
}

/**
 * Creates a plugin that shows hints for empty YAML field values
 */
function createEmptyFieldHintsPlugin() {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;

      constructor(view: EditorView) {
        this.decorations = this.buildDecorations(view);
      }

      update(update: ViewUpdate) {
        if (update.docChanged || update.selectionSet || update.viewportChanged) {
          this.decorations = this.buildDecorations(update.view);
        }
      }

      buildDecorations(view: EditorView): DecorationSet {
        const decorations: { pos: number; widget: WidgetType }[] = [];
        const text = view.state.doc.toString();
        const cursorPos = view.state.selection.main.head;

        // Only process YAML section
        const yamlStart = text.indexOf('---');
        const yamlEnd = text.indexOf('---', yamlStart + 3);
        if (yamlStart === -1 || yamlEnd === -1) return Decoration.none;

        const yamlSection = text.substring(yamlStart, yamlEnd);
        const lines = yamlSection.split('\n');
        let lineOffset = yamlStart;

        for (const line of lines) {
          // Check if this line has a field with an empty value
          const match = line.match(/^(\w+):\s*$/);
          if (match) {
            const fieldName = match[1];
            const options = getFieldOptions(fieldName);

            if (options && options.length > 0) {
              const hintPos = lineOffset + line.length;

              // Don't show hint if cursor is on this line (user is editing)
              const lineStart = lineOffset;
              const lineEnd = lineOffset + line.length;
              const cursorOnLine = cursorPos >= lineStart && cursorPos <= lineEnd;

              if (!cursorOnLine) {
                decorations.push({
                  pos: hintPos,
                  widget: new EmptyFieldHintWidget(options, fieldName, hintPos, view),
                });
              }
            }
          }
          lineOffset += line.length + 1; // +1 for newline
        }

        return Decoration.set(
          decorations.map(d =>
            Decoration.widget({ widget: d.widget, side: 1 }).range(d.pos)
          )
        );
      }
    },
    {
      decorations: v => v.decorations,
    }
  );
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
        const validationState = getValidationState();
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
