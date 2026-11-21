// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * YAML-frontmatter helper plugins for the detection rule editor: faded
 * placeholder values cleared on click, and clickable option hints on empty
 * fields. Both dispatch their own changes, so both check
 * `EditorState.readOnly` themselves (NAN-5683).
 */
import { Decoration, DecorationSet, EditorView, ViewPlugin, ViewUpdate, WidgetType } from '@codemirror/view';

import { isInYamlSection } from './detection-language';
import { YAML_FIELD_OPTIONS } from './detection-autocomplete';

// Placeholder values that should be styled as faded and cleared on click
const PLACEHOLDER_VALUES: Record<string, string> = {
  tags: 'tag1, tag2',
};

/**
 * Create click handlers for special YAML fields (placeholder clearing)
 */
export function createClickableFieldPlugin() {
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
          // NAN-5683: `EditorState.readOnly` only stops built-in input, not a
          // plugin's own dispatch — a read-only buffer takes no click edit.
          if (view.state.readOnly) return false;
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
        // NAN-5683: never write into a read-only buffer.
        if (this.view.state.readOnly) return;

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
export function createEmptyFieldHintsPlugin() {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;

      constructor(view: EditorView) {
        this.decorations = this.buildDecorations(view);
      }

      update(update: ViewUpdate) {
        if (
          update.docChanged ||
          update.selectionSet ||
          update.viewportChanged ||
          update.startState.readOnly !== update.state.readOnly
        ) {
          this.decorations = this.buildDecorations(update.view);
        }
      }

      buildDecorations(view: EditorView): DecorationSet {
        // NAN-5683: a read-only buffer offers no clickable value hints.
        if (view.state.readOnly) return Decoration.none;
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
