// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4586 — easy-mode rendering of `{{path}}` bindings in the nPL editor:
 * each binding is replaced by an atomic inline chip ("Alert → Host"), so the
 * cursor skips it and Backspace removes the whole binding. The document text
 * is unchanged; Advanced mode simply omits this extension.
 */
import type { Extension } from '@codemirror/state';
import { Decoration, EditorView, MatchDecorator, ViewPlugin, WidgetType, type DecorationSet, type ViewUpdate } from '@codemirror/view';
import type { FieldDef } from './soar-fields';
import { fieldFor, fieldLabel } from './soar-fields';

class ChipWidget extends WidgetType {
  constructor(readonly label: string, readonly path: string, readonly known: boolean) {
    super();
  }
  eq(other: ChipWidget) {
    return other.label === this.label && other.path === this.path;
  }
  toDOM() {
    const el = document.createElement('span');
    el.className = this.known
      ? 'npl-binding-chip mx-px inline-flex items-center rounded-[3px] border border-primary/40 bg-primary/10 px-1 align-baseline font-sans text-[11.5px] leading-[16px] text-primary'
      : 'npl-binding-chip mx-px inline-flex items-center rounded-[3px] border border-border-2 px-1 align-baseline font-mono text-[11px] leading-[16px] text-fg-2';
    el.textContent = this.label;
    el.title = this.path;
    el.setAttribute('data-binding', this.path);
    return el;
  }
  ignoreEvent() {
    return false;
  }
}

export function bindingChips(fields: FieldDef[]): Extension {
  const matcher = new MatchDecorator({
    regexp: /\{\{\s*([^}]*?)\s*\}\}/g,
    decoration: (m) => {
      const known = !!fieldFor(m[1], fields);
      return Decoration.replace({ widget: new ChipWidget(known ? fieldLabel(m[1], fields) : m[1], m[1], known) });
    },
  });
  const plugin = ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;
      constructor(view: EditorView) {
        this.decorations = matcher.createDeco(view);
      }
      update(u: ViewUpdate) {
        this.decorations = matcher.updateDeco(u, this.decorations);
      }
    },
    {
      decorations: (v) => v.decorations,
      provide: (p) => EditorView.atomicRanges.of((view) => view.plugin(p)?.decorations ?? Decoration.none),
    },
  );
  return plugin;
}
