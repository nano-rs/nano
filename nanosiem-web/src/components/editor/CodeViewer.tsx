// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Read-only CodeMirror viewer for detection rules
 * Uses the same syntax highlighting as the editor but without editing features
 */
import { useRef, useEffect } from 'react';
import { EditorState, type Extension } from '@codemirror/state';
import { EditorView, lineNumbers } from '@codemirror/view';
import { detectionTheme } from './codemirror-theme';
import { detectionLanguage } from './detection-language';

interface CodeViewerProps {
  content: string;
  className?: string;
  maxHeight?: string;
  /** Override the language extension (defaults to detectionLanguage for full YAML+nPL rules) */
  language?: Extension;
}

/**
 * Read-only code viewer with detection rule syntax highlighting.
 * Pass `language={queryLanguage}` for query-only content (no YAML frontmatter).
 */
export function CodeViewer({ content, className = '', maxHeight = '400px', language }: CodeViewerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const state = EditorState.create({
      doc: content,
      extensions: [
        EditorView.editable.of(false),
        EditorState.readOnly.of(true),
        lineNumbers(),
        language ?? detectionLanguage,
        detectionTheme,
        EditorView.theme({
          '&': {
            maxHeight,
            overflow: 'auto',
          },
          '.cm-scroller': {
            overflow: 'auto',
          },
        }),
      ],
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
  }, [content, maxHeight, language]);

  return (
    <div
      ref={containerRef}
      className={`cm-viewer-container rounded-lg overflow-hidden bg-muted ${className}`}
    />
  );
}

export default CodeViewer;
