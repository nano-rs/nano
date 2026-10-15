import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import ts from 'typescript';
import { expect, it } from 'vitest';

const ticketId = /\b(?:NAN|FOR)-?\d+\b/;
function violations(root: string): string[] {
  const found: string[] = [];
  function walk(dir: string) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) { walk(path); continue; }
      // Test fixtures are internal; comments are excluded by the syntax tree.
      if (!/\.[jt]sx?$/.test(path) || /\.(?:test|spec)\.[jt]sx?$/.test(path)) continue;
      const source = ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true);
      function visit(node: ts.Node) {
        // Console diagnostics are internal. Do not exempt their whole file.
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
          && node.expression.expression.getText(source) === 'console') return;
        if ((ts.isStringLiteralLike(node) || ts.isJsxText(node)
          || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node))
          && ticketId.test(node.text)) {
          found.push(`${path}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`);
        }
        ts.forEachChild(node, visit);
      }
      visit(source);
    }
  }
  walk(root);
  return found;
}

it('keeps internal tracker IDs out of frontend strings and JSX', () => {
  expect(violations(new URL('.', import.meta.url).pathname)).toEqual([]);
});

it('keeps internal tracker IDs out of shipped customer documentation', () => {
  function walk(dir: string) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) { walk(path); continue; }
      if (!/\.mdx?$/.test(path)) continue;
      const visible = readFileSync(path, 'utf8').replace(/\{\/\*[\s\S]*?\*\/\}|<!--[\s\S]*?-->/g, '');
      expect(ticketId.test(visible), path).toBe(false);
    }
  }
  walk(new URL('../../docs/user-guide/', import.meta.url).pathname);
});
