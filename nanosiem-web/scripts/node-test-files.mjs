// Single source of truth for which test files belong to the `node:test` runner
// and which belong to vitest (NAN-4980).
//
// The package has two test runners. vitest's default include glob
// (`**/*.test.*`) also matched every `node:test` file, collected them, found no
// vitest suite, and reported each as "No test suite found" — 32 phantom
// failures that buried real ones. Conversely nothing ran all of the `node:test`
// files together; several had no npm script at all.
//
// A file is a node:test file iff it imports `node:test` (or bare `test`). The
// vitest config excludes exactly this list and `test:node` runs exactly this
// list, so a new file lands in one runner or the other automatically.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TEST_FILE = /\.test\.(?:c|m)?[jt]sx?$/;
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', 'coverage']);
const NODE_TEST_IMPORT = /(?:from\s+|import\s*\(\s*|require\s*\(\s*)['"](?:node:)?test['"]/;
const VITEST_IMPORT = /(?:from\s+|import\s*\(\s*|require\s*\(\s*)['"]vitest['"]/;

function walk(dir, out) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(path.join(dir, entry.name), out);
    } else if (TEST_FILE.test(entry.name)) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/** Repo-relative (posix) paths of every `node:test` test file, sorted. */
export function nodeTestFiles() {
  const files = [];
  for (const abs of walk(ROOT, [])) {
    const src = readFileSync(abs, 'utf8');
    if (!NODE_TEST_IMPORT.test(src)) continue;
    const rel = path.relative(ROOT, abs).split(path.sep).join('/');
    if (VITEST_IMPORT.test(src)) {
      throw new Error(`${rel} imports both node:test and vitest; pick one runner`);
    }
    files.push(rel);
  }
  return files.sort();
}
