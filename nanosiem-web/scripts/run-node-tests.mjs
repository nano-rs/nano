// Runs every `node:test` file in one `tsx --test` invocation (NAN-4980).
// tsx, not bare `node --test`: a few files import `@/` aliases or extensionless
// TypeScript modules that Node's built-in type stripping cannot resolve.
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { nodeTestFiles } from './node-test-files.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = nodeTestFiles();
if (files.length === 0) {
  console.error('test:node found no node:test files; the discovery pattern is broken');
  process.exit(1);
}
console.log(`test:node running ${files.length} files`);

const tsxCli = createRequire(import.meta.url).resolve('tsx/cli');
const result = spawnSync(process.execPath, [tsxCli, '--test', ...files], {
  cwd: root,
  stdio: 'inherit',
});
process.exit(result.status ?? 1);
