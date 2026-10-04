#!/usr/bin/env node

/**
 * Audit Status - bundle for a single executable application (SEA)
 *
 * Bundles the CLI and its dependencies into one CommonJS file and writes the
 * SEA configuration.  scripts/build-binary.sh turns that into a binary.
 *
 * Output:
 *   dist/standalone/cli.cjs   the bundle
 *   sea-config.json           input for `node --experimental-sea-config`
 *
 * @license MIT
 */

import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const {version} = JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8'));

mkdirSync(join(rootDir, 'dist', 'standalone'), {recursive: true});

await build({
  // The bundle has no `require.main`, so call the entry point directly.
  stdin: {
    // The SIGUSR1 handler comes first: until one exists, the signal opens
    // the inspector (see main() in cli.js).
    contents: 'process.on(\'SIGUSR1\', () => {});\nrequire(\'./cli.js\').main();',
    resolveDir: join(rootDir, 'scripts'),
    sourcefile: 'sea-entry.js',
    loader: 'js',
  },
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'cjs',
  outfile: join(rootDir, 'dist', 'standalone', 'cli.cjs'),
  legalComments: 'inline',
  // Cosmiconfig can load TypeScript configuration files through an optional
  // dependency that Audit Status never uses.
  external: ['typescript'],
  logLevel: 'warning',
});

writeFileSync(join(rootDir, 'sea-config.json'), `${JSON.stringify({
  main: 'dist/standalone/cli.cjs',
  output: 'sea-prep.blob',
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: false,
  // No inspector thread: SIGUSR1 cannot open a debugger, even at startup.
  execArgv: ['--disable-sigusr1'],
}, null, 2)}\n`);

console.log(`Bundled Audit Status ${version}: dist/standalone/cli.cjs and sea-config.json`);
