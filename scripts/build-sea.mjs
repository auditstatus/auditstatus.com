#!/usr/bin/env node

/**
 * Audit Status - SEA Build Script
 *
 * Bundles the CLI into a single standalone CJS file suitable for
 * Node.js Single Executable Application (SEA) packaging.
 *
 * Usage:
 *   node scripts/build-sea.mjs
 *
 * Output:
 *   dist/standalone/cli.cjs  - Bundled CLI ready for SEA injection
 *   sea-config.json          - SEA configuration for node --experimental-sea-config
 *
 * @author Forward Email <support@forwardemail.net>
 * @license MIT
 */

import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

const pkg = JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8'));
const {version} = pkg;

console.log(`Building Audit Status v${version} for SEA...`);

// Ensure output directory exists
mkdirSync(join(rootDir, 'dist', 'standalone'), {recursive: true});

// Bundle the CLI into a single CJS file
await build({
  entryPoints: [join(rootDir, 'scripts', 'cli.js')],
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'cjs',
  outfile: join(rootDir, 'dist', 'standalone', 'cli.cjs'),
  minify: true,
  external: [
    // Native modules that cannot be bundled
    'tpm2-tools',
  ],
  logOverride: {
    'empty-import-meta': 'silent',
  },
  define: {
    __AUDITSTATUS_VERSION__: JSON.stringify(version),
  },
  banner: {
    js: '"use strict";',
  },
  // Handle non-JS files
  loader: {
    '.html': 'text',
    '.node': 'copy',
    '.yml': 'text',
    '.yaml': 'text',
  },
});

console.log('Bundle created: dist/standalone/cli.cjs');

// Generate SEA config
const seaConfig = {
  main: 'dist/standalone/cli.cjs',
  output: 'sea-prep.blob',
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: true,
};

writeFileSync(
  join(rootDir, 'sea-config.json'),
  JSON.stringify(seaConfig, null, 2) + '\n',
);

console.log('SEA config created: sea-config.json');
console.log('Build completed successfully!');
console.log('');
console.log('Next steps (platform-specific):');
console.log('  1. node --experimental-sea-config sea-config.json');
console.log('  2. cp $(which node) auditstatus');
console.log('  3. npx postject auditstatus NODE_SEA_BLOB sea-prep.blob \\');
console.log('       --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2');
console.log('  4. chmod +x auditstatus');
