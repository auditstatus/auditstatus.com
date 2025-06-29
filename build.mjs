#!/usr/bin/env node

import {
	readFileSync, writeFileSync, mkdirSync, existsSync,
} from 'node:fs';
import {join} from 'node:path';

// Create dist directory if it doesn't exist
if (!existsSync('dist')) {
	mkdirSync('dist', {recursive: true});
}

// Create package.json for dist directory
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const distPkg = {
	name: pkg.name,
	version: pkg.version,
	description: pkg.description,
	main: '../scripts/audit-servers.js',
	license: pkg.license,
	repository: pkg.repository,
	bugs: pkg.bugs,
	homepage: pkg.homepage,
};

writeFileSync('dist/package.json', JSON.stringify(distPkg, null, 2));

console.log('Build completed successfully!');

