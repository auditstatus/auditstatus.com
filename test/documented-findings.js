'use strict';

/**
 * The finding messages the documentation describes, as patterns, and the
 * findings of a report that none of them describes.
 *
 * docs/reports.md lists findings by check name (one "### check, check"
 * heading per table); containers.md, monitor.md, hardware.md and the
 * language pages list the findings of their own checks.  In a message,
 * "...", "…", "<name>" and a lone N, M, X or Y stand for any text; a
 * documented message may leave out what follows it (": detail",
 * " (detail)"), and one table cell may list several messages separated by
 * commas.  A message may start with the name of what it is about ("web: ",
 * a container's name).
 */

const fs = require('node:fs');
const path = require('node:path');

const DOCS = path.join(__dirname, '..', 'docs');

// Pages that describe the findings of one area, and its check names.
const PAGES = {
  'containers.md': ['container'],
  'monitor.md': ['monitor'],
  'hardware.md': ['tpm', 'ima', 'confidential'],
};

function toPattern(text) {
  const plain = text.replaceAll('`', '').replace(/\s+\(for example [^)]*\)$/, '').trim();
  const any = String.raw`[\s\S]*`;
  const source = plain.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`)
    .replaceAll(String.raw`\.\.\.`, any)
    .replaceAll('…', any)
    .replaceAll(/<[^>]+>/g, any)
    .replaceAll(/\b[MNXY]\b/g, any);
  return new RegExp(`^${source}(?:$|[ :;,.(])`);
}

function cells(line) {
  return line.split(/(?<!\\)\|/).slice(1, -1).map(cell => cell.trim());
}

/**
 * Message patterns from one Markdown table column, by the checks they belong to.
 */
function tablePatterns(text, {column, checksFor}) {
  const patterns = [];
  let header = null;
  let heading = null;
  for (const line of text.split('\n')) {
    const match = /^(#{2,4}) (.*)/.exec(line);
    if (match) {
      heading = match;
      header = null;
      continue;
    }

    if (!line.startsWith('|')) {
      header = null;
      continue;
    }

    if (!header) {
      header = cells(line);
      continue;
    }

    const index = header.indexOf(column);
    const checks = checksFor(heading);
    if (index === -1 || /^\|[\s|:-]+\|$/.test(line) || !checks) {
      continue;
    }

    const cell = cells(line)[index];
    for (const part of new Set([cell, ...cell.split(/,\s+(?:or\s+)?/)])) {
      patterns.push({checks, pattern: toPattern(part), text: cell});
    }
  }

  return patterns;
}

function documentedPatterns() {
  const reports = fs.readFileSync(path.join(DOCS, 'reports.md'), 'utf8');
  const findings = reports.slice(reports.indexOf('\n## Findings'));
  const patterns = tablePatterns(findings, {
    column: 'Message',
    checksFor: heading => (heading && heading[1] === '###' ? heading[2].split(',').map(name => name.trim().replaceAll('`', '')) : null),
  });
  for (const [page, checks] of Object.entries(PAGES)) {
    patterns.push(...tablePatterns(fs.readFileSync(path.join(DOCS, page), 'utf8'), {column: 'Finding', checksFor: () => checks}));
  }

  // The language pages describe what each ecosystem's checks report.
  for (const page of fs.readdirSync(path.join(DOCS, 'languages')).filter(name => name.endsWith('.md'))) {
    patterns.push(...tablePatterns(fs.readFileSync(path.join(DOCS, 'languages', page), 'utf8'), {column: 'Finding', checksFor: () => ['*']}));
  }

  return patterns;
}

/**
 * The findings no documented message describes, as "severity check: message".
 * @param {Array<{severity: string, check: string, message: string}>} findings
 * @returns {string[]}
 */
function undocumented(findings, patterns = documentedPatterns()) {
  const missing = new Set();
  for (const {severity, check, message} of findings) {
    const texts = [String(message), String(message).replace(/^[^:]{1,120}?: /, '')];
    const area = String(check).split(':')[0];
    const described = patterns.some(({checks, pattern}) => (checks.includes('*') || checks.includes(check) || checks.includes(area))
      && texts.some(text => pattern.test(text)));
    if (!described) {
      missing.add(`${severity} ${check}: ${message}`);
    }
  }

  return [...missing].sort();
}

module.exports = {documentedPatterns, undocumented};
