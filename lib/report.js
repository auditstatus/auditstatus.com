/**
 * Audit Status - reports and badge
 *
 * Writes three files per run:
 *   report.json   every finding, for machines and archives
 *   report.md     the same, for people (GitHub renders it)
 *   badge.json    a Shields.io endpoint badge
 *
 * Values from evidence are escaped before they reach Markdown so a server
 * cannot inject links or markup into a published report.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {version: VERSION} = require('../package.json');

// CommonMark ends a line at CR as well as LF; no control character is safe.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]+/g;

const STATUS_TEXT = {
  pass: 'passing',
  warn: 'passing with warnings',
  fail: 'failing',
  error: 'inconclusive',
};

const STATUS_COLOR = {
  pass: 'brightgreen',
  warn: 'yellow',
  fail: 'red',
  error: 'orange',
};

const STATUS_ICON = {
  pass: '✅',
  warn: '⚠️',
  fail: '❌',
  error: '❔',
};

const LEVEL_PART = {
  tpm: 'TPM',
  ima: 'IMA',
  'sev-snp': 'AMD SEV-SNP',
  tdx: 'Intel TDX',
};

/**
 * What backs a server's evidence, for people.
 * @param {string} level - "software", or hardware joined with "+"
 * @returns {string}
 */
function levelText(level) {
  if (!level || level === 'software') {
    return 'software evidence';
  }

  return level.split('+').map(part => LEVEL_PART[part] || part).join(' + ');
}

/**
 * Escape text for Markdown and HTML contexts.  GitHub also turns bare URLs,
 * "www." hosts, @mentions and #references into links, so those characters
 * are written as entities.
 * @param {*} value
 * @returns {string}
 */
function escapeMarkdown(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('#', '&#35;')
    .replaceAll('@', '&#64;')
    .replaceAll(':', '&#58;')
    .replaceAll(/www\./gi, match => `${match.slice(0, 3)}&#46;`)
    .replaceAll(/[\\`*_[\]|~]/g, String.raw`\$&`)
    .replaceAll(CONTROL_CHARACTERS, ' ');
}

/**
 * The evidence level of the least-backed server: "software", the level all
 * servers share, or "hardware" when they are backed by different hardware.
 *
 * @param {Object[]} servers
 * @returns {string}
 */
function weakestLevel(servers) {
  const levels = new Set(servers.map(server => server.level || 'software'));
  if (levels.size === 0 || levels.has('software')) {
    return 'software';
  }

  return levels.size === 1 ? [...levels][0] : 'hardware';
}

/**
 * What backs a passing badge, by its least-backed server: a badge never
 * claims more than every server's evidence shows.  Software evidence is
 * named, because root on a server can forge it.
 *
 * @param {Object[]} servers
 * @returns {string}
 */
function badgeLevel(servers) {
  const level = weakestLevel(servers);
  return level === 'hardware' ? 'hardware evidence' : levelText(level);
}

/**
 * Shields.io endpoint badge.  A passing badge names its evidence level.
 * @param {Object} report
 * @param {string} [label='audit']
 * @returns {{schemaVersion: number, label: string, message: string, color: string}}
 */
function badge(report, label = 'audit') {
  if (!report || !STATUS_TEXT[report.status]) {
    return {
      schemaVersion: 1, label, message: 'unknown', color: 'lightgrey',
    };
  }

  const servers = report.servers || [];
  const passing = servers.filter(server => server.status === 'pass' || server.status === 'warn').length;
  let message = STATUS_TEXT[report.status];
  if (report.status !== 'pass' && servers.length > 1) {
    message = `${message} (${passing}/${servers.length})`;
  }

  if (report.status === 'pass' || report.status === 'warn') {
    message = `${message}, ${badgeLevel(servers)}`;
  }

  return {
    schemaVersion: 1, label, message, color: STATUS_COLOR[report.status],
  };
}

/**
 * Package findings (from comparePackages) as one line each.
 * @param {*} detail
 * @returns {string[]|null}
 */
function packageItems(detail) {
  if (!Array.isArray(detail)) {
    return null;
  }

  const list = (label, files) => (Array.isArray(files) && files.length > 0 ? `; ${label}: ${files.slice(0, 5).join(', ')}${files.length > 5 ? ', …' : ''}` : '');
  return detail
    .filter(item => item && typeof item.package === 'string')
    .map(item => `${item.package} (${item.path}): ${item.reason}${list('modified', item.modified)}${list('missing', item.missing)}${list('added', item.added)}`);
}

function commitLink(service, commit) {
  if (!commit) {
    return '—';
  }

  const web = service && service.repository && service.repository.webUrl;
  return web ? `[\`${commit.slice(0, 12)}\`](${web}/commit/${commit})` : `\`${commit.slice(0, 12)}\``;
}

function ratio(verified, total) {
  return `${verified}/${total}`;
}

/**
 * One line per service of a server.
 */
function serviceLines(report, server) {
  const lines = [];
  for (const service of server.services || []) {
    const configured = (report.services || []).find(item => item.name === service.name);
    if (service.kind === 'container') {
      for (const container of service.containers) {
        const files = container.files ? `${container.files.modified + container.files.missing + container.files.added} changes from the image` : 'files not compared';
        lines.push(`* **${escapeMarkdown(service.name)}** container ${escapeMarkdown(container.name || container.id.slice(0, 12))}: ${escapeMarkdown(container.image || 'unknown image')}${container.digest ? ` (\`${container.digest.slice(0, 19)}\`)` : ''}, ${files}, ${container.processes} process(es)`);
      }

      if (service.containers.length === 0) {
        lines.push(`* **${escapeMarkdown(service.name)}**: no running container`);
      }

      continue;
    }

    const parts = [`commit ${commitLink(configured, service.commit)}`];
    if (service.files) {
      parts.push(`files ${ratio(service.files.verified, service.files.tracked ?? service.files.manifest)}`);
    }

    if (service.build) {
      parts.push(`build ${ratio(service.build.verified, service.build.files)}`);
    }

    for (const [where, summary] of Object.entries(service.packages || {})) {
      parts.push(`${escapeMarkdown(where.split(':')[0])} packages ${ratio(summary.verified ?? (summary.total - summary.failed - summary.unverifiable - (summary.error || 0)), summary.total)}`);
    }

    if (service.processes !== undefined) {
      const runtimes = Object.entries(service.runtimes || {}).map(([name, count]) => `${escapeMarkdown(name)} ×${count}`).join(', ');
      parts.push(`${service.processes} process(es)${runtimes ? ` (${runtimes})` : ''}`);
    }

    lines.push(`* **${escapeMarkdown(service.name)}**: ${parts.join(', ')}`);
  }

  return lines;
}

/**
 * Render a report as Markdown.
 * @param {Object} report
 * @returns {string}
 */
function markdown(report) {
  // A report the public registry publishes names its project (from the
  // registry file, whose website URL lib/registry.js has checked).
  const {project} = report;
  const lines = [
    project ? `# Audit Status: ${escapeMarkdown(project.name)}` : '# Audit Status',
    '',
    ...(project ? [`[${escapeMarkdown(project.url)}](${project.url}), verified by the [Audit Status registry](${project.registry}).`, ''] : []),
    `${STATUS_ICON[report.status]} **${STATUS_TEXT[report.status]}**: ${report.servers.filter(server => server.status === 'pass' || server.status === 'warn').length} of ${report.servers.length} servers passed.`,
    '',
    ...(report.notice ? [escapeMarkdown(report.notice), ''] : []),
    `Generated at ${escapeMarkdown(report.generatedAt)} by Audit Status ${escapeMarkdown(report.verifier.version)}${report.verifier.run && /^https:\/\/[\w.:/@+-]+$/.test(report.verifier.run.url) ? ` in [this workflow run](${report.verifier.run.url})` : ''}.`,
    '',
    '| Server | Status | Evidence | Services | Processes | Code explained |',
    '| --- | --- | --- | --- | --- | --- |',
  ];

  for (const server of report.servers) {
    const {code} = server.summary;
    const explained = code ? `${code.executables + code.libraries - code.differing - code.unexplained - code.unchecked}/${code.executables + code.libraries}` : '—';
    lines.push(`| ${escapeMarkdown(server.name)} | ${STATUS_ICON[server.status]} ${STATUS_TEXT[server.status]} | ${escapeMarkdown(levelText(server.level))} | ${(server.services || []).length} | ${server.summary.processes ?? '—'} | ${explained} |`);
  }

  for (const server of report.servers) {
    lines.push('', `## ${escapeMarkdown(server.name)}`, '');
    if (server.collectedAt) {
      const os = server.os && server.os.id ? ` on ${escapeMarkdown([server.os.id, server.os.versionId].filter(Boolean).join(' '))}` : '';
      lines.push(`Evidence collected at ${escapeMarkdown(server.collectedAt)} by attester ${escapeMarkdown(server.attesterVersion)}${os}, backed by ${escapeMarkdown(levelText(server.level))}.`, '');
    }

    const services = serviceLines(report, server);
    if (services.length > 0) {
      lines.push(...services, '');
    }

    for (const severity of ['fail', 'error', 'warn', 'info']) {
      for (const finding of server.findings.filter(item => item.severity === severity)) {
        const where = finding.service ? `${escapeMarkdown(finding.service)} ` : '';
        lines.push(`* **${severity}** (${where}${escapeMarkdown(finding.check)}): ${escapeMarkdown(finding.message)}`);
        const items = finding.detail && Array.isArray(finding.detail.items) ? finding.detail.items : packageItems(finding.detail);
        if (items) {
          for (const item of items) {
            lines.push(`  * \`${String(item).replaceAll('`', '\'').replaceAll(CONTROL_CHARACTERS, ' ')}\``);
          }

          if (finding.detail.total > items.length) {
            lines.push(`  * … and ${finding.detail.total - items.length} more`);
          }
        }
      }
    }
  }

  lines.push(
    '',
    '---',
    '',
    'Each server is compared with references the verifier fetches itself: the public commit (or an attested release), reproduced builds, the packages its lockfiles pin, container images by digest, official runtime releases and the signed distribution archive. "Software evidence" can be defeated by an attacker with root on the server. A TPM proves which machine answered and how it booted; with IMA, files the kernel measured are also tamper-evident, even to root. A confidential VM protects the server from its host, not from root inside it. See [Audit Status](https://github.com/auditstatus/auditstatus.com) and [Attestium](https://github.com/attestium/attestium.com) for details.',
    '',
  );
  return lines.join('\n');
}

/**
 * Write report.json, report.md and badge.json.
 *
 * @param {Object} report
 * @param {string} dir
 * @param {Object} [options]
 * @param {string} [options.label]
 * @returns {{json: string, markdown: string, badge: string}}
 */
function writeReport(report, dir, options = {}) {
  fs.mkdirSync(dir, {recursive: true});
  const files = {
    json: path.join(dir, 'report.json'),
    markdown: path.join(dir, 'report.md'),
    badge: path.join(dir, 'badge.json'),
  };
  fs.writeFileSync(files.json, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(files.markdown, markdown(report));
  fs.writeFileSync(files.badge, `${JSON.stringify(badge(report, options.label))}\n`);
  return files;
}

module.exports = {
  VERSION,
  STATUS_TEXT,
  STATUS_ICON,
  levelText,
  weakestLevel,
  badge,
  markdown,
  writeReport,
  escapeMarkdown,
};
