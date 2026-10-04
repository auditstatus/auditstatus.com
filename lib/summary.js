/**
 * Audit Status - a local summary of evidence (`auditstatus check`)
 *
 * For operators on the server: what the attester sees, and findings it can
 * judge without references.  It is not a verification; the verifier
 * compares evidence with public references from another machine.
 *
 * @license MIT
 */

'use strict';

/**
 * @param {Object} evidence
 * @returns {Object}
 */
function summarize(evidence) {
  const critical = [];
  const warnings = [];
  const incomplete = [];
  const services = [];
  const inspect = (label, processes) => {
    for (const proc of processes) {
      for (const finding of proc.integrity.findings) {
        if (finding.severity === 'critical') {
          critical.push({where: label, pid: proc.pid, ...finding});
        } else if (finding.severity === 'warning') {
          warnings.push({where: label, pid: proc.pid, ...finding});
        }
      }

      for (const item of proc.integrity.incomplete) {
        incomplete.push({where: label, pid: proc.pid, ...item});
      }
    }
  };

  for (const service of evidence.services) {
    if (service.kind === 'directory') {
      inspect(service.name, service.processes);
      services.push({
        name: service.name,
        kind: 'directory',
        root: service.realRoot,
        commit: service.git.commit,
        manifest: Boolean(service.manifest),
        files: service.fileCount,
        fileErrors: service.errors.length,
        installs: service.installs.map(install => ({ecosystem: install.ecosystem, dir: install.dir, packages: install.packages.length})),
        processes: service.processes.map(proc => ({pid: proc.pid, exe: proc.exe, runtime: proc.runtime ? proc.runtime.label : null})),
      });
    } else {
      for (const container of service.containers) {
        inspect(`${service.name}/${container.name || container.id.slice(0, 12)}`, container.processes);
      }

      services.push({
        name: service.name,
        kind: 'container',
        containers: service.containers.map(container => ({
          id: container.id.slice(0, 12), name: container.name, image: container.image ? container.image.reference : null, processes: container.processes.length, changed: container.upper ? Object.keys(container.upper.files).length + container.upper.deleted.length : null,
        })),
      });
    }
  }

  const hardware = [];
  if (evidence.tpm && evidence.tpm.quote) {
    hardware.push('TPM quote');
  }

  if (evidence.confidential && evidence.confidential.report) {
    hardware.push(`confidential VM report (${evidence.confidential.provider})`);
  }

  if (evidence.ima && evidence.ima.log) {
    hardware.push('IMA log');
  }

  return {
    host: evidence.host.hostname,
    os: evidence.host.os,
    services,
    executables: evidence.executables.length,
    libraries: evidence.libraries.length,
    ownedByPackages: [...evidence.executables, ...evidence.libraries].filter(item => item.package).length,
    hardware,
    tpm: evidence.tpm && !evidence.tpm.quote ? (evidence.tpm.reason || evidence.tpm.error || (evidence.tpm.enabled === false ? 'disabled' : null)) : null,
    monitor: evidence.monitor ? (evidence.monitor.error ? `error: ${evidence.monitor.error}` : `${evidence.monitor.execs.length} programs, ${evidence.monitor.maps.length} libraries since ${evidence.monitor.since || 'the window start'}`) : 'off',
    criticalFindings: critical.length,
    incomplete,
    findings: [...critical, ...warnings],
  };
}

/**
 * @param {Object} summary
 * @returns {string}
 */
function formatSummary(summary) {
  const lines = [`Host: ${summary.host}${summary.os && summary.os.id ? ` (${[summary.os.id, summary.os.versionId].filter(Boolean).join(' ')})` : ''}`];
  for (const service of summary.services) {
    if (service.kind === 'directory') {
      lines.push(`Service ${service.name}: ${service.root}`, `  ${service.manifest ? 'Release manifest present' : `Commit: ${service.commit || 'unknown (not a git checkout?)'}`}`, `  Files hashed: ${service.files}${service.fileErrors > 0 ? ` (${service.fileErrors} unreadable)` : ''}`);
      for (const install of service.installs) {
        lines.push(`  ${install.ecosystem} packages in ${install.dir}: ${install.packages}`);
      }

      lines.push(`  Processes: ${service.processes.length === 0 ? 'none found (check user and root in the configuration)' : service.processes.map(proc => `${proc.pid} ${proc.runtime || proc.exe}`).join(', ')}`);
    } else {
      lines.push(`Service ${service.name}: ${service.containers.length} container(s)`);
      for (const container of service.containers) {
        lines.push(`  ${container.name || container.id} ${container.image || ''}: ${container.processes} process(es)${container.changed === null ? '' : `, ${container.changed} change(s) in the writable layer`}`);
      }
    }
  }

  lines.push(
    `Executables and libraries hashed: ${summary.executables + summary.libraries} (${summary.ownedByPackages} owned by distribution packages)`,
    `Hardware evidence: ${summary.hardware.length > 0 ? summary.hardware.join(', ') : `none${summary.tpm ? ` (TPM: ${summary.tpm})` : ''}`}`,
    `Monitor: ${summary.monitor}`,
  );
  if (summary.findings.length === 0) {
    lines.push('Process findings: none');
  } else {
    lines.push('Process findings:');
    for (const finding of summary.findings) {
      lines.push(`  [${finding.severity}] ${finding.where} pid ${finding.pid} ${finding.type}: ${typeof finding.detail === 'string' ? finding.detail : JSON.stringify(finding.detail)}`);
    }
  }

  if (summary.incomplete.length > 0) {
    lines.push('Checks that could not run (missing permissions? run "auditstatus doctor"):');
    for (const item of summary.incomplete) {
      lines.push(`  ${item.where} pid ${item.pid} ${item.check}: ${item.error}`);
    }
  }

  lines.push('', 'This is a local summary. Run "auditstatus verify" from another machine to compare with public references.');
  return lines.join('\n');
}

module.exports = {summarize, formatSummary};
