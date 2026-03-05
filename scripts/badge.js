#!/usr/bin/env node

/**
 * Audit Status - Badge Generator
 *
 * Generates Shields.io-compatible JSON badge endpoints for audit status.
 * Reads the latest audit report and outputs badge JSON.
 *
 * Usage:
 *   node scripts/badge.js [--output badge.json]
 *
 * The output JSON can be served as a static file or API endpoint
 * for use with Shields.io endpoint badges:
 *   https://img.shields.io/endpoint?url=<your-badge-json-url>
 *
 * @author Forward Email <support@forwardemail.net>
 * @license MIT
 */

const fs = require('node:fs');
const path = require('node:path');

class BadgeGenerator {
  constructor(options = {}) {
    this.outputDir = options.outputDir || path.join(process.cwd(), 'audit-reports');
    this.outputFile = options.outputFile || null;
  }

  /**
	 * Read the latest audit report.
	 */
  getLatestReport() {
    try {
      const latestPath = path.join(this.outputDir, 'latest-audit-report.json');
      if (fs.existsSync(latestPath)) {
        return JSON.parse(fs.readFileSync(latestPath, 'utf8'));
      }
    } catch {
      // Fall through to scan directory
    }

    try {
      const files = fs.readdirSync(this.outputDir)
        .filter(f => f.startsWith('audit-report-') && f.endsWith('.json'))
        .sort()
        .reverse();

      if (files.length > 0) {
        return JSON.parse(fs.readFileSync(path.join(this.outputDir, files[0]), 'utf8'));
      }
    } catch {
      // No reports found
    }

    return null;
  }

  /**
	 * Generate Shields.io endpoint badge JSON.
	 */
  generate(report) {
    if (!report) {
      return {
        schemaVersion: 1,
        label: 'audit status',
        message: 'unknown',
        color: 'lightgrey',
      };
    }

    const summary = report.summary || {};
    const total = summary.totalServers || 0;
    const passed = summary.successfulAudits || 0;
    const failed = summary.failedAudits || 0;

    let message;
    let color;

    if (failed === 0 && total > 0) {
      message = 'passing';
      color = 'brightgreen';
    } else if (failed > 0 && passed > 0) {
      message = `${passed}/${total} passing`;
      color = 'yellow';
    } else if (total === 0) {
      message = 'no servers';
      color = 'lightgrey';
    } else {
      message = 'failing';
      color = 'red';
    }

    return {
      schemaVersion: 1,
      label: 'audit status',
      message,
      color,
    };
  }

  /**
	 * Generate and optionally write badge JSON.
	 */
  run() {
    const report = this.getLatestReport();
    const badge = this.generate(report);

    if (this.outputFile) {
      const outputPath = path.resolve(this.outputFile);
      fs.mkdirSync(path.dirname(outputPath), {recursive: true});
      fs.writeFileSync(outputPath, JSON.stringify(badge, null, 2));
    }

    return badge;
  }
}

/* c8 ignore start */
if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {};

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output') {
      options.outputFile = args[++i];
    } else if (args[i] === '--dir') {
      options.outputDir = args[++i];
    }
  }

  const gen = new BadgeGenerator(options);
  const badge = gen.run();
  console.log(JSON.stringify(badge, null, 2));
}
/* c8 ignore stop */

module.exports = BadgeGenerator;
