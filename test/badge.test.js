const {describe, it, before, after} = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const BadgeGenerator = require('../scripts/badge.js');

describe('BadgeGenerator', () => {
  let temporaryDir;

  before(() => {
    temporaryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'badge-'));
  });

  after(() => {
    fs.rmSync(temporaryDir, {recursive: true, force: true});
  });

  describe('constructor', () => {
    it('uses defaults', () => {
      const gen = new BadgeGenerator();
      assert.ok(gen.outputDir);
      assert.strictEqual(gen.outputFile, null);
    });

    it('accepts options', () => {
      const gen = new BadgeGenerator({
        outputDir: '/tmp/reports',
        outputFile: '/tmp/badge.json',
      });
      assert.strictEqual(gen.outputDir, '/tmp/reports');
      assert.strictEqual(gen.outputFile, '/tmp/badge.json');
    });
  });

  describe('getLatestReport', () => {
    it('returns null when no reports exist', () => {
      const gen = new BadgeGenerator({outputDir: temporaryDir});
      const report = gen.getLatestReport();
      assert.strictEqual(report, null);
    });

    it('reads latest-audit-report.json when available', () => {
      const reportData = {
        summary: {totalServers: 2, successfulAudits: 2, failedAudits: 0},
      };
      fs.writeFileSync(
        path.join(temporaryDir, 'latest-audit-report.json'),
        JSON.stringify(reportData),
      );
      const gen = new BadgeGenerator({outputDir: temporaryDir});
      const report = gen.getLatestReport();
      assert.deepStrictEqual(report, reportData);
      fs.unlinkSync(path.join(temporaryDir, 'latest-audit-report.json'));
    });

    it('falls back to scanning audit-report-* files', () => {
      const reportData = {
        summary: {totalServers: 1, successfulAudits: 1, failedAudits: 0},
      };
      fs.writeFileSync(
        path.join(temporaryDir, 'audit-report-2026-01-01.json'),
        JSON.stringify(reportData),
      );
      fs.writeFileSync(
        path.join(temporaryDir, 'audit-report-2026-01-02.json'),
        JSON.stringify({summary: {totalServers: 3, successfulAudits: 3, failedAudits: 0}}),
      );
      const gen = new BadgeGenerator({outputDir: temporaryDir});
      const report = gen.getLatestReport();
      // Should get the latest (sorted reverse)
      assert.strictEqual(report.summary.totalServers, 3);
      fs.unlinkSync(path.join(temporaryDir, 'audit-report-2026-01-01.json'));
      fs.unlinkSync(path.join(temporaryDir, 'audit-report-2026-01-02.json'));
    });

    it('handles corrupt latest-audit-report.json gracefully', () => {
      fs.writeFileSync(path.join(temporaryDir, 'latest-audit-report.json'), 'not json');
      const gen = new BadgeGenerator({outputDir: temporaryDir});
      const report = gen.getLatestReport();
      // Should fall through to directory scan, which finds nothing
      assert.strictEqual(report, null);
      fs.unlinkSync(path.join(temporaryDir, 'latest-audit-report.json'));
    });

    it('returns null for non-existent directory', () => {
      const gen = new BadgeGenerator({outputDir: '/nonexistent/path/xyz'});
      const report = gen.getLatestReport();
      assert.strictEqual(report, null);
    });
  });

  describe('generate', () => {
    it('returns unknown badge when no report', () => {
      const gen = new BadgeGenerator();
      const badge = gen.generate(null);
      assert.strictEqual(badge.schemaVersion, 1);
      assert.strictEqual(badge.label, 'audit status');
      assert.strictEqual(badge.message, 'unknown');
      assert.strictEqual(badge.color, 'lightgrey');
    });

    it('returns passing badge when all audits pass', () => {
      const gen = new BadgeGenerator();
      const badge = gen.generate({
        summary: {totalServers: 3, successfulAudits: 3, failedAudits: 0},
      });
      assert.strictEqual(badge.message, 'passing');
      assert.strictEqual(badge.color, 'brightgreen');
    });

    it('returns partial badge when some audits fail', () => {
      const gen = new BadgeGenerator();
      const badge = gen.generate({
        summary: {totalServers: 3, successfulAudits: 2, failedAudits: 1},
      });
      assert.strictEqual(badge.message, '2/3 passing');
      assert.strictEqual(badge.color, 'yellow');
    });

    it('returns failing badge when all audits fail', () => {
      const gen = new BadgeGenerator();
      const badge = gen.generate({
        summary: {totalServers: 3, successfulAudits: 0, failedAudits: 3},
      });
      assert.strictEqual(badge.message, 'failing');
      assert.strictEqual(badge.color, 'red');
    });

    it('returns no servers badge when total is 0', () => {
      const gen = new BadgeGenerator();
      const badge = gen.generate({
        summary: {totalServers: 0, successfulAudits: 0, failedAudits: 0},
      });
      assert.strictEqual(badge.message, 'no servers');
      assert.strictEqual(badge.color, 'lightgrey');
    });

    it('handles report with missing summary', () => {
      const gen = new BadgeGenerator();
      const badge = gen.generate({});
      assert.strictEqual(badge.message, 'no servers');
      assert.strictEqual(badge.color, 'lightgrey');
    });
  });

  describe('run', () => {
    it('generates badge without writing file', () => {
      const gen = new BadgeGenerator({outputDir: temporaryDir});
      const badge = gen.run();
      assert.strictEqual(badge.schemaVersion, 1);
      assert.strictEqual(badge.label, 'audit status');
    });

    it('writes badge to output file', () => {
      const reportData = {
        summary: {totalServers: 1, successfulAudits: 1, failedAudits: 0},
      };
      fs.writeFileSync(
        path.join(temporaryDir, 'latest-audit-report.json'),
        JSON.stringify(reportData),
      );

      const outputFile = path.join(temporaryDir, 'output', 'badge.json');
      const gen = new BadgeGenerator({
        outputDir: temporaryDir,
        outputFile,
      });
      const badge = gen.run();
      assert.strictEqual(badge.message, 'passing');

      // Verify file was written
      const written = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
      assert.deepStrictEqual(written, badge);

      fs.unlinkSync(path.join(temporaryDir, 'latest-audit-report.json'));
      fs.rmSync(path.join(temporaryDir, 'output'), {recursive: true, force: true});
    });
  });
});
