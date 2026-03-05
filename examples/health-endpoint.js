/**
 * Audit Status - Health Endpoint Example
 *
 * Exposes /health/audit as an HTTP endpoint for Upptime monitoring.
 * Returns 200 when the last audit passed, 503 when it failed.
 *
 * Works with Express, Koa, Fastify, or any HTTP framework.
 *
 * @example
 *   // Express
 *   const express = require('express');
 *   const { auditHealthMiddleware } = require('auditstatus/examples/health-endpoint');
 *   const app = express();
 *   app.get('/health/audit', auditHealthMiddleware());
 *
 *   // Standalone
 *   const http = require('http');
 *   const { handleAuditHealth } = require('auditstatus/examples/health-endpoint');
 *   http.createServer((req, res) => {
 *     if (req.url === '/health/audit') return handleAuditHealth(req, res);
 *     res.end('ok');
 *   }).listen(3000);
 */

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_REPORT_DIR = path.join(process.cwd(), 'audit-reports');

function getLatestAuditResult(reportDir) {
  const dir = reportDir || DEFAULT_REPORT_DIR;

  try {
    const latestPath = path.join(dir, 'latest-audit-report.json');
    if (fs.existsSync(latestPath)) {
      const report = JSON.parse(fs.readFileSync(latestPath, 'utf8'));
      return {
        ok: (report.summary?.failedAudits || 0) === 0,
        report,
      };
    }
  } catch {
    // Fall through
  }

  try {
    const files = fs.readdirSync(dir)
      .filter(f => f.startsWith('audit-report-') && f.endsWith('.json'))
      .sort()
      .reverse();

    if (files.length > 0) {
      const report = JSON.parse(fs.readFileSync(path.join(dir, files[0]), 'utf8'));
      return {
        ok: (report.summary?.failedAudits || 0) === 0,
        report,
      };
    }
  } catch {
    // No reports
  }

  return {ok: false, report: null};
}

/**
 * Raw HTTP handler for /health/audit.
 */
function handleAuditHealth(request, response, options = {}) {
  const result = getLatestAuditResult(options.reportDir);
  const status = result.ok ? 200 : 503;
  const body = JSON.stringify({
    status: result.ok ? 'passing' : 'failing',
    timestamp: new Date().toISOString(),
    summary: result.report?.summary || null,
  });

  response.writeHead(status, {'Content-Type': 'application/json'});
  response.end(body);
}

/**
 * Express/Connect middleware for /health/audit.
 */
function auditHealthMiddleware(options = {}) {
  return (request, response) => handleAuditHealth(request, response, options);
}

module.exports = {getLatestAuditResult, handleAuditHealth, auditHealthMiddleware};
