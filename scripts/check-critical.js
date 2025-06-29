#!/usr/bin/env node

/**
 * Check for critical security issues in audit results
 */

const fs = require('node:fs');
const {program} = require('commander');

function checkCriticalIssues(auditResults) {
	const criticalThresholds = {
		maxFailedServers: 1,
		maxChecksumMismatches: 0,
		maxMissingFiles: 0,
	};

	const issues = [];

	// Check failed servers
	if (auditResults.summary.failedServers > criticalThresholds.maxFailedServers) {
		issues.push({
			type: 'failed_servers',
			severity: 'CRITICAL',
			count: auditResults.summary.failedServers,
			threshold: criticalThresholds.maxFailedServers,
			message: `${auditResults.summary.failedServers} servers failed verification (threshold: ${criticalThresholds.maxFailedServers})`,
		});
	}

	// Check for checksum mismatches
	const checksumMismatches = auditResults.discrepancies.filter(d => d.type === 'checksum_mismatch');
	if (checksumMismatches.length > criticalThresholds.maxChecksumMismatches) {
		issues.push({
			type: 'checksum_mismatches',
			severity: 'CRITICAL',
			count: checksumMismatches.length,
			threshold: criticalThresholds.maxChecksumMismatches,
			message: `${checksumMismatches.length} checksum mismatches detected (threshold: ${criticalThresholds.maxChecksumMismatches})`,
		});
	}

	// Check for missing files
	const missingFiles = auditResults.discrepancies.filter(d => d.type === 'missing_file');
	if (missingFiles.length > criticalThresholds.maxMissingFiles) {
		issues.push({
			type: 'missing_files',
			severity: 'CRITICAL',
			count: missingFiles.length,
			threshold: criticalThresholds.maxMissingFiles,
			message: `${missingFiles.length} missing files detected (threshold: ${criticalThresholds.maxMissingFiles})`,
		});
	}

	return {
		hasCriticalIssues: issues.length > 0,
		issues,
		summary: {
			totalIssues: issues.length,
			criticalIssues: issues.filter(i => i.severity === 'CRITICAL').length,
		},
	};
}

async function main() {
	program
		.name('check-critical')
		.description('Check audit results for critical security issues')
		.option('-i, --input <file>', 'Input audit results file', 'audit-results.json')
		.option('-o, --output <file>', 'Output file for critical issues')
		.option('--exit-code', 'Exit with error code if critical issues found')
		.parse();

	const options = program.opts();

	try {
		const auditResults = JSON.parse(fs.readFileSync(options.input, 'utf8'));
		const criticalCheck = checkCriticalIssues(auditResults);

		if (options.output) {
			fs.writeFileSync(options.output, JSON.stringify(criticalCheck, null, 2));
		}

		// Output for GitHub Actions
		console.log(criticalCheck.hasCriticalIssues ? 'true' : 'false');

		if (criticalCheck.hasCriticalIssues) {
			console.error('Critical issues detected:');
			for (const issue of criticalCheck.issues) {
				console.error(`- ${issue.message}`);
			}
		}

		if (options.exitCode && criticalCheck.hasCriticalIssues) {
			process.exit(1);
		}
	} catch (error) {
		console.error(`Error checking critical issues: ${error.message}`);
		process.exit(1);
	}
}

if (require.main === module) {
	main();
}

module.exports = {checkCriticalIssues};

