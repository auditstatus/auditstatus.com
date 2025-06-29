#!/usr/bin/env node

/**
 * Format audit results summary for GitHub Actions output
 */

const fs = require('node:fs');
const {program} = require('commander');

function formatSummary(auditResults) {
	const {summary} = auditResults;
	const timestamp = new Date(auditResults.timestamp).toLocaleString();

	let output = '';

	// Status emoji
	const statusEmoji = summary.allVerified ? '✅' : '❌';

	output += `${statusEmoji} **Status**: ${summary.allVerified ? 'All servers verified' : 'Issues detected'}\\n`;
	output += `📊 **Servers**: ${summary.verifiedServers}/${summary.totalServers} verified\\n`;

	if (summary.failedServers > 0) {
		output += `⚠️ **Failed**: ${summary.failedServers} servers\\n`;
	}

	if (summary.unreachableServers > 0) {
		output += `🌐 **Unreachable**: ${summary.unreachableServers} servers\\n`;
	}

	if (auditResults.discrepancies.length > 0) {
		output += `🔍 **Discrepancies**: ${auditResults.discrepancies.length} found\\n`;

		// Group discrepancies by type
		const discrepancyTypes = {};
		for (const discrepancy of auditResults.discrepancies) {
			discrepancyTypes[discrepancy.type] = (discrepancyTypes[discrepancy.type] || 0) + 1;
		}

		for (const [type, count] of Object.entries(discrepancyTypes)) {
			const typeEmoji = {
				checksum_mismatch: '🔴',
				missing_file: '📁',
				extra_file: '📄',
				server_unreachable: '🌐',
			}[type] || '⚠️';

			const typeName = type.replace('_', ' ').replaceAll(String.raw`\b\w`, l => l.toUpperCase());
			output += `   ${typeEmoji} ${typeName}: ${count}\\n`;
		}
	}

	output += String.raw`\n`;
	output += `**Commit**: \`${auditResults.commitHash?.slice(0, 8) || 'unknown'}\`\\n`;
	output += `**Time**: ${timestamp}\\n`;

	if (auditResults.commitInfo) {
		output += `**Message**: ${auditResults.commitInfo.message}\\n`;
		output += `**Author**: ${auditResults.commitInfo.author}\\n`;
	}

	// Add server details
	output += String.raw`\n### Server Details\n\n`;
	output += String.raw`| Server | Status | Files | Issues |\n`;
	output += String.raw`|--------|--------|-------|--------|\n`;

	for (const server of auditResults.servers) {
		const statusIcon = server.verified ? '✅' : (server.error ? '🔴' : '⚠️');
		const filesInfo = server.summary ? `${server.summary.matchingFiles}/${server.summary.totalExpectedFiles}` : 'N/A';
		const issuesCount = server.discrepancies ? server.discrepancies.length : 0;
		const issuesText = issuesCount > 0 ? `${issuesCount} issues` : 'None';

		output += `| ${server.server} | ${statusIcon} | ${filesInfo} | ${issuesText} |\\n`;
	}

	// Add recommendations if any
	if (auditResults.recommendations && auditResults.recommendations.length > 0) {
		output += String.raw`\n### Recommendations\n\n`;
		for (const recommendation of auditResults.recommendations) {
			output += `${recommendation}\\n`;
		}
	}

	return output;
}

async function main() {
	program
		.name('format-summary')
		.description('Format audit results summary for GitHub Actions')
		.option('-i, --input <file>', 'Input audit results file', 'audit-results.json')
		.option('-o, --output <file>', 'Output file for formatted summary')
		.parse();

	const options = program.opts();

	try {
		const auditResults = JSON.parse(fs.readFileSync(options.input, 'utf8'));
		const formattedSummary = formatSummary(auditResults);

		if (options.output) {
			fs.writeFileSync(options.output, formattedSummary);
		} else {
			console.log(formattedSummary);
		}
	} catch (error) {
		console.error(`Error formatting summary: ${error.message}`);
		process.exit(1);
	}
}

if (require.main === module) {
	main();
}

module.exports = {formatSummary};

