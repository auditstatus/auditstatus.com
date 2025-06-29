#!/usr/bin/env node

/**
 * Configuration Validation Script
 *
 * Validates the YAML configuration file for Audit Status
 */

const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');
const {program} = require('commander');

class ConfigValidator {
	constructor() {
		this.errors = [];
		this.warnings = [];
		this.info = [];
	}

	/**
   * Validate configuration file
   */
	validateConfig(configPath) {
		const defaultConfigPath = path.join(process.cwd(), 'auditor.config.yml');
		const finalConfigPath = configPath || defaultConfigPath;

		console.log(`Validating configuration: ${finalConfigPath}`);

		try {
			// Check if file exists
			if (!fs.existsSync(finalConfigPath)) {
				this.errors.push(`Configuration file not found: ${finalConfigPath}`);
				return false;
			}

			// Parse YAML
			const configContent = fs.readFileSync(finalConfigPath, 'utf8');
			let config;

			try {
				config = YAML.parse(configContent);
			} catch (parseError) {
				this.errors.push(`YAML parsing error: ${parseError.message}`);
				return false;
			}

			// Validate structure
			this.validateStructure(config);
			this.validateServers(config.servers || []);
			this.validateRepository(config.repository || {});
			this.validateVerification(config.verification || {});
			this.validateAlerts(config.alerts || {});
			this.validatePerformance(config.performance || {});
			this.validateReporting(config.reporting || {});
			this.validateSecurity(config.security || {});

			// Print results
			this.printResults();

			return this.errors.length === 0;
		} catch (error) {
			this.errors.push(`Validation error: ${error.message}`);
			this.printResults();
			return false;
		}
	}

	/**
   * Validate basic structure
   */
	validateStructure(config) {
		const required = ['servers'];
		const missing = required.filter(key => !config[key]);

		if (missing.length > 0) {
			this.errors.push(`Missing required sections: ${missing.join(', ')}`);
		}

		if (config.auditor) {
			if (!config.auditor.name) {
				this.warnings.push('Auditor name not specified');
			}

			if (!config.auditor.version) {
				this.warnings.push('Auditor version not specified');
			}
		} else {
			this.warnings.push('Auditor section not configured');
		}
	}

	/**
   * Validate servers configuration
   */
	validateServers(servers) {
		if (!Array.isArray(servers)) {
			this.errors.push('Servers must be an array');
			return;
		}

		if (servers.length === 0) {
			this.errors.push('At least one server must be configured');
			return;
		}

		const enabledServers = servers.filter(server => server.enabled !== false);
		if (enabledServers.length === 0) {
			this.warnings.push('No servers are enabled for auditing');
		}

		for (const [index, server] of servers.entries()) {
			this.validateServer(server, index);
		}

		this.info.push(`Total servers configured: ${servers.length}`, `Enabled servers: ${enabledServers.length}`);
	}

	/**
   * Validate individual server
   */
	validateServer(server, index) {
		const serverName = server.name || `Server ${index}`;

		// Required fields
		if (!server.name) {
			this.errors.push(`${serverName}: Missing required field 'name'`);
		}

		if (!server.url) {
			this.errors.push(`${serverName}: Missing required field 'url'`);
		}

		// URL validation
		if (server.url) {
			try {
				new URL(server.url);
			} catch {
				this.errors.push(`${serverName}: Invalid URL format: ${server.url}`);
			}
		}

		// Server type validation
		const validTypes = ['web', 'api', 'smtp', 'imap', 'pop3', 'proxy'];
		if (server.type && !validTypes.includes(server.type)) {
			this.warnings.push(`${serverName}: Invalid server type '${server.type}'. Valid types: ${validTypes.join(', ')}`);
		}

		// Priority validation
		const validPriorities = ['critical', 'high', 'medium', 'low'];
		if (server.priority && !validPriorities.includes(server.priority)) {
			this.warnings.push(`${serverName}: Invalid priority '${server.priority}'. Valid priorities: ${validPriorities.join(', ')}`);
		}

		// Environment validation
		const validEnvironments = ['production', 'staging', 'development', 'test'];
		if (server.environment && !validEnvironments.includes(server.environment)) {
			this.warnings.push(`${serverName}: Invalid environment '${server.environment}'. Valid environments: ${validEnvironments.join(', ')}`);
		}

		// Timeout validation
		if (server.timeout && (typeof server.timeout !== 'number' || server.timeout <= 0)) {
			this.warnings.push(`${serverName}: Invalid timeout value. Must be a positive number`);
		}

		// Retry attempts validation
		if (server.retry_attempts && (typeof server.retry_attempts !== 'number' || server.retry_attempts < 0)) {
			this.warnings.push(`${serverName}: Invalid retry_attempts value. Must be a non-negative number`);
		}

		// Expected status codes validation
		if (server.expected_status_codes) {
			if (Array.isArray(server.expected_status_codes)) {
				const invalidCodes = server.expected_status_codes.filter(code =>
					typeof code !== 'number' || code < 100 || code > 599);
				if (invalidCodes.length > 0) {
					this.warnings.push(`${serverName}: Invalid HTTP status codes: ${invalidCodes.join(', ')}`);
				}
			} else {
				this.warnings.push(`${serverName}: expected_status_codes must be an array`);
			}
		}
	}

	/**
   * Validate repository configuration
   */
	validateRepository(repository) {
		if (repository.name) {
			// Validate GitHub repository format
			const repoPattern = /^[\w.-]+\/[\w.-]+$/;
			if (!repoPattern.test(repository.name)) {
				this.warnings.push(`Repository name '${repository.name}' doesn't match GitHub format (owner/repo)`);
			}
		} else {
			this.warnings.push('Repository name not specified');
		}

		if (!repository.branch) {
			this.warnings.push('Repository branch not specified, defaulting to "main"');
		}

		if (repository.depth && (typeof repository.depth !== 'number' || repository.depth <= 0)) {
			this.warnings.push('Repository depth must be a positive number');
		}

		if (repository.timeout && (typeof repository.timeout !== 'number' || repository.timeout <= 0)) {
			this.warnings.push('Repository timeout must be a positive number');
		}
	}

	/**
   * Validate verification configuration
   */
	validateVerification(verification) {
		if (verification.include_patterns && !Array.isArray(verification.include_patterns)) {
			this.warnings.push('Verification include_patterns must be an array');
		}

		if (verification.exclude_patterns && !Array.isArray(verification.exclude_patterns)) {
			this.warnings.push('Verification exclude_patterns must be an array');
		}

		const validAlgorithms = ['sha256', 'sha512', 'md5'];
		if (verification.checksum_algorithm && !validAlgorithms.includes(verification.checksum_algorithm)) {
			this.warnings.push(`Invalid checksum algorithm '${verification.checksum_algorithm}'. Valid algorithms: ${validAlgorithms.join(', ')}`);
		}

		if (verification.max_file_size && (typeof verification.max_file_size !== 'number' || verification.max_file_size <= 0)) {
			this.warnings.push('max_file_size must be a positive number');
		}

		if (verification.max_files_per_server && (typeof verification.max_files_per_server !== 'number' || verification.max_files_per_server <= 0)) {
			this.warnings.push('max_files_per_server must be a positive number');
		}
	}

	/**
   * Validate alerts configuration
   */
	validateAlerts(alerts) {
		const validSeverities = ['critical', 'high', 'medium', 'low'];
		if (alerts.severity_levels) {
			if (Array.isArray(alerts.severity_levels)) {
				const invalidSeverities = alerts.severity_levels.filter(level => !validSeverities.includes(level));
				if (invalidSeverities.length > 0) {
					this.warnings.push(`Invalid severity levels: ${invalidSeverities.join(', ')}. Valid levels: ${validSeverities.join(', ')}`);
				}
			} else {
				this.warnings.push('Alert severity_levels must be an array');
			}
		}

		if (alerts.github_issues) {
			if (alerts.github_issues.labels && !Array.isArray(alerts.github_issues.labels)) {
				this.warnings.push('GitHub issues labels must be an array');
			}

			if (alerts.github_issues.assignees && !Array.isArray(alerts.github_issues.assignees)) {
				this.warnings.push('GitHub issues assignees must be an array');
			}
		}

		if (alerts.email && alerts.email.enabled) {
			if (!alerts.email.smtp_host) {
				this.warnings.push('Email alerts enabled but smtp_host not configured');
			}

			if (!alerts.email.from_email) {
				this.warnings.push('Email alerts enabled but from_email not configured');
			}

			if (!alerts.email.to_emails || !Array.isArray(alerts.email.to_emails) || alerts.email.to_emails.length === 0) {
				this.warnings.push('Email alerts enabled but to_emails not properly configured');
			}
		}
	}

	/**
   * Validate performance configuration
   */
	validatePerformance(performance) {
		if (performance.request_timeout && (typeof performance.request_timeout !== 'number' || performance.request_timeout <= 0)) {
			this.warnings.push('Performance request_timeout must be a positive number');
		}

		if (performance.max_concurrent_audits && (typeof performance.max_concurrent_audits !== 'number' || performance.max_concurrent_audits <= 0)) {
			this.warnings.push('Performance max_concurrent_audits must be a positive number');
		}

		if (performance.audit_delay && (typeof performance.audit_delay !== 'number' || performance.audit_delay < 0)) {
			this.warnings.push('Performance audit_delay must be a non-negative number');
		}

		if (performance.retry) {
			if (performance.retry.max_attempts && (typeof performance.retry.max_attempts !== 'number' || performance.retry.max_attempts < 0)) {
				this.warnings.push('Retry max_attempts must be a non-negative number');
			}

			if (performance.retry.base_delay && (typeof performance.retry.base_delay !== 'number' || performance.retry.base_delay <= 0)) {
				this.warnings.push('Retry base_delay must be a positive number');
			}

			if (performance.retry.max_delay && (typeof performance.retry.max_delay !== 'number' || performance.retry.max_delay <= 0)) {
				this.warnings.push('Retry max_delay must be a positive number');
			}
		}
	}

	/**
   * Validate reporting configuration
   */
	validateReporting(reporting) {
		const validFormats = ['json', 'markdown', 'html'];
		if (reporting.formats) {
			if (Array.isArray(reporting.formats)) {
				const invalidFormats = reporting.formats.filter(format => !validFormats.includes(format));
				if (invalidFormats.length > 0) {
					this.warnings.push(`Invalid report formats: ${invalidFormats.join(', ')}. Valid formats: ${validFormats.join(', ')}`);
				}
			} else {
				this.warnings.push('Reporting formats must be an array');
			}
		}

		if (reporting.storage && reporting.storage.retention_days && (typeof reporting.storage.retention_days !== 'number' || reporting.storage.retention_days <= 0)) {
			this.warnings.push('Storage retention_days must be a positive number');
		}

		if (reporting.dashboard && reporting.dashboard.max_history_entries && (typeof reporting.dashboard.max_history_entries !== 'number' || reporting.dashboard.max_history_entries <= 0)) {
			this.warnings.push('Dashboard max_history_entries must be a positive number');
		}
	}

	/**
   * Validate security configuration
   */
	validateSecurity(security) {
		if (security.request_signing && security.request_signing.algorithm) {
			const validAlgorithms = ['sha256', 'sha512', 'md5'];
			if (!validAlgorithms.includes(security.request_signing.algorithm)) {
				this.warnings.push(`Invalid request signing algorithm '${security.request_signing.algorithm}'. Valid algorithms: ${validAlgorithms.join(', ')}`);
			}
		}

		if (security.nonce) {
			if (security.nonce.length > 0 && (typeof security.nonce.length !== 'number' || security.nonce.length <= 0)) {
				this.warnings.push('Nonce length must be a positive number');
			}

			const validAlgorithms = ['random', 'timestamp', 'counter'];
			if (security.nonce.algorithm && !validAlgorithms.includes(security.nonce.algorithm)) {
				this.warnings.push(`Invalid nonce algorithm '${security.nonce.algorithm}'. Valid algorithms: ${validAlgorithms.join(', ')}`);
			}
		}
	}

	/**
   * Print validation results
   */
	printResults() {
		console.log('\n=== Configuration Validation Results ===\n');

		if (this.errors.length > 0) {
			console.log('❌ ERRORS:');
			for (const error of this.errors) {
				console.log(`   ${error}`);
			}

			console.log('');
		}

		if (this.warnings.length > 0) {
			console.log('⚠️  WARNINGS:');
			for (const warning of this.warnings) {
				console.log(`   ${warning}`);
			}

			console.log('');
		}

		if (this.info.length > 0) {
			console.log('ℹ️  INFO:');
			for (const info of this.info) {
				console.log(`   ${info}`);
			}

			console.log('');
		}

		if (this.errors.length === 0 && this.warnings.length === 0) {
			console.log('✅ Configuration is valid!');
		} else if (this.errors.length === 0) {
			console.log('✅ Configuration is valid (with warnings)');
		} else {
			console.log('❌ Configuration has errors that must be fixed');
		}

		console.log(`\nSummary: ${this.errors.length} errors, ${this.warnings.length} warnings, ${this.info.length} info`);
	}
}

// CLI Program
program
	.name('validate-config')
	.description('Validate Audit Status configuration file')
	.version('1.0.0')
	.option('-c, --config <path>', 'Configuration file path', 'auditstatus.config.yml')
	.option('-q, --quiet', 'Quiet mode (only show errors)')
	.option('--strict', 'Strict mode (treat warnings as errors)');

program.parse();

const options = program.opts();

// Main execution
async function main() {
	try {
		const validator = new ConfigValidator();
		const isValid = validator.validateConfig(options.config);

		// In strict mode, treat warnings as errors
		const hasWarnings = validator.warnings.length > 0;
		const exitCode = isValid && (!options.strict || !hasWarnings) ? 0 : 1;

		if (options.strict && hasWarnings) {
			console.log('\n⚠️  Strict mode: Warnings treated as errors');
		}

		process.exit(exitCode);
	} catch (error) {
		console.error(`Fatal error: ${error.message}`);
		process.exit(1);
	}
}

// Run if called directly
if (require.main === module) {
	main();
}

module.exports = {ConfigValidator};

