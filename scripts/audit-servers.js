#!/usr/bin/env node

/**
 * Audit Status - Server Auditor with Attestium Integration
 * Automated third-party auditing system for code integrity verification
 *
 * Features:
 * - Real-time server verification using Attestium
 * - Nonce-based challenge-response authentication
 * - Tamper-proof verification reports
 * - GitHub integration for transparency
 * - Configurable via YAML files
 * - TPM 2.0 hardware security with software fallback
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {cosmiconfig} = require('cosmiconfig');
const axios = require('axios');
const yaml = require('js-yaml');
const Attestium = require('attestium');

class ServerAuditor {
	constructor(options = {}) {
		// Load configuration using cosmiconfig
		const explorer = cosmiconfig('auditstatus');
		let configResult;

		// Handle configFile option from README documentation
		if (options.configFile || options.configPath) {
			const configPath = options.configFile || options.configPath;
			const fs = require('node:fs');
			const yaml = require('js-yaml');
			if (fs.existsSync(configPath)) {
				const configContent = fs.readFileSync(configPath, 'utf8');
				configResult = {config: yaml.load(configContent)};
			} else {
				configResult = explorer.search();
			}
		} else {
			configResult = explorer.search();
		}

		const config = configResult ? configResult.config : {};

		// Merge options with config, giving priority to options
		this.config = {...config, ...options};

		// Handle attestium configuration from README documentation
		const attestiumConfig = {
			projectRoot: this.config.projectRoot || process.cwd(),
			enableRuntimeHooks: this.config.enableRuntimeHooks !== false,
			enableTpm: this.config.attestium?.enableTpm ?? this.config.enableTpm ?? false,
			autoDetectTpm: this.config.attestium?.autoDetectTpm ?? true,
			fallbackMode: this.config.attestium?.fallbackMode ?? 'software',
			productionMode: this.config.attestium?.productionMode ?? false,
			tpm: this.config.attestium?.tpm ?? this.config.tmp ?? {},
		};

		// Initialize Attestium with tamper-resistant protection for local verification
		this.attestium = new Attestium(attestiumConfig);

		// Check TPM availability and log status
		this.tpmAvailable = false;
		this.initializeTpm().catch(error => {
			this.log(`TPM initialization failed: ${error.message}`, 'WARN');
		});

		// Validate tamper-resistant store integrity on startup
		if (!this.attestium.tamperResistantStore.validateIntegrity()) {
			throw new Error('Critical: Tamper-resistant store integrity validation failed - potential security breach detected');
		}

		// Server configuration
		this.servers = this.config.servers || [];
		this.timeout = this.config.timeout || 30_000;
		this.retryAttempts = this.config.retryAttempts || 3;
		this.retryDelay = this.config.retryDelay || 1000;

		// Verification settings with tamper-resistant nonce generation
		this.verificationEndpoint = this.config.verificationEndpoint || '/api/verification';
		this.nonceExpiry = this.config.nonceExpiry || 300_000; // 5 minutes

		// Initialize audit results structure
		this.auditResults = {
			timestamp: new Date().toISOString(),
			auditId: crypto.randomUUID(),
			summary: {
				totalServers: 0,
				passedServers: 0,
				failedServers: 0,
				totalChecks: 0,
				passedChecks: 0,
				failedChecks: 0,
			},
			servers: [],
			discrepancies: [],
			recommendations: [],
		};
		this.enableNonceVerification = this.config.enableNonceVerification !== false;

		// Output settings
		this.outputDir = this.config.outputDir || './audit-reports';
		this.enableGitHubIntegration = this.config.enableGitHubIntegration || false;
		this.githubToken = this.config.githubToken || process.env.GITHUB_TOKEN;

		// Notification settings
		this.notifications = this.config.notifications || {enabled: false};
		this.notificationEvents = this.notifications.events || ['failure', 'success', 'warning'];

		// Ensure output directory exists
		if (!fs.existsSync(this.outputDir)) {
			fs.mkdirSync(this.outputDir, {recursive: true});
		}

		this.log('ServerAuditor initialized with tamper-resistant Attestium integration', 'INFO');
	}

	/**
   * Create verification challenge for server with tamper-resistant baseline
   * @param {Object} server - Server configuration
   * @returns {Object} Challenge data
   */
	async createVerificationChallenge(server) {
		// Validate tamper-resistant store before proceeding
		if (!this.attestium.tamperResistantStore.validateIntegrity()) {
			throw new Error('Tamper-resistant store integrity validation failed during challenge creation');
		}

		const nonce = this.generateNonce();
		const timestamp = new Date().toISOString();

		// Generate local verification baseline using tamper-resistant Attestium
		const localReport = await this.attestium.generateVerificationReport();
		const expectedChecksum = crypto.createHash('sha256')
			.update(JSON.stringify(localReport.summary))
			.digest('hex');

		// Store challenge data in tamper-resistant memory
		const challengeKey = this.attestium.tamperResistantStore.storeChecksum(
			`challenge_${server.name}`,
			expectedChecksum,
			nonce,
		);

		return {
			nonce,
			timestamp,
			expectedChecksum,
			serverUrl: server.url,
			serverName: server.name,
			localReport: localReport.summary,
			challengeKey, // For later verification
		};
	}

	/**
   * Generate a cryptographically secure nonce using tamper-resistant store
   * @returns {string} Base64 encoded nonce
   */
	generateNonce() {
		// Use tamper-resistant nonce generation
		return this.attestium.tamperResistantStore.generateSecureNonce();
	}

	/**
   * Verify server response to challenge with tamper-resistant validation
   * @param {Object} challenge - Original challenge
   * @param {Object} response - Server response
   * @returns {Object} Verification result
   */
	verifyServerResponse(challenge, response) {
		// Validate tamper-resistant store integrity before verification
		if (!this.attestium.tamperResistantStore.validateIntegrity()) {
			throw new Error('Tamper-resistant store integrity validation failed during response verification');
		}

		const result = {
			success: false,
			timestamp: new Date().toISOString(),
			challenge: challenge.nonce,
			errors: [],
		};

		// Verify nonce using tamper-resistant store
		if (challenge.challengeKey) {
			const isValidChallenge = this.attestium.tamperResistantStore.verifyChecksum(
				`challenge_${challenge.serverName}`,
				challenge.expectedChecksum,
				challenge.nonce,
			);

			if (!isValidChallenge) {
				result.errors.push('Challenge integrity validation failed - potential tampering detected');
				return result;
			}
		}

		// Verify nonce
		if (response.nonce !== challenge.nonce) {
			result.errors.push('Nonce mismatch');
			return result;
		}

		// Verify timestamp (within expiry window)
		const challengeTime = new Date(challenge.timestamp).getTime();
		const responseTime = new Date(response.timestamp || Date.now()).getTime();

		if (responseTime - challengeTime > this.nonceExpiry) {
			result.errors.push('Challenge expired');
			return result;
		}

		// Verify server signature if provided
		if (response.signature) {
			const expectedSignature = crypto.createHash('sha256')
				.update(challenge.nonce + challenge.expectedChecksum + (response.serverChecksum || ''))
				.digest('hex');

			if (response.signature !== expectedSignature) {
				result.errors.push('Invalid server signature');
				return result;
			}
		}

		// Compare checksums
		if (response.serverChecksum && response.serverChecksum !== challenge.expectedChecksum) {
			result.errors.push('Checksum mismatch - server state differs from expected');
			result.details = {
				expected: challenge.expectedChecksum,
				actual: response.serverChecksum,
			};
		}

		// If no errors, verification successful
		if (result.errors.length === 0) {
			result.success = true;
			result.verification = {
				checksumMatch: response.serverChecksum === challenge.expectedChecksum,
				serverData: response.verification || response.status,
				localBaseline: challenge.localReport,
				tamperResistantValidation: true,
			};
		}

		return result;
	}

	/**
   * Audit a single server with nonce verification
   * @param {Object} server - Server configuration or options
   * @returns {Object} Audit result with status, integrity, and attestation
   */
	async auditServer(server) {
		// Handle both server config object and options object from README
		const serverConfig = server.url ? server : this.servers.find(s => s.name === server.name);
		if (!serverConfig) {
			throw new Error(`Server not found: ${server.name || 'unknown'}`);
		}

		const auditResult = {
			server: serverConfig.name,
			url: serverConfig.url,
			timestamp: new Date().toISOString(),
			success: false,
			verification: null,
			errors: [],
			duration: 0,
		};

		const startTime = Date.now();

		try {
			this.log(`Starting audit of ${serverConfig.name} (${serverConfig.url})`, 'INFO');

			if (this.enableNonceVerification) {
				// Step 1: Create verification challenge
				const challenge = await this.createVerificationChallenge(serverConfig);
				this.log(`Generated challenge for ${serverConfig.name}: ${challenge.nonce.slice(0, 8)}...`, 'DEBUG');

				// Step 2: Request challenge from server
				const challengeResponse = await axios.get(
					`${serverConfig.url}${this.verificationEndpoint}/challenge`,
					{
						timeout: this.timeout,
						headers: {
							'User-Agent': 'Audit-Status/1.0.0',
							Accept: 'application/json',
						},
					},
				);

				if (!challengeResponse.data.success) {
					throw new Error(`Server challenge failed: ${challengeResponse.data.error}`);
				}

				const serverChallenge = challengeResponse.data.challenge;

				// Step 3: Generate client signature
				const clientSignature = crypto.createHash('sha256')
					.update(serverChallenge.nonce + serverChallenge.serverChecksum + challenge.expectedChecksum)
					.diges; // Step 3: Send verification request with challenge
				const verifyResponse = await axios.post(`${serverConfig.url}${this.verificationEndpoint}/verify`, {
					nonce: serverChallenge.nonce,
					clientSignature,
					expectedChecksum: challenge.expectedChecksum,
					auditorChallenge: challenge.nonce,
				}, {
					timeout: this.timeout,
					headers: {
						'Content-Type': 'application/json',
						'User-Agent': 'Audit-Status/1.0.0',
					},
				});

				// Step 5: Verify server response
				const verificationResult = this.verifyServerResponse(challenge, {
					nonce: serverChallenge.nonce,
					timestamp: verifyResponse.data.verification?.timestamp,
					serverChecksum: verifyResponse.data.verification?.serverChecksum,
					signature: verifyResponse.data.verification?.signature,
					verification: verifyResponse.data.verification,
				});

				auditResult.verification = verificationResult;
				auditResult.success = verificationResult.success;

				if (!verificationResult.success) {
					auditResult.errors = verificationResult.errors;
				}
			} else {
				// Fallback: Simple status check
				const statusResponse = await axios.get(
					`${serverConfig.url}${this.verificationEndpoint}/status`,
					{
						timeout: this.timeout,
						headers: {
							'User-Agent': 'Audit-Status/1.0.0',
							Accept: 'application/json',
						},
					},
				);

				auditResult.success = statusResponse.data.success;
				auditResult.verification = {
					success: true,
					serverData: statusResponse.data.status,
					method: 'status-only',
				};
			}

			this.log(
				`Audit completed for ${serverConfig.name}: ${auditResult.success ? 'PASS' : 'FAIL'}`,
				auditResult.success ? 'INFO' : 'WARN',
			);
		} catch (error) {
			auditResult.errors.push(error.message);
			this.log(`Audit failed for ${serverConfig.name}: ${error.message}`, 'ERROR');
		}

		auditResult.duration = Date.now() - startTime;

		// Send notifications for audit events
		const notificationEvent = auditResult.success ? 'success' : 'failure';
		await this.sendNotifications(notificationEvent, {
			summary: `Server ${serverConfig.name} audit ${auditResult.success ? 'passed' : 'failed'}`,
			details: {
				server: serverConfig.name,
				url: serverConfig.url,
				duration: auditResult.duration,
				errors: auditResult.errors,
			},
		});

		// Return format matching README documentation
		return {
			status: auditResult.success ? 'passed' : 'failed',
			integrity: auditResult.success && auditResult.verification?.checksumMatch !== false,
			attestation: auditResult.verification?.signature || 'software-fallback',
			server: serverConfig.name,
			url: serverConfig.url,
			timestamp: auditResult.timestamp,
			duration: auditResult.duration,
			details: auditResult,
		};
	}

	/**
   * Audit all configured servers
   * @returns {Object} Complete audit report
   */
	async auditAllServers() {
		const report = {
			timestamp: new Date().toISOString(),
			auditor: {
				version: '1.0.0',
				attestiumEnabled: true,
				nonceVerification: this.enableNonceVerification,
			},
			summary: {
				totalServers: this.servers.length,
				successfulAudits: 0,
				failedAudits: 0,
				totalDuration: 0,
			},
			servers: [],
			localBaseline: null,
		};

		const startTime = Date.now();

		try {
			// Generate local baseline using Attestium
			report.localBaseline = await this.attestium.generateVerificationReport();
			this.log('Generated local verification baseline', 'INFO');

			// Audit each server
			for (const server of this.servers) {
				if (!server.enabled) {
					this.log(`Skipping disabled server: ${server.name}`, 'INFO');
					continue;
				}

				const auditResult = await this.auditServer(server);
				report.servers.push(auditResult);

				if (auditResult.success) {
					report.summary.successfulAudits++;
				} else {
					report.summary.failedAudits++;
				}

				// Add delay between audits to avoid overwhelming servers
				if (this.retryDelay > 0) {
					await new Promise(resolve => setTimeout(resolve, this.retryDelay));
				}
			}
		} catch (error) {
			this.log(`Audit process failed: ${error.message}`, 'ERROR');
			report.error = error.message;
		}

		report.summary.totalDuration = Date.now() - startTime;

		// Save report
		await this.saveAuditReport(report);

		// Update GitHub if enabled
		if (this.enableGitHubIntegration) {
			await this.updateGitHubStatus(report);
		}

		return report;
	}

	/**
   * Save audit report to file
   * @param {Object} report - Audit report
   */
	async saveAuditReport(report) {
		const timestamp = new Date().toISOString().replaceAll(/[:.]/g, '-');
		const filename = `audit-report-${timestamp}.json`;
		const filepath = path.join(this.outputDir, filename);

		try {
			fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
			this.log(`Audit report saved: ${filepath}`, 'INFO');

			// Also save as latest
			const latestPath = path.join(this.outputDir, 'latest-audit-report.json');
			fs.writeFileSync(latestPath, JSON.stringify(report, null, 2));
		} catch (error) {
			this.log(`Failed to save audit report: ${error.message}`, 'ERROR');
		}
	}

	/**
   * Update GitHub status with audit results
   * @param {Object} report - Audit report
   */
	async updateGitHubStatus(report) {
		if (!this.githubToken || !this.config.githubRepo) {
			this.log('GitHub integration not configured', 'WARN');
			return;
		}

		try {
			const status = report.summary.failedAudits === 0 ? 'success' : 'failure';
			const description = `${report.summary.successfulAudits}/${report.summary.totalServers} servers verified`;

			// Update commit status (requires specific commit SHA)
			if (this.config.githubCommitSha) {
				await axios.post(
					`https://api.github.com/repos/${this.config.githubRepo}/statuses/${this.config.githubCommitSha}`,
					{
						state: status,
						description,
						context: 'auditstatus/auditstatus',
					},
					{
						headers: {
							Authorization: `token ${this.githubToken}`,
							Accept: 'application/vnd.github.v3+json',
						},
					},
				);

				this.log('GitHub status updated', 'INFO');
			}
		} catch (error) {
			this.log(`Failed to update GitHub status: ${error.message}`, 'ERROR');
		}
	}

	/**
   * Log message with timestamp and level
   * @param {string} message - Log message
   * @param {string} level - Log level
   */
	log(message, level = 'INFO') {
		const timestamp = new Date().toISOString();
		const logMessage = `[${timestamp}] [AUDITOR] [${level}] ${message}`;

		if (this.config.logger) {
			this.config.logger.log(logMessage);
		} else {
			console.log(logMessage);
		}
	}

	/**
   * Initialize TPM for hardware-backed verification
   * @returns {Promise<void>}
   */
	async initializeTpm() {
		try {
			this.tpmAvailable = await this.attestium.isTpmAvailable();

			if (this.tpmAvailable) {
				await this.attestium.initializeTpm();
				this.log('✅ TPM 2.0 hardware-backed verification enabled', 'INFO');

				// Test hardware random generation
				const hardwareRandom = await this.attestium.generateHardwareRandom(16);
				this.log(`TPM hardware random test: ${hardwareRandom.toString('hex')}`, 'DEBUG');
			} else {
				this.log('⚠️ TPM not available, using software-only verification', 'WARN');
				this.log(this.attestium.getTpmInstallationInstructions(), 'INFO');
			}
		} catch (error) {
			this.log(`TPM initialization error: ${error.message}`, 'ERROR');
			this.tpmAvailable = false;
		}
	}

	/**
   * Generate hardware-backed attestation if TPM is available
   * @param {string} nonce - Challenge nonce
   * @returns {Promise<Object>} Hardware attestation or software fallback
   */
	async generateHardwareAttestation(nonce) {
		if (this.tpmAvailable) {
			try {
				const hardwareAttestation = await this.attestium.generateHardwareAttestation(nonce);
				this.log('✅ Hardware-backed attestation generated', 'INFO');
				return hardwareAttestation;
			} catch (error) {
				this.log(`Hardware attestation failed: ${error.message}`, 'WARN');
			}
		}

		// Fallback to software verification
		const report = await this.attestium.generateVerificationReport();
		return {
			type: 'software-only',
			verification: report,
			nonce,
			timestamp: new Date().toISOString(),
			tpmEnabled: false,
		};
	}

	/**
   * Initialize configuration file
   */
	static initializeConfig(customPath = null) {
		const configPath = customPath || path.join(process.cwd(), 'auditstatus.config.yml');

		if (fs.existsSync(configPath)) {
			console.log('Configuration file already exists:', configPath);
			return true;
		}

		const defaultConfig = {
			auditor: {
				name: 'Audit Status',
				version: '1.0.0',
				contact: {
					email: 'support@auditstatus.com',
					github: 'auditstatus',
					website: 'https://auditstatus.com',
				},
			},
			servers: [
				{
					name: 'api.example.com',
					url: 'https://api.example.com',
					type: 'web',
					environment: 'production',
					enabled: true,
				},
			],
			timeout: 30_000,
			retryAttempts: 3,
			retryDelay: 1000,
			enableNonceVerification: true,
			verificationEndpoint: '/api/verification',
			nonceExpiry: 300_000,
			outputDir: './audit-reports',
			enableGitHubIntegration: false,
			projectRoot: process.cwd(),
			enableRuntimeHooks: true,
			attestium: {
				enableTpm: false,
				autoDetectTpm: true,
				fallbackMode: 'software',
				productionMode: false,
			},
		};

		try {
			fs.writeFileSync(configPath, yaml.dump(defaultConfig, {indent: 2}));
			console.log('Configuration file created:', configPath);
			return true;
		} catch (error) {
			console.error('Failed to create configuration file:', error.message);
			return false;
		}
	}

	/**
   * Generate HTML report from audit results
   */
	generateHtmlReport() {
		const timestamp = new Date().toISOString();
		const {summary} = this.auditResults;

		return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Status Server Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .server { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
        .passed { background: #d4edda; }
        .failed { background: #f8d7da; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Audit Status Server Audit Report</h1>
        <p>Generated: ${timestamp}</p>
        <p>Audit ID: ${this.auditResults.auditId}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Servers: ${summary.totalServers}</p>
        <p>Passed: ${summary.passedServers}</p>
        <p>Failed: ${summary.failedServers}</p>
    </div>
    
    <div class="servers">
        <h2>Server Results</h2>
        ${this.auditResults.servers.map(server => `
            <div class="server ${server.status === 'passed' ? 'passed' : 'failed'}">
                <h3>${server.name}</h3>
                <p>Status: ${server.status}</p>
                <p>URL: ${server.url}</p>
            </div>
        `).join('')}
    </div>
</body>
</html>`;
	}

	/**
   * Generate markdown report from audit results
   */
	generateMarkdownReport() {
		const timestamp = new Date().toISOString();
		const {summary} = this.auditResults;

		return `# Audit Status Server Audit Report

**Generated:** ${timestamp}  
**Audit ID:** ${this.auditResults.auditId}

## Summary

- **Total Servers:** ${summary.totalServers}
- **Passed:** ${summary.passedServers}
- **Failed:** ${summary.failedServers}
- **Total Checks:** ${summary.totalChecks}
- **Passed Checks:** ${summary.passedChecks}
- **Failed Checks:** ${summary.failedChecks}

## Server Results

${this.auditResults.servers.map(server => `
### ${server.name}

- **Status:** ${server.status}
- **URL:** ${server.url}
- **Type:** ${server.type}
- **Environment:** ${server.environment}

`).join('')}

## Discrepancies

${this.auditResults.discrepancies.length > 0
	? this.auditResults.discrepancies.map(d => `- ${d}`).join('\n')
	: 'No discrepancies found.'}

## Recommendations

${this.auditResults.recommendations.length > 0
	? this.auditResults.recommendations.map(r => `- ${r}`).join('\n')
	: 'No recommendations at this time.'}
`;
	}

	/**
   * Generate audit reports in various formats
   * @param {string} format - Report format ('html', 'markdown', 'json')
   * @param {Object} options - Report options
   * @returns {Promise<string>} Generated report content or file path
   */
	async generateReport(format, options = {}) {
		let content;

		switch (format.toLowerCase()) {
			case 'html': {
				content = this.generateHtmlReport();
				break;
			}

			case 'markdown': {
				content = this.generateMarkdownReport();
				break;
			}

			case 'json': {
				content = JSON.stringify(this.auditResults, null, 2);
				break;
			}

			default: {
				throw new Error(`Unsupported report format: ${format}`);
			}
		}

		if (options.outputPath) {
			const fs = require('node:fs');
			const path = require('node:path');

			// Ensure directory exists
			const dir = path.dirname(options.outputPath);
			if (!fs.existsSync(dir)) {
				fs.mkdirSync(dir, {recursive: true});
			}

			fs.writeFileSync(options.outputPath, content);
			return options.outputPath;
		}

		return content;
	}

	/**
   * Get current security configuration and TPM status
   * @returns {Promise<Object>} Security status information
   */
	async getSecurityStatus() {
		let attestiumVersion = '1.0.0'; // Default fallback
		try {
			// Try to get version from attestium instance
			attestiumVersion = this.attestium.version || '1.0.0';
		} catch {
			// Fallback to default version
		}

		return {
			mode: this.tpmAvailable ? 'tpm' : 'software',
			tpmAvailable: this.tpmAvailable,
			hardwareBacked: this.tpmAvailable,
			attestiumVersion,
			securityLevel: this.tpmAvailable ? 'high' : 'medium',
			fallbackMode: this.config.attestium?.fallbackMode || 'software',
			productionMode: this.config.attestium?.productionMode || false,
		};
	}

	/**
	 * Send webhook notification
	 * @param {string} event - Event type (success, failure, warning)
	 * @param {Object} data - Notification data
	 * @returns {Promise<boolean>} Success status
	 */
	async sendWebhookNotification(event, data) {
		if (!this.notifications.enabled || !this.notifications.webhook?.url) {
			return false;
		}

		if (!this.notificationEvents.includes(event)) {
			return false;
		}

		try {
			const payload = {
				event,
				timestamp: new Date().toISOString(),
				service: 'Audit Status',
				data,
			};

			const response = await axios.post(this.notifications.webhook.url, payload, {
				headers: {
					'Content-Type': 'application/json',
					'User-Agent': 'Audit-Status/1.0.0',
				},
				timeout: 10_000,
			});

			this.log(`Webhook notification sent for ${event}: ${response.status}`, 'INFO');
			return true;
		} catch (error) {
			this.log(`Failed to send webhook notification: ${error.message}`, 'ERROR');
			return false;
		}
	}

	/**
	 * Send email notification
	 * @param {string} event - Event type (success, failure, warning)
	 * @param {Object} data - Notification data
	 * @returns {Promise<boolean>} Success status
	 */
	async sendEmailNotification(event, data) {
		if (!this.notifications.enabled || !this.notifications.email?.smtp) {
			return false;
		}

		if (!this.notificationEvents.includes(event)) {
			return false;
		}

		try {
			const nodemailer = require('nodemailer');

			const transporter = nodemailer.createTransport(this.notifications.email.smtp);

			const subject = `Audit Status ${event.toUpperCase()}: ${data.summary || 'Server Audit'}`;
			const text = `
Audit Status Notification

Event: ${event.toUpperCase()}
Timestamp: ${new Date().toISOString()}
Summary: ${data.summary || 'No summary available'}

${data.details ? `Details:\n${JSON.stringify(data.details, null, 2)}` : ''}

--
Audit Status
https://auditstatus.com
			`.trim();

			const mailOptions = {
				from: this.notifications.email.from,
				to: this.notifications.email.to,
				subject,
				text,
			};

			await transporter.sendMail(mailOptions);
			this.log(`Email notification sent for ${event}`, 'INFO');
			return true;
		} catch (error) {
			this.log(`Failed to send email notification: ${error.message}`, 'ERROR');
			return false;
		}
	}

	/**
	 * Send notifications for audit events
	 * @param {string} event - Event type
	 * @param {Object} data - Event data
	 * @returns {Promise<void>}
	 */
	async sendNotifications(event, data) {
		if (!this.notifications.enabled) {
			return;
		}

		const promises = [];

		if (this.notifications.webhook?.url) {
			promises.push(this.sendWebhookNotification(event, data));
		}

		if (this.notifications.email?.smtp) {
			promises.push(this.sendEmailNotification(event, data));
		}

		await Promise.allSettled(promises);
	}

	/**
   * Validate configuration structure
   * @param {Object} config - Configuration to validate
   * @throws {Error} If configuration is invalid
   */
	validateConfiguration(config) {
		if (!config || typeof config !== 'object') {
			throw new Error('Configuration must be an object');
		}

		if (config.servers && !Array.isArray(config.servers)) {
			throw new Error('servers must be an array');
		}

		if (config.servers) {
			for (const [index, server] of config.servers.entries()) {
				if (!server.name || !server.url) {
					throw new Error(`Server at index ${index} must have name and url properties`);
				}
			}
		}

		return true;
	}

	/**
   * Save audit results to file (alias for saveAuditResults)
   * @param {string} filePath - Path to save results
   * @returns {Promise<boolean>} Success status
   */
	async saveResults(filePath) {
		return this.saveAuditResults(filePath);
	}

	/**
   * Save audit results to file
   */
	saveAuditResults(filePath) {
		try {
			fs.writeFileSync(filePath, JSON.stringify(this.auditResults, null, 2));
			return true;
		} catch (error) {
			console.error('Failed to save audit results:', error.message);
			return false;
		}
	}
}

// CLI interface
if (require.main === module) {
	const args = process.argv.slice(2);

	if (args.includes('--init')) {
		ServerAuditor.initializeConfig();
	} else {
		const auditor = new ServerAuditor();

		auditor.auditAllServers()
			.then(report => {
				console.log('\n🧪 Attestium-Powered Audit Complete!');
				console.log(`✅ Successful: ${report.summary.successfulAudits}`);
				console.log(`❌ Failed: ${report.summary.failedAudits}`);
				console.log(`⏱️  Duration: ${report.summary.totalDuration}ms`);

				if (report.summary.failedAudits > 0) {
					process.exit(1);
				}
			})
			.catch(error => {
				console.error('Audit failed:', error.message);
				process.exit(1);
			});
	}
}

module.exports = ServerAuditor;
// Alias for README documentation compatibility
module.exports.AuditStatus = ServerAuditor;
module.exports.default = ServerAuditor;

