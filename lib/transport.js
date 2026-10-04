/**
 * Audit Status - how the verifier reaches each server's attester
 *
 *   ssh         a forced command for the verifier's key (the default)
 *   kubernetes  a port-forward to the attester DaemonSet's pod on the node
 *   local       in this process (the verifier and the server are one)
 *
 * @license MIT
 */

'use strict';

const {runOverSsh} = require('./ssh');
const {requestOverPortForward, toRequest} = require('./kubernetes');
const {parseOperation, perform} = require('./remote');
const {loadAttesterConfig} = require('./config');

/**
 * @param {Object} config - normalized verifier configuration
 * @param {Object} [options]
 * @param {string} [options.privateKey] - SSH key content
 * @param {Object} [options.collectOptions] - local collection (tests)
 * @param {Object} [options.tpm] - local TPM (tests)
 * @returns {{run(server: Object, operation: string): Promise<Object>}}
 */
function createTransport(config, options = {}) {
  return {
    run(server, operation) {
      if (!parseOperation(operation)) {
        return Promise.reject(new TypeError(`Not an attester operation: ${operation.slice(0, 40)}`));
      }

      if (server.transport === 'local') {
        return Promise.resolve().then(() => perform(parseOperation(operation), loadAttesterConfig(server.attesterConfig), {collectOptions: options.collectOptions, tpm: options.tpm}));
      }

      if (server.transport === 'kubernetes') {
        return requestOverPortForward(config.kubernetes, server, toRequest(operation));
      }

      return runOverSsh({
        host: server.host,
        port: server.port || config.ssh.port,
        user: server.user || config.ssh.user,
        knownHosts: config.ssh.knownHosts,
        identityFile: config.ssh.identityFile,
        privateKey: options.privateKey,
        timeoutSeconds: config.ssh.timeoutSeconds,
        command: config.ssh.command,
        remoteCommand: operation,
      });
    },
  };
}

module.exports = {createTransport};
