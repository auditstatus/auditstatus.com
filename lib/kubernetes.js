/**
 * Audit Status - Kubernetes transport for the verifier
 *
 * The attester runs as a DaemonSet (one pod per node, see the Helm chart)
 * serving the attester operations on the pod's loopback interface
 * (`auditstatus serve`).  The verifier reaches it with `kubectl
 * port-forward`, so its credentials need only `pods/portforward` (and
 * `pods` get/list) in the attester's namespace: it can ask for evidence,
 * never run commands.  The pods listen on kubernetes.port (default 8740,
 * the Helm chart's attester.port).
 *
 * @license MIT
 */

'use strict';

const http = require('node:http');
const {spawn, execFile} = require('node:child_process');
const {MAX_OUTPUT} = require('./ssh');

const PORT = 8740;
const DAEMON_SET = 'auditstatus-attester';

function kubectlArguments(settings, server) {
  const args = [];
  if (settings.kubeconfig) {
    args.push('--kubeconfig', settings.kubeconfig);
  }

  if (server.kubernetes.context) {
    args.push('--context', server.kubernetes.context);
  }

  args.push('--namespace', server.kubernetes.namespace || settings.namespace);
  return args;
}

function kubectl(settings, args, timeoutSeconds) {
  return new Promise((resolve, reject) => {
    execFile(settings.kubectl, args, {timeout: timeoutSeconds * 1000, maxBuffer: 64 * 1024 * 1024}, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`kubectl failed: ${String(stderr || error.message).trim().split('\n').slice(-2).join(' ').slice(0, 500)}`));
      } else {
        resolve(stdout);
      }
    });
  });
}

// What a pod must share with its DaemonSet's template: anything else in
// it could answer the port-forward, or run the attester differently.
const CONTAINER_FIELDS = ['command', 'args', 'env', 'envFrom', 'volumeMounts', 'securityContext', 'workingDir'];
// A debugging container (kubectl debug) added to the running pod could
// trace the attester; a template has none.
const POD_FIELDS = ['hostPID', 'hostNetwork', 'hostIPC', 'shareProcessNamespace', 'securityContext', 'runtimeClassName', 'ephemeralContainers'];
// The service account token the API server adds to a pod whose template
// does not turn it off.
const TOKEN_VOLUME = /^kube-api-access-/;

// An absent field, null and an empty list are the same.
const empty = value => value === undefined || value === null || (Array.isArray(value) && value.length === 0);

function canonical(value) {
  if (empty(value)) {
    return 'null';
  }

  if (Array.isArray(value)) {
    return `[${value.map(item => canonical(item)).join(',')}]`;
  }

  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().filter(key => !empty(value[key])).map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }

  return JSON.stringify(value);
}

/**
 * How a pod differs from the pod template of its DaemonSet (field names).
 */
function templateDifferences(pod, template) {
  const differences = [];
  const podSpec = pod.spec || {};
  const templateSpec = template.spec || {};
  for (const field of POD_FIELDS) {
    if (canonical(podSpec[field]) !== canonical(templateSpec[field])) {
      differences.push(field);
    }
  }

  const volumes = spec => (spec.volumes || []).filter(volume => !TOKEN_VOLUME.test(volume.name));
  if (canonical(volumes(podSpec)) !== canonical(volumes(templateSpec))) {
    differences.push('volumes');
  }

  for (const kind of ['initContainers', 'containers']) {
    const expected = templateSpec[kind] || [];
    const actual = podSpec[kind] || [];
    if (canonical(actual.map(item => item.name)) !== canonical(expected.map(item => item.name))) {
      differences.push(kind);
      continue;
    }

    for (const [index, container] of expected.entries()) {
      const running = actual[index];
      // An admission controller may pin a tag to its digest.
      if (running.image !== container.image && !String(running.image).startsWith(`${container.image}@sha256:`)) {
        differences.push(`${container.name}.image`);
      }

      for (const field of CONTAINER_FIELDS) {
        const value = field === 'volumeMounts' ? (running[field] || []).filter(mount => !TOKEN_VOLUME.test(mount.name)) : running[field];
        if (canonical(value) !== canonical(container[field])) {
          differences.push(`${container.name}.${field}`);
        }
      }
    }
  }

  return differences;
}

/**
 * The attester pod for a server: the configured pod, or the running pod of
 * the attester DaemonSet on the configured node.
 *
 * Anyone who can create a pod in the namespace could give it the
 * attester's labels, and a name that sorts first: a pod is used only when
 * the DaemonSet (by its UID) controls it, it is the only such pod on the
 * node, and it runs the DaemonSet's pod template.
 */
async function findPod(settings, server) {
  if (server.kubernetes.pod) {
    return server.kubernetes.pod;
  }

  const base = kubectlArguments(settings, server);
  const selector = server.kubernetes.selector || settings.selector;
  const name = server.kubernetes.daemonSet || settings.daemonSet || DAEMON_SET;
  const daemonSet = JSON.parse(await kubectl(settings, [...base, 'get', 'daemonset', name, '--output', 'json'], 60));
  const uid = daemonSet && daemonSet.metadata && daemonSet.metadata.uid;
  if (!uid) {
    throw new Error(`The DaemonSet ${name} has no UID`);
  }

  const list = JSON.parse(await kubectl(settings, [...base, 'get', 'pods', '--selector', selector, '--field-selector', `spec.nodeName=${server.kubernetes.node},status.phase=Running`, '--output', 'json'], 60));
  const items = (list.items || []).filter(item => !item.metadata.deletionTimestamp);
  const pods = items.filter(item => (item.metadata.ownerReferences || []).some(owner => owner.controller === true && owner.kind === 'DaemonSet' && owner.uid === uid));
  const others = items.filter(item => !pods.includes(item)).map(item => item.metadata.name).sort();
  const alsoFound = others.length > 0 ? `; pods matching ${selector} that it does not control: ${others.slice(0, 10).join(', ')}` : '';
  if (pods.length !== 1) {
    throw new Error(`${pods.length === 0 ? 'No' : pods.length} running pod${pods.length === 0 ? '' : 's'} of the DaemonSet ${name} on node ${server.kubernetes.node}${alsoFound}`);
  }

  const [pod] = pods;
  const differences = templateDifferences(pod, (daemonSet.spec && daemonSet.spec.template) || {});
  if (differences.length > 0) {
    throw new Error(`The pod ${pod.metadata.name} does not run the pod template of the DaemonSet ${name} (${differences.join(', ')})`);
  }

  return pod.metadata.name;
}

/**
 * Run an operation through a port-forward to the attester pod.
 *
 * @param {Object} settings - config.kubernetes (port: where the pods listen;
 *   maxOutput: the largest answer accepted, default the SSH transport's)
 * @param {Object} server - normalized server entry
 * @param {{method: string, path: string, body?: string}} request
 * @returns {Promise<Object>} the JSON answer
 */
async function requestOverPortForward(settings, server, request) {
  const pod = await findPod(settings, server);
  const child = spawn(settings.kubectl, [...kubectlArguments(settings, server), 'port-forward', `pod/${pod}`, `:${settings.port || PORT}`, '--address', '127.0.0.1'], {stdio: ['ignore', 'pipe', 'pipe']});
  try {
    const port = await new Promise((resolve, reject) => {
      let output = '';
      let errors = '';
      const timer = setTimeout(() => reject(new Error(`kubectl port-forward to ${pod} did not start: ${errors.trim().slice(0, 300)}`)), 60_000);
      child.stdout.on('data', chunk => {
        output += chunk;
        const match = output.match(/Forwarding from 127\.0\.0\.1:(\d+)/);
        if (match) {
          clearTimeout(timer);
          resolve(Number(match[1]));
        }
      });
      child.stderr.on('data', chunk => {
        errors = (errors + chunk).slice(-4096);
      });
      child.on('error', error => {
        clearTimeout(timer);
        reject(error);
      });
      child.on('close', code => {
        clearTimeout(timer);
        reject(new Error(`kubectl port-forward to ${pod} exited with ${code}: ${errors.trim().slice(0, 300)}`));
      });
    });
    return await new Promise((resolve, reject) => {
      const outgoing = http.request({
        host: '127.0.0.1', port, method: request.method, path: request.path, timeout: settings.timeoutSeconds * 1000,
      }, response => {
        // The answer comes from the audited node: bounded, and any JSON
        // value (not only an object) must be handled.
        const maxOutput = settings.maxOutput || MAX_OUTPUT;
        const chunks = [];
        let size = 0;
        response.on('error', reject);
        response.on('data', chunk => {
          size += chunk.length;
          if (size > maxOutput) {
            reject(new Error(`The answer from ${pod} exceeded ${maxOutput} bytes`));
            outgoing.destroy();
            return;
          }

          chunks.push(chunk);
        });
        response.on('end', () => {
          let body;
          try {
            body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch {
            reject(new Error(`The answer from ${pod} is not valid JSON`));
            return;
          }

          if (response.statusCode === 200) {
            resolve(body);
          } else {
            reject(new Error(`The attester in ${pod} answered ${response.statusCode}: ${String(body && body.error).slice(0, 500)}`));
          }
        });
      });
      outgoing.on('timeout', () => outgoing.destroy(new Error(`The attester in ${pod} timed out after ${settings.timeoutSeconds} seconds`)));
      outgoing.on('error', reject);
      outgoing.end(request.body);
    });
  } finally {
    child.kill();
  }
}

/**
 * The request for an operation (see ./remote).
 * @param {string} operation - "check <nonce>", "enroll" or "activate <base64>"
 * @returns {{method: string, path: string, body?: string}}
 */
function toRequest(operation) {
  const [name, argument] = operation.split(' ');
  if (name === 'check') {
    return {method: 'GET', path: `/v1/check?nonce=${argument}`};
  }

  if (name === 'activate') {
    return {method: 'POST', path: '/v1/activate', body: argument};
  }

  return {method: 'GET', path: '/v1/enroll'};
}

module.exports = {
  PORT, DAEMON_SET, kubectlArguments, findPod, templateDifferences, requestOverPortForward, toRequest,
};
