# Kubernetes

In a Kubernetes cluster, the attester runs as a DaemonSet, one pod per node, and answers on the pod's loopback interface. The verifier reaches it with `kubectl port-forward`, so it needs no Service, no open port, and no permission to run commands in the pod. This page covers the Helm chart, `auditstatus serve`, the verifier's access, and the verifier configuration.


## The Helm chart

`charts/auditstatus-attester` installs the attester on every node:

```sh
helm install attester charts/auditstatus-attester \
  --namespace auditstatus --create-namespace \
  --values attester-values.yaml
```

The configuration must list at least one service, or the chart refuses to render. A values file for two container services (`charts/auditstatus-attester/values.example.yaml`):

```yaml
config:
  version: 2
  services:
    - name: web
      container:
        label: app.kubernetes.io/name=web
    - name: worker
      container:
        image: ghcr.io/example/worker
  containers:
    crictl: /usr/local/bin/crictl
  distro:
    root: /proc/1/root
```

`config` becomes `/etc/auditstatus/config.yml` in the pod (a ConfigMap). See [Configuration](configuration.md#attester-configuration) for its settings and [Containers](containers.md) for container services.

### Values

| Value               | Default                                                                                                                                                | Meaning                                                                                                                |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `image.repository`  | `ghcr.io/auditstatus/attester`                                                                                                                         | The attester image.                                                                                                    |
| `image.tag`         | `v2.0.0`                                                                                                                                               | Its tag. Pin by digest in production (`tag@sha256:...`).                                                               |
| `image.pullPolicy`  | `IfNotPresent`                                                                                                                                         |                                                                                                                        |
| `port`              | `8740`                                                                                                                                                 | The loopback port the attester listens on. Set the verifier's `kubernetes.port` to the same value.                     |
| `config`            | `version: 2`, no services, `containers.crictl: /usr/local/bin/crictl`, `containers.hashRootfs: true`, `distro.root: /proc/1/root`, `tpm.enabled: auto` | The attester configuration.                                                                                            |
| `cri.socket`        | `/run/containerd/containerd.sock`                                                                                                                      | The node's CRI socket, mounted into the pod and passed to `crictl`. For CRI-O, `/var/run/crio/crio.sock`.              |
| `tpm.enabled`       | `false`                                                                                                                                                | Give the pod the node's TPM (`/dev/tpmrm0`).                                                                           |
| `tpm.privileged`    | `false`                                                                                                                                                | Run the pod privileged, which device nodes need unless a device plugin provides the TPM.                               |
| `tpm.resourceName`  | `""`                                                                                                                                                   | A device plugin's resource for the TPM. When set, the pod requests one instead of mounting `/dev/tpmrm0`.              |
| `ima.enabled`       | `false`                                                                                                                                                | Mount securityfs read-only, for the IMA log. Also set `config.ima.enabled: true`.                                      |
| `verifier.create`   | `true`                                                                                                                                                 | Create the verifier's ServiceAccount, Role and RoleBinding.                                                            |
| `verifier.name`     | `auditstatus-verifier`                                                                                                                                 | Their name.                                                                                                            |
| `resources`         | requests `10m` CPU and `64Mi`; limit `1Gi` memory                                                                                                      |                                                                                                                        |
| `tolerations`       | `[{operator: Exists}]`                                                                                                                                 | Run on every node, including tainted ones.                                                                             |
| `nodeSelector`      | `{}`                                                                                                                                                   |                                                                                                                        |
| `priorityClassName` | `""`                                                                                                                                                   |                                                                                                                        |
| `appArmorProfile`   | `RuntimeDefault`                                                                                                                                       | Some distributions confine ptrace with AppArmor; the attester reads other processes' memory maps and executable pages. |
| `nameOverride`      | the chart name                                                                                                                                         | The name of the DaemonSet and its `app.kubernetes.io/name` label.                                                      |

### The DaemonSet

The pod:

* shares the host's PID namespace (`hostPID: true`), to inspect every process on the node;
* runs as root with only `SYS_PTRACE` and `DAC_READ_SEARCH` added and every other capability dropped (unless `tpm.privileged`), a read-only root filesystem, no privilege escalation, and the `RuntimeDefault` seccomp profile;
* does not mount a service account token;
* mounts the configuration, the CRI socket, and optionally securityfs and the TPM;
* runs `auditstatus serve --config /etc/auditstatus/config.yml --listen 127.0.0.1:<port>` (the chart's `port`, `8740` by default).

The image holds the release binary, `crictl` and `tpm2-tools`. Its attester is the same binary as the release, so the verifier matches it with `SHA256SUMS` like any other. The release workflow attests the image, so you can require its signer too.


## auditstatus serve

`serve` answers the attester's three operations over HTTP, one request at a time:

| Request                                           | Operation               |
| ------------------------------------------------- | ----------------------- |
| `GET /v1/check?nonce=<hex>`                       | `check <nonce>`         |
| `GET /v1/enroll`                                  | `enroll`                |
| `POST /v1/activate` (body: the base64 credential) | `activate <credential>` |

Anything else answers `404` with `{"error": "unknown operation"}`. It listens only on a loopback address (`127.0.0.1`, `::1` or `localhost`); any other address is refused. The verifier's port-forward connects to `kubernetes.port` (default `8740`): set it to the port given to `--listen` (the chart's `port`) when that is another. The configuration is read again for each request.

A request whose `Host` header is not a loopback name (`127.0.0.1`, `localhost` or `[::1]`, with any port) answers `421`: a web page whose name was made to resolve to `127.0.0.1` (DNS rebinding) cannot reach a port-forward through a browser. At most four operations wait their turn; more answer `503`. A client has 20 seconds to send its request headers and 60 seconds for the whole request.


## The verifier's access

The chart creates a ServiceAccount whose Role allows only `get` and `list` on `pods`, `create` on `pods/portforward` in the chart's namespace, and `get` on the attester DaemonSet. The verifier can find the attester pod on a node and reach its loopback port; it cannot run commands in it.

Create a token for CI:

```sh
kubectl -n auditstatus create token auditstatus-verifier --duration 8760h
```

Build a kubeconfig with the cluster's API server, its CA certificate and this token, and store it as a CI secret. Write it to a file before the verification, for example:

```yaml
- name: Kubeconfig
  run: echo "$KUBECONFIG_CONTENT" > "$RUNNER_TEMP/kubeconfig"
  env:
    KUBECONFIG_CONTENT: ${{ secrets.AUDITSTATUS_KUBECONFIG }}
- uses: auditstatus/auditstatus.com@v2
  env:
    KUBECONFIG: ${{ runner.temp }}/kubeconfig
  with:
    config: auditstatus.config.yml
```

The token expires; create a new one before it does.


## Verifier configuration

```yaml
kubernetes:
  namespace: auditstatus
  selector: app.kubernetes.io/name=auditstatus-attester
servers:
  - name: node-a
    transport: kubernetes
    services: [web, worker]
    kubernetes:
      node: node-a
```

For each server, the verifier reads the DaemonSet `kubernetes.daemonSet`, lists the running pods matching `selector` on `kubernetes.node`, starts `kubectl port-forward pod/<pod> :<kubernetes.port> --address 127.0.0.1`, and sends the request. Each server can override `namespace`, `selector`, `daemonSet`, and choose a kubeconfig `context`.

A pod answers for the node only when:

* the DaemonSet, by its UID, is the pod's controller (a pod that only carries the attester's labels, or names the DaemonSet without its UID, is not the attester);
* it is the only such pod on the node, not counting pods being deleted (two pods make the result inconclusive, never the first by name);
* it runs the DaemonSet's pod template: the same containers with the same images (a digest an admission controller added to a tag is accepted), commands, arguments, environment, mounts and security contexts, the same volumes, host namespaces and pod security context, and no ephemeral (debugging) containers. The service account token the API server adds is ignored.

Otherwise the server's result is inconclusive, with the reason. `kubernetes.pod` names a pod directly instead; that pod is not checked.

| Setting                     | Default                                       |
| --------------------------- | --------------------------------------------- |
| `kubernetes.kubectl`        | `kubectl`                                     |
| `kubernetes.kubeconfig`     | kubectl's default (`KUBECONFIG`)              |
| `kubernetes.namespace`      | `auditstatus`                                 |
| `kubernetes.selector`       | `app.kubernetes.io/name=auditstatus-attester` |
| `kubernetes.port`           | `8740` (the chart's `port`)                   |
| `kubernetes.timeoutSeconds` | `600`                                         |
| `kubernetes.daemonSet`      | `auditstatus-attester` (the chart's name)     |

`auditstatus doctor --role verifier` checks that `kubectl` is installed. `NOTES.txt` of the chart prints the namespace and selector to use after installation. For a TPM on the nodes, enroll each one with `auditstatus tpm-verify --server <name>` as described in [Hardware evidence](hardware.md); it goes through the same port-forward.

### Who can answer for a node

The attester pod is as trusted as the attester on a server. Anyone who can change what runs in the attester's namespace can make a node's evidence say anything, as root on a server can with software evidence:

* creating pods, or running commands in them (`pods/exec`, `pods/attach`, `pods/ephemeralcontainers`), in the namespace;
* changing the DaemonSet or its ConfigMap (the pod template is what the verifier compares with);
* administering the cluster or the node (a node's root can replace the image the pods run unless it is pinned by digest);
* sitting on the network between the API server and the node's kubelet, when the API server does not verify the kubelet's serving certificate (`--kubelet-certificate-authority` unset, as in many clusters): the port-forward runs through that connection, so such an attacker can answer in the node's place. The verifier authenticates only the API server, through its kubeconfig. Over SSH there is no such hop: the verifier pins each server's host key itself.

Keep only the attester in its namespace, give those permissions to no one who is not trusted with the servers, and pin the image by digest (`image.digest`). With a TPM, a pod that is not the attester cannot sign a quote with the node's pinned key; it can still answer without one, so set `tpm.required` or pin `tpm.publicKey` for each node.
