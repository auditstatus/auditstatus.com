<!--
title: Install the Audit Status Helm chart on Kubernetes
description: Install the Audit Status attester on every Kubernetes node with the Helm chart: DaemonSet values, TPM and IMA, the verifier's token and port-forward.
label: Helm chart
kind: howto
keywords: audit status helm chart, kubernetes attestation helm, attester daemonset, helm install auditstatus-attester, kubectl port-forward verifier
-->

<!--lint disable no-heading-punctuation-->

# Install the Audit Status Helm chart on Kubernetes

The Helm chart `charts/auditstatus-attester` runs the Audit Status attester as a DaemonSet, one pod per node. Each pod answers on its own loopback interface, and the verifier reaches it with `kubectl port-forward`. The cluster needs no Service and no open port, and the verifier gets no permission to run commands in the pod.

The chart lives in the repository; clone it, or download the release's source archive, to install it.


## 1. Write the values file

The attester configuration goes under `config`, and must list at least one service, or the chart refuses to render. Each service selects containers by label or image:

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

`config` becomes `/etc/auditstatus/config.yml` in each pod, through a ConfigMap. The repository's `charts/auditstatus-attester/values.example.yaml` is this file.


## 2. Install the chart

```sh
git clone https://github.com/auditstatus/auditstatus.com.git
helm install attester auditstatus.com/charts/auditstatus-attester \
  --namespace auditstatus --create-namespace \
  --values attester-values.yaml
```

After installation, the chart's notes print the namespace and selector to put in the verifier configuration.


## 3. Create the verifier's token

The chart creates a ServiceAccount, `auditstatus-verifier`, whose Role allows only `get` and `list` on pods, `create` on `pods/portforward` in the chart's namespace, and `get` on the attester DaemonSet. Create a token for CI:

```sh
kubectl -n auditstatus create token auditstatus-verifier --duration 8760h
```

Build a kubeconfig with the cluster's API server, its CA certificate and this token, and store it as a CI secret. The token expires, so create a new one before it does.


## 4. Point the verifier at each node

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

For each server, the verifier finds the DaemonSet's pod on that node, starts a port-forward to its loopback port, and sends the request. Then run the [GitHub Action](/install/github-action/) with `KUBECONFIG` set to the file you wrote from the secret.


## Main chart values

| Value                   | Default                           | Meaning                                                              |
| ----------------------- | --------------------------------- | -------------------------------------------------------------------- |
| `image.repository`      | `ghcr.io/auditstatus/attester`    | The attester image.                                                  |
| `image.digest`          | empty                             | Pin the image by digest in production.                               |
| `port`                  | `8740`                            | The loopback port; set the verifier's `kubernetes.port` to the same. |
| `cri.socket`            | `/run/containerd/containerd.sock` | The node's CRI socket. For CRI-O, `/var/run/crio/crio.sock`.         |
| `tpm.enabled`           | `false`                           | Give the pod the node's TPM (`/dev/tpmrm0`).                         |
| `ima.enabled`           | `false`                           | Mount securityfs read-only, for the IMA log.                         |
| `verifier.create`       | `true`                            | Create the verifier's ServiceAccount, Role and RoleBinding.          |
| `networkPolicy.enabled` | `true`                            | Deny all other traffic to and from the attester's pods.              |

The other values (resources, tolerations, node selector, AppArmor profile) are in [The Helm chart](/docs/kubernetes/#the-helm-chart) and the chart's `values.yaml`.


## How is the attester pod locked down?

The pod shares the host's PID namespace to inspect every process on the node. It runs with only `SYS_PTRACE` and `DAC_READ_SEARCH` added and every other capability dropped, a read-only root filesystem, no privilege escalation, the `RuntimeDefault` seccomp profile, and no service account token. The attester makes no network connections, and the chart's NetworkPolicy denies other traffic to its pods where the cluster enforces policies.


## Which pod may answer for a node?

The verifier accepts a pod only when the DaemonSet, by its UID, controls it, it is the only such pod on the node, and it runs the DaemonSet's pod template unchanged, with no ephemeral debugging containers. Anything else makes the result inconclusive. Whoever can create pods, run commands in them or change the DaemonSet in the attester's namespace can make a node's evidence say anything, so keep only the attester in that namespace. See [Who can answer for a node](/docs/kubernetes/#who-can-answer-for-a-node) and the [Kubernetes attestation guide](/kubernetes-attestation/).
