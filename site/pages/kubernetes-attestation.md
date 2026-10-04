<!--
title: Kubernetes attestation for container workloads
description: Run the Audit Status attester as a DaemonSet and verify every pod's containers against their images by digest, with no open port and no exec access.
label: Kubernetes attestation
keywords: kubernetes attestation, container verification, DaemonSet, image digest, helm chart, port-forward, runtime verification
-->

# Kubernetes attestation for container workloads

In a Kubernetes cluster, the Audit Status attester runs as a DaemonSet, one pod per node. The verifier reaches it through `kubectl port-forward` and compares each container with the image it runs, fetched by digest from the registry.


## Install the attester

The Helm chart in `charts/auditstatus-attester` installs the attester on every node:

```sh
helm install attester charts/auditstatus-attester \
  --namespace auditstatus --create-namespace \
  --values attester-values.yaml
```

The values list the services: containers selected by label or by image. See [Kubernetes](/docs/kubernetes/) for every value.


## A minimal attack surface

The attester pod:

* shares the host's PID namespace, to inspect every process on the node;
* runs with only `SYS_PTRACE` and `DAC_READ_SEARCH` added, every other capability dropped, a read-only root filesystem and the `RuntimeDefault` seccomp profile;
* mounts no service account token;
* listens only on the pod's loopback interface.

The verifier's ServiceAccount may only `get` and `list` pods and create `pods/portforward` in the chart's namespace. It can reach the attester's loopback port; it cannot run commands in any pod. The cluster needs no Service and no open port.


## What is compared

For each container, the attester reports the image the runtime names, mounts, the overlay's writable layer, and every file of the root filesystem, hashed through `/proc/<pid>/root`. The verifier does not trust the runtime's claim. It fetches the image by digest, checks every manifest and layer against its digest, applies the layers in order, and compares the files. It can also require the image to be signed by an expected workflow. See [Containers](/docs/containers/).

| Finding                                                                | Meaning                                                       |
| ---------------------------------------------------------------------- | ------------------------------------------------------------- |
| Files differ from the image                                            | A file in the container was changed after the image was built |
| Files not in the image are present                                     | Something wrote new files outside the mounts                  |
| Files of the image are missing                                         | Image files were deleted                                      |
| The container runs manifest ..., which is not the image's ... manifest | The runtime runs something other than the image it names      |
| The image is not attested by ...                                       | The image has no valid attestation from the expected signer   |

Volumes and bind mounts are not part of the image, so their files are not compared with it; code that runs from a mount is still hashed and must be explained like any executable.

Docker, containerd, CRI-O and Podman are supported, through their APIs or `crictl`.


## Every node, every run

Each run sends a fresh nonce to the attester on every selected node. The same binary serves both servers and pods, so the verifier checks the attester in each pod against the release's `SHA256SUMS`, like any other.


## Next

* [Kubernetes](/docs/kubernetes/): the chart, `auditstatus serve` and the verifier's access.
* [Containers](/docs/containers/): image resolution, root filesystem comparison and image signers.
* [Verify that production matches the source](/verify-production-matches-source/).
