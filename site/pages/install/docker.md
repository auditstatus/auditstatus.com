<!--
title: Verify Docker containers with Audit Status
description: Check that Docker, containerd, CRI-O and Podman containers run their published images, compared by digest, and use the Audit Status attester image.
label: Docker
kind: howto
keywords: verify docker containers, docker image digest verification, container attestation, podman, containerd, ghcr.io/auditstatus/attester
-->

<!--lint disable no-heading-punctuation-->

# Verify Docker containers with Audit Status

Audit Status checks that each running container matches the image it claims to run. The attester on the host finds the containers, hashes their files and inspects their processes; the verifier fetches the image from its registry by digest and compares every file. Docker, containerd, CRI-O and Podman are supported.

On a server that runs Docker, install the [release binary](/install/binary/) on the host, not in a container: it needs to see every container's processes and root filesystem. The attester container image is for [Kubernetes](/install/helm/), where the Helm chart runs it on every node.


## 1. Install the attester on the host

Follow the [release binary guide](/install/binary/): download and check the binary, create the `auditstatus` account, set the capabilities, and allow the verifier's SSH key.


## 2. Describe the container service on the server

In `/etc/auditstatus/config.yml`, a container service selects running containers by `name`, `id`, `image` or `label`. Every matching container is reported, so one service covers its replicas:

```yaml
version: 2
services:
  - name: worker
    container:
      image: ghcr.io/example/worker
containers:
  dockerSocket: /var/run/docker.sock
  hashRootfs: true
```

The attester asks the runtime what each container runs: Docker through the Docker Engine API socket, Podman through its Docker-compatible socket (`systemctl enable --now podman.socket`), containerd and CRI-O through `crictl`.


## 3. Name the images the service may run

In the verifier configuration, list the image repository, and optionally the workflow that must have signed the image:

```yaml
services:
  - name: worker
    image:
      repository: ghcr.io/example/worker
      signer:
        repository: example/worker
        workflow: .github/workflows/release.yml
      compareFiles: true
      allowChanges: [tmp/**, var/cache/**]
```

A container of any other repository fails. With `signer`, the image must carry a GitHub artifact attestation from that workflow.


## 4. Check and verify

```sh
sudo -u auditstatus auditstatus doctor
```

`doctor` checks that the Docker or Podman socket, or `crictl`, is available and names the running containers each service selects. Then run a verification from the [GitHub Action](/install/github-action/) or [`auditstatus verify`](/install/npm/).


## What is compared?

| On the server                             | Compared with                                                               |
| ----------------------------------------- | --------------------------------------------------------------------------- |
| The image the runtime names               | The image fetched from its registry by digest, for the container's platform |
| Every file of the root filesystem         | The image's files (`policy.containerChanges`, `fail` by default)            |
| Files written or deleted in the container | The image, through the overlay's writable layer                             |
| Mounts that hide files of the image       | Fail by default, unless `allowChanges` covers the hidden files              |
| Every process in the container            | Its executable and libraries against the image's files                      |
| The image's signature                     | The configured signer's GitHub artifact attestation                         |

An image built on the server, or pulled by a tag that was never pushed, has no registry digest and fails: deploy images pushed to a registry, and prefer references pinned by digest. Code that runs from a volume is not in the image and fails unless another reference explains it, so keep code in the image and use volumes for data. See [Containers](/docs/containers/) for every rule.


## The attester container image

Each release publishes the attester as a container image for `linux/amd64` and `linux/arm64`:

```text
ghcr.io/auditstatus/attester:v<version>
ghcr.io/auditstatus/attester:latest
```

The image holds the release binary, `crictl` and `tpm2-tools`, on a Debian base pinned by digest. Its attester is the same binary as the release, so the verifier matches it with `SHA256SUMS` like any other. It runs `auditstatus serve` on the pod's loopback interface, for the verifier's `kubectl port-forward`. The release workflow attests the image, so you can check where it came from before you deploy it:

```sh
gh attestation verify oci://ghcr.io/auditstatus/attester:v<version> --repo auditstatus/auditstatus.com
```

Pin the image by digest in production. To build it yourself from the repository's `Dockerfile`, put the release's Linux binaries in `release/` and run `docker buildx build --platform linux/amd64,linux/arm64 .`.
