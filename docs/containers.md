# Containers

A container service is every running container that matches a filter. The attester reports each container's image, mounts, writable layer, root filesystem and processes; the verifier fetches the image from its registry by digest and compares the container's files with it. This page covers the supported runtimes, image resolution, the comparison, allowed changes, mounts, and image signers.


## Configure a container service

On the server, in the attester configuration:

```yaml
services:
  - name: worker
    container:
      image: ghcr.io/example/worker
containers:
  dockerSocket: /var/run/docker.sock
  podmanSocket: /run/podman/podman.sock
  crictl: crictl
  hashRootfs: true
```

A container matches when it matches every filter given: `name`, `id` (a prefix), `image` (the repository, with or without a tag), and `label` (`key=value`). Every matching container is reported, so a service can cover several replicas.

In the verifier configuration, a service with an `image` section:

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

A container service needs no `repository`. See [Configuration](configuration.md#image) for every setting.

The server names the image a container runs. `image.repository` (a repository, or a list of them) is the verifier's own record of which images the service may run: only a registry digest in one of them is used, and a container of any other repository fails. Names are compared as a registry resolves them, so `nginx` is `docker.io/library/nginx` and `ghcr.io/example/worker` matches only that repository. Without `image.repository` or `image.signer`, any image the server names is accepted if the container's files match it.


## Runtimes

The attester finds containers from each process's cgroup, then asks the runtime what the container runs. A process counts as a container's only when it also runs in another root than the host's: a user can name a cgroup like a container's where systemd delegates cgroups to it, but cannot leave the host's root without privileges, so such a process stays in the directory services.

| Runtime                               | Recognized by                                                                    | Inspected through                                                 |
| ------------------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Docker                                | `/docker/<id>`, `docker-<id>.scope`                                              | The Docker Engine API socket (`containers.dockerSocket`)          |
| containerd, including Kubernetes pods | `cri-containerd-<id>.scope`, `/kubepods.../<id>`, `/containerd/<namespace>/<id>` | `crictl inspect` (`containers.crictl`)                            |
| CRI-O                                 | `crio-<id>.scope`                                                                | `crictl inspect`                                                  |
| Podman                                | `libpod-<id>.scope`, `/libpod_parent/libpod-<id>`                                | Podman's Docker-compatible API socket (`containers.podmanSocket`) |

Podman serves the Docker Engine API on its own socket when its API service runs: `systemctl enable --now podman.socket` for rootful Podman (`/run/podman/podman.sock`, the default), or `systemctl --user enable --now podman.socket` for rootless Podman (`/run/user/<uid>/podman/podman.sock`; set `containers.podmanSocket`). Without the socket, Podman containers are tried through `crictl`, which cannot inspect them (Podman does not serve the CRI): they are skipped, and a service that selects them reports that no running container matches. Docker containers are inspected through `crictl` too when the Docker socket is not at `containers.dockerSocket`.

`auditstatus doctor` checks that the Docker or Podman API socket, or `crictl`, is available when the configuration has a container service, and names the running containers each container service selects; a service that selects none is a warning. For containerd and CRI-O, point `crictl` at the runtime's socket with `CONTAINER_RUNTIME_ENDPOINT` or `/etc/crictl.yaml`.


## What the attester reports

For each matching container:

* the container's id, runtime and name;
* the image the runtime says it runs: its reference, id, the platform manifest digest the runtime recorded (Docker), and its repository digests;
* the platform (CRI runtimes do not report the architecture, so it is this machine's);
* mounts that bring in files from outside the image: volumes and bind mounts, with whether each is read-only;
* the overlay's writable layer: files written, and files deleted (whiteouts);
* with `containers.hashRootfs` (the default), every file of the root filesystem, hashed through `/proc/<pid>/root` of the container's first process as the runtime reports it (Docker and Podman `State.Pid`, `crictl inspect` `info.pid`), other mounts left out, up to `containers.maxFiles`;
* every process, inspected like any other process (runtime injection vectors, executable pages, libraries, tracer, open files).

A process counts as the container's only when it is in the container's cgroup and sees the same root directory as that first process. A cgroup and a root of its own are within reach of a user with unprivileged user namespaces; such a process does not speak for the container, and is left to the host's services.

The runtime's claims are not trusted: the verifier compares the files with the image the runtime names.


## Image resolution by digest

The verifier needs a registry digest to fetch the image. It uses, in order:

1. a repository digest whose repository is the container's image reference;
2. any other repository digest;
3. the image reference itself, when it is pinned by digest (`...@sha256:...`).

With `image.repository`, only digests in those repositories are considered.

With none of these, the image was built on the server or pulled by a tag that was never pushed, and the verifier reports "The image has no registry digest ... so it cannot be compared with a published image" (`policy.containerChanges`, `fail` by default). Deploy images that were pushed to a registry, and prefer references pinned by digest.

The verifier fetches the image by digest, so the registry cannot serve other content under the same name, and selects the manifest for the container's platform. When the runtime recorded the platform manifest it runs, it must be that image's manifest for the platform (or its index); otherwise the container fails.

The registry is named by the evidence, so the verifier contacts only public registries by itself: a registry on a loopback, private, link-local or shared address, or a name without a dot (such as `localhost`), is not contacted unless `references.containerRegistries` names it ("The image's registry ... is not a public host", error).

For a private registry, give the verifier a token:

```yaml
references:
  containerRegistries:
    ghcr.io:
      tokenEnv: GHCR_TOKEN
    registry.example.com:
      url: https://registry.example.com
      tokenEnv: REGISTRY_TOKEN
```


## Root filesystem comparison

With `image.compareFiles` (the default), every image file is compared with the container's:

| Difference                                                       | Finding                                                           | Severity                  |
| ---------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------- |
| A file differs from the image                                    | Files differ from the image                                       | `policy.containerChanges` |
| An image file is missing                                         | Files of the image are missing                                    | `policy.containerChanges` |
| A file is not in the image                                       | Files not in the image are present                                | `policy.containerChanges` |
| A file's mode differs                                            | File modes differ from the image                                  | warn                      |
| The file list was cut at `containers.maxFiles`                   | The file list was truncated by the server's limits                | fail                      |
| Files could not be read                                          | Some container files could not be read                            | fail                      |
| A `*.pid` or `*.lock` file under `/run` that is not in the image | Process id and lock files in /run are not compared with the image | info                      |
| Nothing differs                                                  | All files match the image                                         | info                      |

Ignored in the comparison:

* files every runtime creates or bind-mounts: `.dockerenv`, `etc/hostname`, `etc/hosts`, `etc/resolv.conf`, `etc/mtab`, `run/.containerenv`;
* everything under a mount point;
* process id and lock files the image does not have under `/run` (or `/var/run`), named `*.pid` or `*.lock`, which daemons write when they start (`run/nginx.pid`, PostgreSQL's `run/postgresql/.s.PGSQL.5432.lock`); they are listed as "Process id and lock files in /run are not compared with the image" (info). On a host, `/run` is a tmpfs, whose files are not compared either;
* paths matching `image.allowChanges` (glob patterns relative to `/`, for example `tmp/**`).

With `containers.hashRootfs: false` on the server, the verifier compares only the writable layer: files written in the container must be in the image with the same content, and files deleted from the image are reported missing. This catches changes made in the container, but not a runtime that started the container from other layers than the image's.

With `image.compareFiles: false`, the verifier still checks the image digest and signer, but not the files.


## Mounts

Volumes and bind mounts are not part of the image, so their files cannot be compared with it. Writable mounts are listed in the report ("Writable volumes are not compared with the image"). A mount that covers files of the image hides them: the container sees the mounted files instead, so "Mounts hide files of the image" lists each such mount (`policy.containerChanges`, `fail` by default). Paths matching `image.allowChanges` are left out, for a file mounted on purpose such as a configuration file: nginx with its configuration mounted over `/etc/nginx/conf.d/default.conf` needs `allowChanges: [etc/nginx/conf.d/default.conf]` (the finding names the files a mount hides). Code that runs from a mount is still hashed as an executable or library of the container's processes; unless another reference explains it, it fails as code not in the image (`policy.containerCode`, `fail` by default). Keep code in the image and use volumes for data.


## Image signers

With `image.signer`, the image must carry a GitHub artifact attestation (a Sigstore bundle) signed by the configured repository's workflow. The verifier looks for bundles stored with the image as OCI referrers first, then in GitHub's attestation store. It tries the image index digest (what `docker push` and build actions attest) and the platform manifest digest.

A release workflow that pushes and attests an image:

```yaml
permissions:
  contents: read
  packages: write
  id-token: write
  attestations: write

steps:
  - uses: docker/build-push-action@v6
    id: build
    with:
      push: true
      tags: ghcr.io/example/worker:${{ github.ref_name }}
  - uses: actions/attest-build-provenance@v2
    with:
      subject-name: ghcr.io/example/worker
      subject-digest: ${{ steps.build.outputs.digest }}
      push-to-registry: true
```

A verified signer adds "The image was built and attested by ... from commit ...". An image without a valid attestation fails ("The image is not attested by ..."); when only network errors prevented the check, the result is inconclusive.


## Code in containers

Every file of the image is a reference for the code check: an executable or library of a container's processes that matches its image file is explained. The [monitor](monitor.md) records programs in containers with paths inside the container; those that are image files are not reported.
