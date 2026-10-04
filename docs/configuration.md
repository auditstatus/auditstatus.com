# Configuration

Audit Status reads two configuration files: the attester configuration on each server, and the verifier configuration in the repository that runs the verification. This page lists every setting of both, with its type, default and meaning. Both files are YAML (or JSON). Validation is strict: an unknown key is an error, so a typo cannot silently turn a check off.

Check a file with:

```sh
auditstatus validate --role attester --config /etc/auditstatus/config.yml
auditstatus validate --role verifier --config auditstatus.config.yml
```

YAML is parsed with the JSON schema: no custom tags, and values such as `yes` or `on` are strings, not booleans. Quote hex values that could be read as numbers, such as `'0x81010002'`. Relative paths are resolved against the configuration file's directory.

Annotated examples with every setting: [`examples/attester.yml`](../examples/attester.yml) and [`examples/auditstatus.config.yml`](../examples/auditstatus.config.yml).

Both files have JSON Schemas, generated from the same validation: [attester.schema.json](https://auditstatus.com/schema/attester.schema.json) and [verifier.schema.json](https://auditstatus.com/schema/verifier.schema.json). Editors with the YAML language server validate and complete a file whose first line names its schema:

```yaml
# yaml-language-server: $schema=https://auditstatus.com/schema/attester.schema.json
```

For the verifier configuration, use `https://auditstatus.com/schema/verifier.schema.json`.


## Attester configuration

`/etc/auditstatus/config.yml` on each server. It must be owned by root (or, without capabilities, by the user running the attester) and must not be writable by group or others.

```yaml
version: 2
services:
  - name: web
    root: /var/www/production/current
    user: deploy
  - name: worker
    container:
      image: ghcr.io/example/worker
tpm:
  enabled: auto
```

### Top level

| Key                                               | Type    | Default                       | Meaning                                                |
| ------------------------------------------------- | ------- | ----------------------------- | ------------------------------------------------------ |
| `version`                                         | `2`     | none                          | The configuration format. Any other value is an error. |
| `services`                                        | list    | (required, or the short form) | What runs on this server. See [services](#services).   |
| `runtimes`                                        | mapping |                               | See [runtimes](#runtimes).                             |
| `distro`                                          | mapping |                               | See [distro](#distro).                                 |
| `containers`                                      | mapping |                               | See [containers](#containers).                         |
| `tpm`                                             | mapping |                               | See [tpm](#tpm).                                       |
| `ima`                                             | mapping |                               | See [ima](#ima).                                       |
| `confidential`                                    | mapping |                               | See [confidential](#confidential).                     |
| `monitor`                                         | mapping |                               | See [monitor](#monitor).                               |
| `limits`                                          | mapping |                               | See [limits](#limits).                                 |
| `projectRoot`, `exclude`, `processes`, `packages` |         |                               | The [short form](#short-form).                         |

### services

Each service is either a directory (`root`) or the containers matching a filter (`container`); exactly one of the two is required.

| Key               | Type                                              | Default             | Meaning                                                                                                                                                                                                                                                                                                                          |
| ----------------- | ------------------------------------------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`            | string (letters, digits, `_`, `.`, `-`; up to 64) | (required)          | The service's name. It must match a service in the verifier configuration. Names must be unique.                                                                                                                                                                                                                                 |
| `root`            | path                                              |                     | The deployed directory: a git checkout of the public repository, or a release directory with `.attestium-manifest.json`. A symbolic link is resolved.                                                                                                                                                                            |
| `user`            | user name                                         |                     | Inspect only processes of this user. Looked up in `/etc/passwd`.                                                                                                                                                                                                                                                                 |
| `uid`             | integer                                           |                     | The same, by user id. Takes precedence over `user`.                                                                                                                                                                                                                                                                              |
| `cwd`             | path                                              | the resolved `root` | Inspect processes whose working directory is this directory or inside it. A symbolic link (PM2's `current`) is resolved, as for `root`.                                                                                                                                                                                          |
| `exclude`         | list of glob patterns                             | `[]`                | Paths (relative to `root`) left out of the file list entirely. Files the commit's `.gitignore` ignores are listed but not compared, so this is rarely needed.                                                                                                                                                                    |
| `ecosystems`      | `auto`, `false`, or a list                        | `auto`              | Which installed packages to look for in `root`: `npm`, `pypi`, `rubygems`, `hex`, `composer`, `maven`, `nuget`. `false` turns package checks off for this service.                                                                                                                                                               |
| `installs`        | list                                              | `[]`                | Package install directories to add, for example outside `root`. Each is `{ecosystem, dir}`; both are required, and `dir` is relative to `root` or absolute. `dir` is the directory the table below names: for `pypi` the `site-packages` directory (`/opt/venvs/web/lib/python3.12/site-packages`), not the virtual environment. |
| `container`       | mapping                                           |                     | A container service: every running container that matches all the given filters. At least one is required.                                                                                                                                                                                                                       |
| `container.name`  | string                                            |                     | The container's name.                                                                                                                                                                                                                                                                                                            |
| `container.id`    | hex string (12 to 64)                             |                     | A prefix of the container's id.                                                                                                                                                                                                                                                                                                  |
| `container.image` | string                                            |                     | The image repository, with or without a tag (for example `ghcr.io/example/worker`).                                                                                                                                                                                                                                              |
| `container.label` | `key=value`                                       |                     | A container label.                                                                                                                                                                                                                                                                                                               |

The attester inspects every process whose working directory is inside the service's `cwd` (and whose user matches, when set), whatever its language. Processes in containers are left out of directory services. The same user's other processes are listed in the report but not inspected.

For each directory, installed packages are detected in `root`:

| Ecosystem  | Detected in                                                                                                     |
| ---------- | --------------------------------------------------------------------------------------------------------------- |
| `npm`      | `node_modules`                                                                                                  |
| `pypi`     | `site-packages` of `.venv`, `venv`, `env`, `.virtualenv`, `virtualenv` (virtual environments with `pyvenv.cfg`) |
| `rubygems` | `vendor/bundle/ruby/<version>`, `.bundle/ruby/<version>`                                                        |
| `hex`      | `deps/`, when `mix.lock` exists                                                                                 |
| `composer` | `vendor/`, when `composer.lock` and `vendor/composer` exist                                                     |
| `maven`    | `target/lib`, `target/dependency`, `lib`, `libs`, `build/install/*/lib`, `WEB-INF/lib` of unpacked wars         |
| `nuget`    | .NET publish output (`*.runtimeconfig.json` with `*.deps.json`)                                                 |

### runtimes

| Key                            | Type              | Default                                              | Meaning                                                                                                                          |
| ------------------------------ | ----------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `runtimes.debugPorts`          | list of TCP ports | `[]`                                                 | Debugger and management ports that must not be listening, in addition to each runtime's default ports, which are always checked. |
| `runtimes.node.globalDir`      | path              | found from the first running official Node.js binary | Where the global Node.js packages are installed.                                                                                 |
| `runtimes.node.globalPackages` | list of names     | `[npm, corepack, pnpm, pm2]`                         | Global packages next to Node.js to report and verify.                                                                            |

### distro

| Key              | Type          | Default | Meaning                                                                                                                                                            |
| ---------------- | ------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `distro.enabled` | boolean       | `true`  | Record the Debian or Ubuntu package that owns each executable and library, so the verifier can compare it with the signed archive. Needs a readable dpkg database. |
| `distro.root`    | absolute path | `/`     | The host's root as the attester sees it: `/proc/1/root` in a container that shares the host's PID namespace.                                                       |

### containers

| Key                       | Type                     | Default                   | Meaning                                                                                                                                   |
| ------------------------- | ------------------------ | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `containers.dockerSocket` | path                     | `/var/run/docker.sock`    | The Docker Engine API socket.                                                                                                             |
| `containers.podmanSocket` | path                     | `/run/podman/podman.sock` | Podman's Docker-compatible API socket (`systemctl enable --now podman.socket`; `/run/user/<uid>/podman/podman.sock` for rootless Podman). |
| `containers.crictl`       | command                  | `crictl`                  | `crictl`, to identify containers of CRI runtimes (containerd, CRI-O).                                                                     |
| `containers.hashRootfs`   | boolean                  | `true`                    | Hash every file of each container's root filesystem. When `false`, only the writable layer is compared with the image.                    |
| `containers.maxFiles`     | integer, 1 to 10,000,000 | `500000`                  | The most files hashed per container root filesystem.                                                                                      |

See [Containers](containers.md).

### tpm

| Key               | Type                                 | Default                                                  | Meaning                                                                                                                                          |
| ----------------- | ------------------------------------ | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tpm.enabled`     | `auto`, `true`, `false`              | `auto`                                                   | `auto`: quote when a TPM is present. `true`: report a missing TPM as a failure. `false`: never use the TPM (and refuse `enroll` and `activate`). |
| `tpm.tcti`        | string                               | the tpm2-tools default                                   | The TPM transmission interface, for example `device:/dev/tpmrm0`.                                                                                |
| `tpm.handle`      | string `0x81xxxxxx`                  | `0x81010002`                                             | The persistent handle of the attestation key.                                                                                                    |
| `tpm.bank`        | `sha1`, `sha256`, `sha384`, `sha512` | `sha256`                                                 | The PCR bank to quote.                                                                                                                           |
| `tpm.pcrs`        | list of PCR indexes (0 to 23)        | `[0, 1, 2, 3, 4, 5, 6, 7]`, plus `10` when `ima.enabled` | The PCRs to quote.                                                                                                                               |
| `tpm.ekAlgorithm` | `rsa`, `ecc`                         | `rsa`                                                    | The endorsement key type used for enrollment, and the attestation key type created when there is none.                                           |

See [Hardware evidence](hardware.md#tpm).

### ima

| Key            | Type                       | Default                                                | Meaning                                                                                 |
| -------------- | -------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| `ima.enabled`  | boolean                    | `false`                                                | Include the kernel's IMA measurement log.                                               |
| `ima.log`      | path                       | `/sys/kernel/security/ima/binary_runtime_measurements` | The binary measurement log. With capabilities it must be under `/sys/kernel/security/`. |
| `ima.maxBytes` | integer, 1024 to 536870912 | `67108864` (64 MiB)                                    | The largest log the attester reads.                                                     |

See [Hardware evidence](hardware.md#ima).

### confidential

| Key                    | Type                    | Default                | Meaning                                                                                                                                                                      |
| ---------------------- | ----------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `confidential.enabled` | `auto`, `true`, `false` | `auto`                 | `auto`: on an AMD SEV-SNP or Intel TDX guest (configfs-tsm available), add a hardware report bound to the evidence. `true`: report its absence as a failure. `false`: never. |
| `confidential.entry`   | path                    | a new entry per report | An existing report directory under `/sys/kernel/config/tsm/report/`, created by root at boot. With capabilities it must be under `/sys/kernel/config/tsm/`.                  |

See [Hardware evidence](hardware.md#confidential-vms).

### monitor

| Key                     | Type                   | Default                            | Meaning                                                            |
| ----------------------- | ---------------------- | ---------------------------------- | ------------------------------------------------------------------ |
| `monitor.enabled`       | boolean                | `false`                            | Include what the monitor service recorded.                         |
| `monitor.log`           | path                   | `/var/log/auditstatus/monitor.log` | The monitor's log. With capabilities it must be under `/var/log/`. |
| `monitor.windowSeconds` | integer, 60 to 2592000 | `86400`                            | How far back each report looks.                                    |

See [Monitor](monitor.md).

### limits

| Key                      | Type                     | Default  | Meaning                                                                                           |
| ------------------------ | ------------------------ | -------- | ------------------------------------------------------------------------------------------------- |
| `limits.maxFiles`        | integer, 1 to 10,000,000 | `500000` | The most files reported per directory service. More fails as a truncated file list.               |
| `limits.maxChangedFiles` | integer, 0 to 100,000    | `1000`   | The most files and directories reported as changed after a process started, per process and list. |

### Short form

A server running one application can leave out `services` and use these keys instead. They describe one directory service named `app`. Using both forms in one file is an error.

| Key                        | Type                  | Default                      | Meaning                                                                                                                                                                                   |
| -------------------------- | --------------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `projectRoot`              | path                  | (required in the short form) | The service's `root`.                                                                                                                                                                     |
| `exclude`                  | list of glob patterns | `[]`                         | The service's `exclude`.                                                                                                                                                                  |
| `processes.user`           | user name             |                              | The service's `user`.                                                                                                                                                                     |
| `processes.uid`            | integer               |                              | The service's `uid`.                                                                                                                                                                      |
| `processes.cwdPrefix`      | path                  |                              | The service's `cwd`.                                                                                                                                                                      |
| `processes.inspectorPorts` | list of TCP ports     |                              | Used as `runtimes.debugPorts` when that is not set.                                                                                                                                       |
| `packages.enabled`         | boolean               | `true`                       | `false` turns off installed package checks (`ecosystems: false`) and the global Node.js packages. `packages` is also accepted with `services`, where it affects only the global packages. |
| `packages.globalDir`       | path                  |                              | Used as `runtimes.node.globalDir` when that is not set.                                                                                                                                   |
| `packages.globalPackages`  | list                  |                              | Used as `runtimes.node.globalPackages` when that is not set.                                                                                                                              |


## Verifier configuration

`auditstatus.config.yml` in the repository that runs `auditstatus verify`.

```yaml
version: 2
services:
  - name: web
    repository:
      url: https://github.com/example/app.git
      branch: main
    build:
      command: npm ci && npm run build
      outputs: ['dist/**']
ssh:
  knownHosts: known_hosts
servers:
  - name: web1
    host: web1.example.com
```

### Top level

| Key          | Type    | Default                                                | Meaning                                                                                                                    |
| ------------ | ------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `version`    | `2`     | none                                                   | The configuration format. Any other value is an error.                                                                     |
| `repository` | mapping |                                                        | The repository for services that do not name their own; required when `services` is absent. See [repository](#repository). |
| `build`      | mapping |                                                        | The build for services that do not have their own. See [build](#build).                                                    |
| `services`   | list    | one service named `app` using `repository` and `build` | What each service is verified against. See [services](#services-1).                                                        |
| `servers`    | list    | (required, at least one)                               | The servers to verify. See [servers](#servers).                                                                            |
| `references` | mapping |                                                        | Where references come from. See [references](#references).                                                                 |
| `ssh`        | mapping |                                                        | See [ssh](#ssh).                                                                                                           |
| `kubernetes` | mapping |                                                        | See [kubernetes](#kubernetes).                                                                                             |
| `policy`     | mapping |                                                        | See [policy](#policy).                                                                                                     |
| `output`     | mapping |                                                        | See [output](#output).                                                                                                     |

### repository

| Key       | Type                                   | Default                                         | Meaning                                                                                             |
| --------- | -------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `url`     | `https://`, `file://` or absolute path | (required)                                      | The public repository.                                                                              |
| `branch`  | string                                 | `master`                                        | The audited branch. The deployed commit must be on it. Set it explicitly (`auditstatus init` does). |
| `webUrl`  | `https://` URL                         | the `url` without `.git`, for `github.com` URLs | Used to link commits in `report.md`.                                                                |
| `version` | see below                              | `any`                                           | The version the servers must run.                                                                   |

The verifier keeps a blobless clone and checks out the reported commit in a worktree. Git runs with hooks disabled, no system or global configuration, no prompts, and the `ext` and `fd` transports disabled.

#### version

| Value                    | The servers must run                                                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `any`                    | Any commit of `branch`. A commit older than `policy.maxCommitAgeDays` is a warning.                                                        |
| `latest`                 | The latest commit of `branch`.                                                                                                             |
| `latest-release`         | The commit of the latest release of the GitHub repository (not a draft or prerelease), by its tag. Needs a `github.com` `url` or `webUrl`. |
| a tag, such as `v1.4.2`  | The commit the tag points to.                                                                                                              |
| a 40-character commit id | That commit.                                                                                                                               |

Each run resolves the version once. A server that runs another commit is a `policy.versionMismatch` finding (`fail` by default): "The server runs 3f2a9c81d0e4, not the latest release, v2.1.0 (9b1e44c07a3d)". That commit must still be on `branch`. The version itself need not be (a release tagged on another branch): a server that runs it is never too old, and its build is reproduced as for a commit of `branch`. A version that cannot be resolved (no such tag, GitHub unreachable) makes the result inconclusive.

A version that moves (`latest`, `latest-release`) is deployed some time after it appears. `policy.versionGraceSeconds` (for example `3600`) makes a server that still runs an earlier commit of it a warning for that long after the release was published (by GitHub's clock) or the branch's latest commit was made: "The server runs 3f2a9c81d0e4, an earlier commit than the latest release, v2.1.0 (9b1e44c07a3d), which is 12 minute(s) old: a deploy in progress". After that, or for any other commit, `policy.versionMismatch` applies. Deploy as soon as a release is published, and publish a release for each deploy: a server that runs a newer commit than the latest release is a mismatch too.

### services

| Key           | Type                         | Default                                               | Meaning                                                                                                                                                                                                                                                                                                                                    |
| ------------- | ---------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`        | string                       | (required)                                            | Matches the service of the same name in the attester configuration. Names must be unique.                                                                                                                                                                                                                                                  |
| `repository`  | mapping                      | the top-level `repository`                            | See [repository](#repository). A service needs one unless it has `image`.                                                                                                                                                                                                                                                                  |
| `build`       | mapping                      | the top-level `build`; none for services with `image` | See [build](#build).                                                                                                                                                                                                                                                                                                                       |
| `lockfiles`   | mapping of ecosystem to path | `{}`                                                  | A lockfile not in its default place, relative to the repository root. Keys: `npm`, `pypi`, `rubygems`, `hex`, `composer`, `maven`, `nuget`, `cargo`. For `npm` the file is `pnpm-lock.yaml`, `npm-shrinkwrap.json` or `package-lock.json` (for example `web/package-lock.json`), and the `package.json` next to it holds the pnpm patches. |
| `goModule`    | path                         | `.`                                                   | Where `go.mod` is, for the dependencies built into Go binaries.                                                                                                                                                                                                                                                                            |
| `root`        | absolute path                | the root the server reports                           | Where the service is deployed on its servers (the real path, after symbolic links). A server that reports another root fails. With IMA, project files the kernel measured are compared under this root; without it, under the root the server names, which warns.                                                                          |
| `artifact`    | mapping                      |                                                       | A release deployed without git. See [artifact](#artifact).                                                                                                                                                                                                                                                                                 |
| `image`       | mapping                      |                                                       | Settings for container services. See [image](#image).                                                                                                                                                                                                                                                                                      |
| `executables` | list                         | `[]`                                                  | Programs no other reference explains. See [executables](#executables).                                                                                                                                                                                                                                                                     |

#### artifact

| Key               | Type    | Default    | Meaning                                                     |
| ----------------- | ------- | ---------- | ----------------------------------------------------------- |
| `artifact.signer` | mapping | (required) | Who must have attested the manifest. See [signer](#signer). |

The release manifest is always `.attestium-manifest.json` at the release directory's root, the file `auditstatus manifest` writes and the attester sends.

#### image

| Key                  | Type                  | Default | Meaning                                                                                                                                                                                                                                                                                                            |
| -------------------- | --------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `image.repository`   | string or list        |         | The image repositories the service may run, as `registry/repository` (`ghcr.io/example/worker`; `nginx` is `docker.io/library/nginx`). A container whose image has no registry digest in one of them fails. Without it (and without `signer`), any image the server names is accepted if the container matches it. |
| `image.signer`       | mapping               |         | Require the image to be attested by this workflow. See [signer](#signer).                                                                                                                                                                                                                                          |
| `image.compareFiles` | boolean               | `true`  | Compare the container's files with the image.                                                                                                                                                                                                                                                                      |
| `image.allowChanges` | list of glob patterns | `[]`    | Paths (relative to `/`) the container may write.                                                                                                                                                                                                                                                                   |

#### signer

| Key          | Type                           | Default    | Meaning                                                               |
| ------------ | ------------------------------ | ---------- | --------------------------------------------------------------------- |
| `repository` | `owner/name`                   | (required) | The GitHub repository whose workflow signed the attestation.          |
| `workflow`   | `.github/workflows/<file>.yml` | any        | The workflow file that must have signed it.                           |
| `ref`        | `refs/...`                     | any        | The ref the workflow must have run on, for example `refs/heads/main`. |

#### executables

| Key                             | Type                                    | Default                                                    | Meaning                                                                                                                                                                                                                                                |
| ------------------------------- | --------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `path`                          | absolute path                           | (required)                                                 | The program's path on the server.                                                                                                                                                                                                                      |
| `sha256`                        | list of hex SHA-256                     | `[]`                                                       | Accepted hashes.                                                                                                                                                                                                                                       |
| `checksums.url`                 | `https://` URL                          | (required with `checksums`)                                | A checksum list the project publishes (`<hash>  <file>` or `SHA256 (<file>) = <hash>` lines). The program matches when the list gives its hash for its file name (`checksums.name`), or for that name in a directory of the list (`linux-amd64/tool`). |
| `checksums.name`                | file name                               | the base name of `path`                                    | The program's name in the list, when it is installed under another name.                                                                                                                                                                               |
| `checksums.signature.type`      | `gpg`, `minisign`, `sigstore`           | (required with `signature`)                                | How the list is signed. Without `signature`, the list is trusted as far as HTTPS and its host.                                                                                                                                                         |
| `checksums.signature.url`       | URL                                     | the list's URL plus `.sig`, `.minisig` or `.sigstore.json` | The signature.                                                                                                                                                                                                                                         |
| `checksums.signature.keyring`   | path                                    |                                                            | `gpg`: the keyring to check with (`gpgv`).                                                                                                                                                                                                             |
| `checksums.signature.publicKey` | base64 key                              |                                                            | `minisign`: the public key (the second line of the `.pub` file).                                                                                                                                                                                       |
| `checksums.signature.identity`  | mapping of claim to string or `/regex/` |                                                            | `sigstore`: certificate claims the signer must have, for example `subjectAlternativeName`.                                                                                                                                                             |

### build

| Key              | Type                      | Default                             | Meaning                                                                                                                                                                                                                                                                                                                         |
| ---------------- | ------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `command`        | string                    | (required)                          | Run with `/bin/sh -c` in a clean checkout of the deployed commit.                                                                                                                                                                                                                                                               |
| `outputs`        | list of glob patterns     | (required, not empty)               | The files the build produces, compared with the server's. Patterns under `node_modules` are not allowed. Outputs inside another install directory (a .NET publish directory, `vendor/` of Composer, a directory of jars) are compared with the files the attester hashed there, and the package check leaves them to the build. |
| `env`            | mapping of name to string | `{}`                                | Variables set for the build.                                                                                                                                                                                                                                                                                                    |
| `passEnv`        | list of names             | `[]`                                | Variables passed on from the verifier's environment.                                                                                                                                                                                                                                                                            |
| `timeoutSeconds` | integer, 60 to 21600      | `3600`                              | The build's time limit.                                                                                                                                                                                                                                                                                                         |
| `user`           | account name              | `AUDITSTATUS_BUILD_USER`, else none | An unprivileged account the build runs as (Linux). The verifier must run as root or have passwordless `sudo`. Without one, the build runs as the verifier's user and can read its secrets and change its cache. The GitHub action creates `auditstatus-build` and sets `AUDITSTATUS_BUILD_USER`.                                |

See [Verifier](verifier.md#builds).

### servers

| Key                         | Type                              | Default                        | Meaning                                                                                                                                                                                   |
| --------------------------- | --------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                      | string                            | (required)                     | The server's name in the report. Names must be unique.                                                                                                                                    |
| `transport`                 | `ssh`, `kubernetes`, `local`      | `ssh`                          | How the verifier reaches the attester.                                                                                                                                                    |
| `host`                      | host name, IPv4, or `[IPv6]`      | (required for `ssh`)           | The server's address.                                                                                                                                                                     |
| `port`                      | integer                           | `ssh.port`                     | The SSH port.                                                                                                                                                                             |
| `user`                      | user name                         | `ssh.user`                     | The SSH user.                                                                                                                                                                             |
| `attesterConfig`            | path                              | (required for `local`)         | The attester configuration to collect with, in the verifier's process.                                                                                                                    |
| `services`                  | list of service names             | all services                   | The services this server runs. Each must be defined in `services`.                                                                                                                        |
| `minProcesses`              | integer, 0 to 100,000             | `1`                            | Fewer processes across the server's services fails.                                                                                                                                       |
| `kubernetes.node`           | string                            |                                | The node whose attester pod to reach. `node` or `pod` is required for `kubernetes`.                                                                                                       |
| `kubernetes.pod`            | string                            |                                | A specific attester pod.                                                                                                                                                                  |
| `kubernetes.namespace`      | string                            | `kubernetes.namespace`         | The attester's namespace.                                                                                                                                                                 |
| `kubernetes.selector`       | label selector                    | `kubernetes.selector`          | Selects the attester pods.                                                                                                                                                                |
| `kubernetes.daemonSet`      | string                            | `kubernetes.daemonSet`         | The attester DaemonSet; only a pod it controls, running its pod template, answers.                                                                                                        |
| `kubernetes.context`        | string                            | the current context            | The kubeconfig context.                                                                                                                                                                   |
| `tpm.publicKey`             | PEM public key                    |                                | The pinned attestation key, printed by `auditstatus tpm-verify`. A pinned key makes a valid quote mandatory.                                                                              |
| `tpm.required`              | boolean                           | `true` when `publicKey` is set | Requires `publicKey` (`auditstatus tpm-verify --server <name>` prints it).                                                                                                                |
| `tpm.expectedPcrs`          | mapping of bank to `{index: hex}` |                                | PCR values the quote must show.                                                                                                                                                           |
| `tpm.ima`                   | boolean                           | `false`                        | Require an IMA log that replays to the quoted PCR 10 (evidence level `TPM + IMA`). Requires `publicKey`. Without it, a server that stops sending the log drops to `TPM` and still passes. |
| `tpm.ekCertificate`         | base64                            |                                | The endorsement certificate `tpm-verify` printed, recorded for reference. It is not checked again; it only adds "enrolled against the TPM's endorsement certificate" to the TPM finding.  |
| `confidential.required`     | boolean                           | `true`                         | Fail when the server sends no confidential VM report.                                                                                                                                     |
| `confidential.type`         | `sev-snp`, `tdx`                  | any                            | The expected technology.                                                                                                                                                                  |
| `confidential.measurements` | list of hex                       | `[]`                           | Accepted launch measurements. Without any, a verified report warns.                                                                                                                       |
| `confidential.mrConfigId`   | hex                               |                                | Intel TDX: the expected MRCONFIGID.                                                                                                                                                       |
| `confidential.mrOwner`      | hex                               |                                | Intel TDX: the expected MROWNER.                                                                                                                                                          |

See [Hardware evidence](hardware.md) for `tpm` and `confidential`, and [Kubernetes](kubernetes.md) for `kubernetes`.

### references

| Key                    | Type                                     | Default                                                                                  | Meaning                                                                                                                                        |
| ---------------------- | ---------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `nodeDistUrl`          | URL                                      | `https://nodejs.org/dist`                                                                | Official Node.js releases.                                                                                                                     |
| `nodeKeyring`          | path                                     |                                                                                          | A GPG keyring to check the Node.js release's signed `SHASUMS256.txt` with.                                                                     |
| `registryUrl`          | URL                                      | `https://registry.npmjs.org`                                                             | The npm registry.                                                                                                                              |
| `githubArchiveUrl`     | URL                                      | `https://codeload.github.com`                                                            | Archives of GitHub commits, for dependencies pinned to a commit.                                                                               |
| `registries`           | mapping                                  | `{}`                                                                                     | Mirrors for other ecosystems. Keys: `pypi`, `rubygems`, `hex`, `nuget`, `maven`, `packagist`, `uvSource`, `goproxy`, `crates`.                 |
| `npmProvenance`        | boolean                                  | `false`                                                                                  | Report which repository and commit built each npm package (Sigstore provenance). Provenance that does not verify fails.                        |
| `sigstore.tufUrl`      | URL                                      | `https://tuf-repo-cdn.sigstore.dev`                                                      | Sigstore's TUF repository, for the trust root.                                                                                                 |
| `sigstore.trustedRoot` | path                                     |                                                                                          | A Sigstore trusted root JSON file to use instead of TUF.                                                                                       |
| `distro.enabled`       | boolean                                  | `true`                                                                                   | Compare system binaries and libraries with the signed Debian or Ubuntu archive.                                                                |
| `distro.archives`      | list                                     | the default archives for the server's release                                            | Archives to use. Each has `url`, `suites`, `components`, `keyring` (all required), and `snapshot` (an `https://` URL for superseded versions). |
| `containerRegistries`  | mapping of registry to `{url, tokenEnv}` | `{}`                                                                                     | An endpoint to use for a registry, and the environment variable holding its token.                                                             |
| `githubApiUrl`         | URL                                      | `https://api.github.com`                                                                 | GitHub's API, for artifact attestations. Set it for GitHub Enterprise Server.                                                                  |
| `githubTokenEnv`       | variable name                            | `GITHUB_TOKEN`                                                                           | The variable holding a GitHub token, which raises the API rate limit.                                                                          |
| `amdKdsUrl`            | URL                                      | `https://kdsintf.amd.com`                                                                | AMD's key distribution service, for SEV-SNP chip certificates.                                                                                 |
| `tpmRoots`             | list of paths                            | `[]`                                                                                     | TPM manufacturer CA certificates (PEM) for `auditstatus tpm-verify`.                                                                           |
| `auditorChecksumsUrl`  | URL containing `{version}`               | `https://github.com/auditstatus/auditstatus.com/releases/download/v{version}/SHA256SUMS` | Where the attester's release checksums are.                                                                                                    |
| `cacheDir`             | path                                     | `.cache/auditstatus`                                                                     | The reference cache, relative to the configuration file.                                                                                       |

URLs must be `https://`, or `http://` to `127.0.0.1` or `localhost`. Archive URLs in `distro.archives` may be `http://`, since the archive's `Release` file is signed. The default archives are the Ubuntu archive (`archive.ubuntu.com`, or `ports.ubuntu.com` for other architectures) with its snapshot service, and for Debian `deb.debian.org` and `debian-security` with `snapshot.debian.org`. The default keyrings are `/usr/share/keyrings/ubuntu-archive-keyring.gpg` and `/usr/share/keyrings/debian-archive-keyring.gpg`, which must exist on the verifier (the GitHub action installs `debian-archive-keyring` when it is missing).

### ssh

| Key              | Type               | Default       | Meaning                                                 |
| ---------------- | ------------------ | ------------- | ------------------------------------------------------- |
| `user`           | user name          | `auditstatus` | The account on each server.                             |
| `port`           | integer            | `22`          | The SSH port.                                           |
| `knownHosts`     | path               | `known_hosts` | Pinned host keys.                                       |
| `identityFile`   | path               |               | The private key, when `AUDITSTATUS_SSH_KEY` is not set. |
| `timeoutSeconds` | integer, 5 to 3600 | `600`         | Time limit per server.                                  |
| `command`        | command            | `ssh`         | The SSH client.                                         |

### kubernetes

| Key              | Type               | Default                                       | Meaning                                                                                                                                                                       |
| ---------------- | ------------------ | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kubectl`        | command            | `kubectl`                                     | The kubectl binary.                                                                                                                                                           |
| `kubeconfig`     | path               | kubectl's default (`KUBECONFIG`)              | The kubeconfig file.                                                                                                                                                          |
| `namespace`      | string             | `auditstatus`                                 | The attester's namespace.                                                                                                                                                     |
| `selector`       | label selector     | `app.kubernetes.io/name=auditstatus-attester` | Selects the attester pods.                                                                                                                                                    |
| `daemonSet`      | string             | `auditstatus-attester`                        | The attester DaemonSet (the Helm chart's name): only a pod it controls, running its pod template, answers for a node. See [Kubernetes](kubernetes.md#verifier-configuration). |
| `port`           | integer            | `8740`                                        | The port the attester pods listen on (`auditstatus serve --listen`, the chart's `port`).                                                                                      |
| `timeoutSeconds` | integer, 5 to 3600 | `600`                                         | Time limit per request.                                                                                                                                                       |

### policy

Settings with the values `fail` or `warn` choose the severity of a finding. See [Reports](reports.md) for each finding.

| Key                         | Type                  | Default | Meaning                                                                                                                                                                                                                                                                                                                    |
| --------------------------- | --------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allowUntracked`            | list of glob patterns | `[]`    | Files not in the commit and not ignored by it, allowed anyway. Also applies to release manifests.                                                                                                                                                                                                                          |
| `codePaths`                 | list of glob patterns | `[]`    | Paths that hold code: files there that the commit ignores must be explained by a build (`unexplainedCode`).                                                                                                                                                                                                                |
| `modifiedAfterStart`        | `fail`, `warn`        | `fail`  | Tracked files, build output or installed packages written after a process started, and PM2's files written after its daemon started.                                                                                                                                                                                       |
| `metadataChangedAfterStart` | `fail`, `warn`        | `fail`  | The same whose status alone changed (a new mode or owner, or contents restored with an earlier modification time), and their directories whose entries changed (a file added and removed again).                                                                                                                           |
| `unofficialNode`            | `fail`, `warn`        | `fail`  | A Node.js binary that differs from the official release of its version.                                                                                                                                                                                                                                                    |
| `unverifiedAuditor`         | `fail`, `warn`        | `fail`  | The attester binary does not match a published release (or a hash in `attesters`), and evidence from an attester `attesters` does not name. When the checksums cannot be fetched, `fail` makes the result inconclusive.                                                                                                    |
| `attesters`                 | list                  | `[]`    | Other attester implementations whose evidence is accepted: `name` (the name the evidence reports; not `auditstatus`), and `sha256` (hashes of its binaries) or `checksumsUrl` (a checksum list, `{version}` replaced by the reported version), or both. Evidence from any other attester is judged by `unverifiedAuditor`. |
| `unverifiablePackages`      | `fail`, `warn`        | `fail`  | Installed packages that cannot be verified, or no lockfile pins them.                                                                                                                                                                                                                                                      |
| `buildOutputs`              | `fail`, `warn`        | `fail`  | Build output that differs from the reproduced build.                                                                                                                                                                                                                                                                       |
| `unexplainedCode`           | `fail`, `warn`        | `warn`  | Executables and libraries no reference explains, and ignored files in `codePaths`.                                                                                                                                                                                                                                         |
| `containerCode`             | `fail`, `warn`        | `fail`  | Executables and libraries a container runs that are not in its image (from a volume, a bind mount or the writable layer) and no other reference explains. Applies once the image could be read; otherwise `unexplainedCode` does.                                                                                          |
| `bytecode`                  | `fail`, `warn`        | `warn`  | Python bytecode caches, which are not verified.                                                                                                                                                                                                                                                                            |
| `builtPackages`             | `fail`, `warn`        | `warn`  | Gems with native extensions compiled on the server (RubyGems only).                                                                                                                                                                                                                                                        |
| `unpinnedPackages`          | `fail`, `warn`        | `warn`  | Packages compared with a registry because the lockfile pins no hash.                                                                                                                                                                                                                                                       |
| `containerChanges`          | `fail`, `warn`        | `fail`  | Container files that differ from the image, and images without a registry digest.                                                                                                                                                                                                                                          |
| `monitor`                   | `fail`, `warn`        | `fail`  | Programs the monitor saw that no reference explains or that are gone, and monitor errors. Paths longer than the monitor keeps are a warning.                                                                                                                                                                               |
| `maxEvidenceAgeSeconds`     | integer, 10 to 86400  | `900`   | The oldest evidence accepted.                                                                                                                                                                                                                                                                                              |
| `maxCommitAgeDays`          | integer, 1 to 3650    | `30`    | Warn when the deployed commit is older (with `repository.version: any`).                                                                                                                                                                                                                                                   |
| `versionMismatch`           | `fail`, `warn`        | `fail`  | A server runs another commit than `repository.version` names.                                                                                                                                                                                                                                                              |
| `versionGraceSeconds`       | integer, 0 to 86400   | `0`     | With `repository.version` `latest` or `latest-release`: for this long after the version appeared, a server that runs an earlier commit of it is a warning (a deploy in progress). See [version](#version).                                                                                                                 |
| `retryAfterSeconds`         | integer, 0 to 3600    | `0`     | Collect a server that failed or was inconclusive again after this delay, and report the second result. `0`: no retry.                                                                                                                                                                                                      |

### output

| Key     | Type   | Default        | Meaning                                                                                 |
| ------- | ------ | -------------- | --------------------------------------------------------------------------------------- |
| `dir`   | path   | `audit-status` | Where `report.json`, `report.md` and `badge.json` are written. `--output` overrides it. |
| `label` | string | `audit`        | The badge's label.                                                                      |
