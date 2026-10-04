# Attester

The attester runs on each audited server. It reads the deployed files, installed packages and running processes, and reports them as evidence when the verifier asks. This page covers installing the release binary, giving it the permissions it needs, the SSH forced command, the Ansible role, the local commands, and how PM2 and git-based deploys are checked.


## Install the release binary

Releases publish single executables (Node.js with the bundled CLI) for `linux-x64`, `linux-arm64` and `darwin-arm64`, a `SHA256SUMS` file, an `install.sh` script, and [build provenance](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) for each file.

Install a pinned version by hand:

```sh
VERSION=<version>
curl -fsSLO "https://github.com/auditstatus/auditstatus.com/releases/download/v${VERSION}/auditstatus-linux-x64"
curl -fsSLO "https://github.com/auditstatus/auditstatus.com/releases/download/v${VERSION}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify auditstatus-linux-x64 --repo auditstatus/auditstatus.com
sudo install -o root -g root -m 0755 auditstatus-linux-x64 /usr/local/bin/auditstatus
```

Or use the installer, which checks the binary against `SHA256SUMS` before it installs it:

```sh
curl -fsSLO https://github.com/auditstatus/auditstatus.com/releases/latest/download/install.sh
AUDITSTATUS_VERSION=<version> bash install.sh
```

| Variable              | Default            | Meaning                                      |
| --------------------- | ------------------ | -------------------------------------------- |
| `AUDITSTATUS_VERSION` | the latest release | The release to install, for example `2.0.0`. |
| `AUDITSTATUS_BIN_DIR` | `/usr/local/bin`   | Where to install `auditstatus`.              |

Run the release binary on servers, not the npm package. The verifier compares the attester's own executable with the release's `SHA256SUMS` (`policy.unverifiedAuditor`, `fail` by default), and an npm installation runs a Node.js binary that is not in that list.


## Permissions: capabilities or root

The attester reads other users' processes (their environment, memory maps and executable pages) and files. It needs either root or two file capabilities. With the capabilities, the binary can read files other local users cannot, so let only root and the verifier's account run it (create the account first, as below). Set the group and mode first: changing the owner or group clears file capabilities.

```sh
sudo chgrp auditstatus /usr/local/bin/auditstatus
sudo chmod 0750 /usr/local/bin/auditstatus
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep /usr/local/bin/auditstatus
```

`/proc/<pid>/environ` and `/proc/<pid>/mem` are readable only by the process owner, so reading them for another user needs `CAP_DAC_READ_SEARCH` as well as `CAP_SYS_PTRACE`. Without root or these capabilities, `doctor` warns that only this user's processes can be inspected, and process checks that cannot run make the result inconclusive, never passing.

A non-root process with capabilities is locked down so that the account running it cannot borrow them:

* Only the attester commands run: `ssh`, `serve`, `collect`, `check`, `doctor` (attester role), `tpm-enroll` and `monitor`. Anything else fails with "with capabilities, only the attester commands are available".
* Only `/etc/auditstatus/config.yml` is read, and it must be owned by root.
* `ima.log` must be under `/sys/kernel/security/`, `monitor.log` under `/var/log/`, and `confidential.entry` under `/sys/kernel/config/tsm/`.
* The release binary runs with `--disable-sigusr1` and a `SIGUSR1` handler, so the signal cannot open the Node.js inspector. Node.js also ignores `NODE_OPTIONS` in a process with file capabilities.

Running as root works too. In both cases the configuration file must not be writable by group or others. Without capabilities, a file owned by the current user is also accepted.


## The configuration file

The attester reads `/etc/auditstatus/config.yml` by default (`--config` for another file, except with capabilities). `auditstatus init` writes a starting one as `auditstatus/attester.config.yml`. Check a file before installing it:

```sh
auditstatus validate --role attester --config attester.config.yml
```

A minimal configuration:

```yaml
version: 2
services:
  - name: web
    root: /var/www/production/current
    user: deploy
```

See [Configuration](configuration.md#attester-configuration) for every setting.


## The SSH forced command

The verifier connects as a dedicated account whose key may only run the attester. Create the account (add it to the `tss` group if the server has a TPM):

```sh
sudo useradd --system --create-home --shell /bin/sh auditstatus
```

Add the verifier's public key to `~auditstatus/.ssh/authorized_keys` with a forced command and `restrict` (no forwarding, no TTY):

```text
command="/usr/local/bin/auditstatus ssh",restrict ssh-ed25519 AAAA... audit-status
```

Keep `~auditstatus/.ssh` and `authorized_keys` owned by root, so the account cannot replace its own keys. The forced command reads the requested operation from `SSH_ORIGINAL_COMMAND` and accepts only:

| Operation               | What it returns                                                                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `check <nonce>`         | Evidence for this nonce (64 lowercase hex characters).                                                                                |
| `enroll`                | The TPM's attestation key and endorsement key; it creates the attestation key if there is none. See [Hardware evidence](hardware.md). |
| `activate <credential>` | The secret in a credential the verifier encrypted to the endorsement key, proving both keys are in the same TPM.                      |

Anything else prints `auditstatus: this key may only run "check <64 hex nonce>", "enroll" or "activate <credential>"` and exits with `2`.

On the verifier side, pin each server's host key in `known_hosts` (see [Verifier](verifier.md#ssh)).


## Commands on the server

| Command                  | Options                                                | What it does                                                                                                                                                                                                                                              |
| ------------------------ | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auditstatus doctor`     | `--config file`, `--role attester` (default), `--json` | Checks that this server can produce complete evidence, and prints a `fix:` line for each problem. Exits `1` while any check fails.                                                                                                                        |
| `auditstatus check`      | `--config file`, `--json`                              | Collects evidence with a random nonce and prints a summary: services, commits, packages, processes, hardware evidence, monitor, and process findings. Exits `1` on critical process findings and `3` when checks could not run. It is not a verification. |
| `auditstatus collect`    | `--config file`, `--nonce hex`                         | Prints the full evidence as JSON (with a random nonce unless given).                                                                                                                                                                                      |
| `auditstatus tpm-enroll` | `--config file`                                        | Prints the TPM enrollment (the same as the `enroll` operation).                                                                                                                                                                                           |
| `auditstatus monitor`    | `--config file`                                        | Runs bpftrace and records every program and library loaded. Runs as a service; see [Monitor](monitor.md).                                                                                                                                                 |
| `auditstatus serve`      | `--config file`, `--listen 127.0.0.1:8740`             | Answers the three operations over HTTP on a loopback address, for Kubernetes. The verifier's `kubernetes.port` must be the port given here. See [Kubernetes](kubernetes.md).                                                                              |
| `auditstatus ssh`        | `--config file`                                        | The forced command.                                                                                                                                                                                                                                       |

Run them as the account the verifier uses, so they see what the verifier will see:

```sh
sudo -u auditstatus auditstatus doctor
sudo -u auditstatus auditstatus check
```

`doctor` checks, in order: the configuration; permissions (root, or `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`); for each directory service, that the root exists and is a git checkout or a release with `.attestium-manifest.json`, the installed packages found, and that at least one process runs from it as the configured user with every check able to run (each such process is checked, and their runtimes named); the Docker socket or `crictl` for container services, and the running containers each one selects (none is a warning); the dpkg database; the TPM and its attestation key; the IMA log; configfs-tsm for confidential VMs; and the monitor log and `bpftrace`.


## The Ansible role

`ansible/roles/auditstatus_attester` installs the attester the same way on many servers. Use the playbook in `ansible/attester.yml` as a start:

```sh
ansible-playbook -i inventory ansible/attester.yml
```

```yaml
- name: Install the Audit Status attester
  hosts: all
  become: true
  roles:
    - role: auditstatus_attester
      vars:
        auditstatus_sha256: "<SHA-256 of auditstatus-linux-x64 from SHA256SUMS>"
        auditstatus_verifier_keys:
          - ssh-ed25519 AAAA... verifier
        auditstatus_config:
          version: 2
          services:
            - name: web
              root: /var/www/app/current
              user: deploy
        auditstatus_tpm: true
```

| Variable                    | Default                        | Meaning                                                                                     |
| --------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------- |
| `auditstatus_version`       | `2.0.0`                        | The release to install.                                                                     |
| `auditstatus_sha256`        | (required)                     | The SHA-256 of the binary for this machine's architecture, from the release's `SHA256SUMS`. |
| `auditstatus_arch`          | `arm64` on aarch64, else `x64` | The binary's architecture.                                                                  |
| `auditstatus_url`           | the release download URL       | Where to download the binary.                                                               |
| `auditstatus_bin`           | `/usr/local/bin/auditstatus`   | Where to install it.                                                                        |
| `auditstatus_user`          | `auditstatus`                  | The account the verifier connects as.                                                       |
| `auditstatus_verifier_keys` | `[]`                           | Public keys allowed to run the attester (and nothing else).                                 |
| `auditstatus_capabilities`  | `true`                         | Set `cap_sys_ptrace,cap_dac_read_search+ep` on the binary.                                  |
| `auditstatus_config`        | `{version: 2, services: []}`   | The content of `/etc/auditstatus/config.yml`. At least one service is required.             |
| `auditstatus_tpm_group`     | `tss`                          | The group that owns the TPM device.                                                         |
| `auditstatus_tpm`           | `false`                        | Add the account to `auditstatus_tpm_group`.                                                 |
| `auditstatus_monitor`       | `false`                        | Install `bpftrace` and the monitor service.                                                 |

The role downloads the binary and checks its SHA-256, sets the capabilities, creates the account with a root-owned `.ssh` directory, writes `authorized_keys` with `command="<auditstatus_bin> ssh",restrict` for each key, writes the configuration after `auditstatus validate --role attester` accepts it, optionally installs the monitor, and finally prints the output of `auditstatus doctor` run as the account.


## The monitor service

`packaging/systemd/auditstatus-monitor.service` runs `auditstatus monitor` as root and writes `/var/log/auditstatus/monitor.log`. Enable it and set `monitor.enabled: true` in the configuration. See [Monitor](monitor.md).


## Git deploys and PM2

Forward Email deploys with git and [PM2](https://pm2.keymetrics.io/): each server holds a git checkout of the public repository, installs dependencies from the lockfile, builds, and reloads the PM2 applications. Audit Status checks each part of that:

* **The checkout.** Set `root` to the directory the application runs from. It may be a symbolic link (for example PM2 deploy's `current`); the attester resolves it. The attester reads the commit from `.git` without running git. The verifier requires the commit to be on the audited branch and every tracked file to match it. Files the commit's `.gitignore` ignores (`.env`, logs, uploads) are listed by top-level directory but not compared.
* **Dependencies.** `node_modules` is compared, file by file, with the packages the lockfile at the commit pins.
* **Build output.** Files the deploy generates and the repository ignores are compared with a build of the same commit, when the verifier configuration has a `build` section.
* **Every worker.** The attester inspects every process of the service's `user` whose working directory is inside `root`. In PM2 cluster mode, each worker is its own Node.js process, and each is inspected: its runtime's injection vectors (`NODE_OPTIONS`, preloads, inspector flags and ports), its executable pages against the files, its libraries, tracer and open files. The PM2 daemon usually runs from another directory; it is listed in the report as another program of the same user, not inspected.
* **PM2 options.** The `node_args` and `interpreter_args` PM2 starts an application with (from `pm2_env`, or the variables of fork mode) are checked for preloads and inspector flags. PM2 renames the processes it starts; a rewritten command line is accepted only for a child of the PM2 daemon.
* **PM2 itself.** `pm2`, `npm`, `corepack` and `pnpm` installed next to the Node.js binary are compared with their references (`runtimes.node.globalPackages`).
* **The Node.js binary.** A running official Node.js binary embeds its release URL; the verifier compares it with that official release (`policy.unofficialNode`).
* **Restarts.** A tracked file, build output or file in `node_modules` written after a process started means the process may run code that is no longer on disk. That fails (`policy.modifiedAfterStart`) until the process restarts. Restoring the original contents does not hide it: Linux sets a file's status-change time on every change, and a file whose status alone changed (contents restored with an earlier modification time), or a directory whose entries changed (a file added and removed again), fails too (`policy.metadataChangedAfterStart`). PM2's own files are compared with the start of the PM2 daemon, which starts each worker through them: after upgrading PM2, run `pm2 update`.

Set `minProcesses` on the server in the verifier configuration to the number of workers you expect, so a server with fewer running is reported:

```yaml
servers:
  - name: web1
    host: web1.example.com
    minProcesses: 4
```

A deploy in progress looks like tampering for a few minutes: files change under running processes, and a build runs. Set `policy.retryAfterSeconds` (for example `600`) so a server that fails is collected again after that delay; the second result is reported, with what the first attempt found kept as a warning. See [Verifier](verifier.md#retries).
