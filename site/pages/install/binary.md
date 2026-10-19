<!--
title: Install the Audit Status attester binary on Linux
description: Install the Audit Status release binary on a Linux server: checksum and provenance checks, capabilities, the SSH forced command and doctor.
label: Release binary
kind: howto
keywords: audit status binary, install attester linux, auditstatus install.sh, sha256sums, setcap cap_sys_ptrace, ssh forced command
-->

<!--lint disable no-heading-punctuation-->

# Install the attester binary on a Linux server

The attester is one executable: Node.js with the Audit Status command line tool bundled in, with no runtime dependencies. Each release publishes it for `linux-x64`, `linux-arm64` and `darwin-arm64`, with a `SHA256SUMS` file, an `install.sh` script and build provenance for every file. Servers run this binary, because the verifier compares the attester's own executable with `SHA256SUMS` and fails a server whose attester does not match.


## 1. Download and check the binary

Pin a version, check the binary against the release's checksums, and check its build provenance with the GitHub CLI:

```sh
VERSION=<version>
curl -fsSLO "https://github.com/auditstatus/auditstatus.com/releases/download/v${VERSION}/auditstatus-linux-x64"
curl -fsSLO "https://github.com/auditstatus/auditstatus.com/releases/download/v${VERSION}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify auditstatus-linux-x64 --repo auditstatus/auditstatus.com
sudo install -o root -g root -m 0755 auditstatus-linux-x64 /usr/local/bin/auditstatus
```

Or use the installer, which picks the binary for the machine's operating system and architecture and refuses to install it when its checksum does not match `SHA256SUMS`:

```sh
curl -fsSLO https://github.com/auditstatus/auditstatus.com/releases/latest/download/install.sh
AUDITSTATUS_VERSION=<version> bash install.sh
```

`AUDITSTATUS_VERSION` defaults to the latest release, and `AUDITSTATUS_BIN_DIR` to `/usr/local/bin`.


## 2. Create the verifier's account

The verifier connects as a dedicated account. Add it to the `tss` group if the server has a TPM:

```sh
sudo useradd --system --create-home --shell /bin/sh auditstatus
```


## 3. Give the attester read access

The attester reads other users' processes and files, so it needs root or two file capabilities: `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. Let only root and the verifier's account run the binary, and set the group and mode before the capabilities, since changing the owner or group clears them:

```sh
sudo chgrp auditstatus /usr/local/bin/auditstatus
sudo chmod 0750 /usr/local/bin/auditstatus
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep /usr/local/bin/auditstatus
```

With capabilities, the binary locks itself down: only the attester commands run, only `/etc/auditstatus/config.yml` is read, and that file must be owned by root.


## 4. Install the configuration

`auditstatus init` writes a starting configuration in your repository as `auditstatus/attester.config.yml`. Install it as `/etc/auditstatus/config.yml`, owned by root and not writable by group or others:

```sh
sudo install -d -o root -g root -m 0755 /etc/auditstatus
sudo install -o root -g root -m 0644 attester.config.yml /etc/auditstatus/config.yml
```

A minimal configuration names one service, where it is deployed, and the account it runs as:

```yaml
version: 2
services:
  - name: web
    root: /var/www/production/current
    user: deploy
```


## 5. Allow the verifier's SSH key

Add the verifier's public key with a forced command and `restrict`, so the key can only run the attester. Keep the `.ssh` directory owned by root, so the account cannot replace its own keys:

```sh
sudo install -d -o root -g auditstatus -m 0755 ~auditstatus/.ssh
echo "command=\"/usr/local/bin/auditstatus ssh\",restrict ssh-ed25519 AAAA... verifier" | sudo tee ~auditstatus/.ssh/authorized_keys
```

For the [public registry](/docs/registry/), the key is Audit Status's own, `verifier/auditstatus.pub` in the repository.


## 6. Check the server

Run `doctor` as the account the verifier uses, so it sees what the verifier will see:

```sh
sudo -u auditstatus auditstatus doctor
sudo -u auditstatus auditstatus check
```

`doctor` checks the configuration, the permissions, each service's checkout, packages and processes, the container runtime, the TPM, IMA and the monitor, and prints a `fix:` line for each problem. It exits with `1` while any check fails. `check` prints a summary of the evidence the verifier would receive.


## What does the attester send?

Paths and SHA-256 hashes, never file contents (the release manifest, `.attestium-manifest.json`, is the one file sent whole): the deployed commit, installed packages, each process's executable and libraries, containers and their images, and the TPM quote or confidential VM report when there is one. Environment values stay on the server. Command lines reach the verifier over SSH but never the report, since they can hold secrets. See [What leaves the server](/docs/threat-model/#what-leaves-the-server-and-what-is-published).


## Record what runs between audits

The same binary runs the monitor, which records every program and library loaded between two audits with bpftrace. The repository ships a systemd unit for it, `packaging/systemd/auditstatus-monitor.service`. See [Monitor](/docs/monitor/).

Next, set up a verifier: the [GitHub Action](/install/github-action/), [`auditstatus verify` from npm](/install/npm/), or the [public registry](/docs/registry/#add-your-project).
