<!--
title: Install the Audit Status attester with Ansible
description: Use the Audit Status Ansible role to install the attester on many servers: pinned SHA-256, capabilities, forced-command SSH keys, configuration and monitor.
label: Ansible role
kind: howto
keywords: audit status ansible role, auditstatus_attester, ansible install attester, ansible-playbook attestation, configuration management
-->

<!--lint disable no-heading-punctuation-->

# Install the attester with Ansible

The Ansible role `auditstatus_attester` installs the Audit Status attester the same way on every server: the release binary checked against a pinned SHA-256, its capabilities, the verifier's account with forced-command SSH keys, the configuration, and optionally the monitor. It ends by running `auditstatus doctor` as the verifier's account and printing the result.

The role needs Ansible 2.15 or later and targets Debian 12 and 13 and Ubuntu 22.04 and 24.04. It lives in the repository under `ansible/roles/auditstatus_attester`, with a starting playbook in `ansible/attester.yml`.


## 1. Get the role

Clone the repository, or copy `ansible/roles/auditstatus_attester` into your own roles directory:

```sh
git clone https://github.com/auditstatus/auditstatus.com.git
cd auditstatus.com
```


## 2. Pin the release and its checksum

Take the SHA-256 of `auditstatus-linux-x64` (or `auditstatus-linux-arm64`) from the release's `SHA256SUMS`. The role refuses to run without it, and refuses a download that does not match it. Set `auditstatus_version` to the same release.


## 3. Write the playbook

Edit the starting playbook, `ansible/attester.yml`, with the verifier's public keys and the attester configuration for these servers:

```yaml
- name: Install the Audit Status attester
  hosts: all
  become: true
  roles:
    - role: auditstatus_attester
      vars:
        auditstatus_version: "<version>"
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

The configuration needs at least one service. The role writes it to `/etc/auditstatus/config.yml` only after `auditstatus validate --role attester` accepts it.


## 4. Run it

```sh
ansible-playbook -i inventory ansible/attester.yml
```

Read the `doctor` output the role prints for each server. Each problem comes with a `fix:` line.


## What does the role do on each server?

1. Checks the settings, then creates the verifier's account.
2. Downloads the binary, checks its SHA-256 and installs it to `/usr/local/bin/auditstatus`.
3. Installs the capability tools and sets `cap_sys_ptrace,cap_dac_read_search+ep` on the binary, so the attester can read other users' processes without running as root.
4. Creates a root-owned `.ssh` directory and writes `authorized_keys` with `command="/usr/local/bin/auditstatus ssh",restrict` for each key.
5. Writes the validated configuration.
6. With `auditstatus_monitor: true`, installs `bpftrace` and the monitor's systemd service, and starts it.
7. Runs `auditstatus doctor` as the account and reports the result.


## Role variables

| Variable                    | Default                        | Meaning                                                              |
| --------------------------- | ------------------------------ | -------------------------------------------------------------------- |
| `auditstatus_version`       | the role's release             | The release to install.                                              |
| `auditstatus_sha256`        | (required)                     | The SHA-256 of the binary for this machine's architecture.           |
| `auditstatus_arch`          | `arm64` on aarch64, else `x64` | The binary's architecture.                                           |
| `auditstatus_user`          | `auditstatus`                  | The account the verifier connects as.                                |
| `auditstatus_verifier_keys` | `[]`                           | Public keys allowed to run the attester and nothing else.            |
| `auditstatus_capabilities`  | `true`                         | Set the two capabilities on the binary.                              |
| `auditstatus_config`        | `{version: 2, services: []}`   | The content of `/etc/auditstatus/config.yml`.                        |
| `auditstatus_tpm`           | `false`                        | Add the account to the TPM's group (`auditstatus_tpm_group`, `tss`). |
| `auditstatus_monitor`       | `false`                        | Install `bpftrace` and the monitor service.                          |

See [The Ansible role](/docs/attester/#the-ansible-role) for the rest, and the [public registry](/docs/registry/#add-your-project) to use Audit Status's key in `auditstatus_verifier_keys` instead of your own.

Next, set up the verifier with the [GitHub Action](/install/github-action/) and pin each server's host key in its `known_hosts`.
