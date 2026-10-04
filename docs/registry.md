# Public registry

Audit Status verifies the servers of every registered project each hour, from its own GitHub Actions workflow, and publishes each project's report and badge. A project adds one file to [registry/](../registry/) and Audit Status's public key to its servers. Nothing runs in the project's CI. The verifier is a third party: the project chooses what to verify, and cannot change what its servers are compared with (the public repository, the package registries, the official releases).


## How a run works

```text
registry/<project>.yml            Registry workflow, every hour (GitHub Actions)
                                  ┌──────────────────────────────────────────────┐
                                  │ plan     list the projects                    │
                                  │ build    reproduce the project's build, as    │
                                  │          an unprivileged account, no SSH key  │
                                  │ audit    SSH to each server with the key,     │──► your servers:
                                  │          appraise with builds from the cache  │    auditstatus ssh
                                  │ again    a failing server, after a delay      │    (forced command)
                                  │ publish  status branch, signature, issues     │
                                  └──────────────────────────────────────────────┘
                                                       │
                                                       ▼
                          status branch: projects/<project>/report.md, report.json,
                          badge.json, report.sigstore.json; index.json; README.md
```

1. **Plan** lists the projects in `registry/`.
2. **Build** reproduces the project's build (when it has one) for the version its servers must run and for the commits they ran at the last audit. The build runs as an account of its own, in a job that holds no SSH key and no token with write access, and its result goes to a cache.
3. **Audit** connects to each server with Audit Status's key, sends a fresh nonce, collects the evidence and appraises it: the files against the public commit, the packages against the lockfile and the registries, the build output against the cached build, the runtime against its official release. This job holds the key and runs no code of the project: it never builds.
4. **Again**: a server that failed or was inconclusive is built and collected again after the project's `policy.retryAfterSeconds` (a deploy in progress), and the second result is reported with what the first found.
5. **Publish** writes each report to the `status` branch, signs the files it wrote with a GitHub artifact attestation, and opens an issue for each project that is not passing.


## Add your project

### 1. Install the attester on each server

```sh
curl -fsSLO https://github.com/auditstatus/auditstatus.com/releases/latest/download/install.sh
AUDITSTATUS_VERSION=<version> bash install.sh
sudo useradd --system --create-home --shell /bin/sh auditstatus
sudo chgrp auditstatus /usr/local/bin/auditstatus
sudo chmod 0750 /usr/local/bin/auditstatus
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep /usr/local/bin/auditstatus
sudo install -D -o root -g root -m 0644 attester.config.yml /etc/auditstatus/config.yml
sudo -u auditstatus auditstatus doctor
```

`attester.config.yml` names your services and where they are deployed. `auditstatus init` writes one for your repository; [Attester](attester.md) describes every setting.

### 2. Allow Audit Status's key

The keys are in [verifier/auditstatus.pub](../verifier/auditstatus.pub), with their fingerprints and how they were generated in [verifier/README.md](../verifier/README.md). Allow each line for the `auditstatus` account, with the forced command:

```sh
curl -fsSLo auditstatus.pub https://raw.githubusercontent.com/auditstatus/auditstatus.com/main/verifier/auditstatus.pub
ssh-keygen -lf auditstatus.pub
sudo install -d -o root -g auditstatus -m 0755 ~auditstatus/.ssh
sed 's|^|command="/usr/local/bin/auditstatus ssh",restrict |' auditstatus.pub | sudo tee ~auditstatus/.ssh/authorized_keys
```

Compare the fingerprints with [verifier/README.md](../verifier/README.md). The key can run the attester and nothing else.

### 3. Write your registry file

Name it after your project: `registry/<project>.yml`, in lowercase letters, digits and dashes. The simplest file verifies that a git checkout matches its public repository:

```yaml
# yaml-language-server: $schema=https://auditstatus.com/schema/registry.schema.json
project:
  name: Example
  url: https://example.com
  contact: security@example.com
  github: example-maintainer
repository:
  url: https://github.com/example/app.git
  branch: main
services:
  - name: app
    root: /srv/app
servers:
  - name: web1
    host: web1.example.com
```

The service names match the attester configuration on your servers, and `root` is where the checkout is (the real path, after symbolic links). [The registry file](#the-registry-file) lists every section, and [Examples](#examples) shows builds, lockfiles, PM2, containers and hardware evidence.

### 4. Pin your servers' host keys

The registry connects only to servers whose host keys the file pins. Copy each server's public host key from the server itself:

```sh
cat /etc/ssh/ssh_host_ed25519_key.pub
```

and add it under the server:

```yaml
servers:
  - name: web1
    host: web1.example.com
    hostKeys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

Or collect them with `ssh-keyscan` from a network you trust, compare the fingerprints (`ssh-keygen -lf`) with the servers' own, and let the command line add them, in your fork of this repository (the `servers` section must be the last in the file):

```sh
ssh-keyscan -t ed25519 web1.example.com > known_hosts
pnpm install
node scripts/cli.js registry host-keys --project example --known-hosts known_hosts --write
```

A server without `hostKeys` is not contacted, and its result is inconclusive.

#### TPM keys

A server with a TPM 2.0 can sign each answer with it and, with IMA, show what its kernel measured ([Hardware evidence](hardware.md)). Pin each server's attestation key once its attester runs: allow your own SSH key on the server with the same forced command as the registry's keys, and enroll from your fork:

```sh
AUDITSTATUS_SSH_KEY="$(cat ~/.ssh/id_ed25519)" node scripts/cli.js registry tpm-verify --project example --roots tpm-cas.pem --ima --write
```

For each server with pinned host keys, it checks that the TPM's EK certificate chains to a CA certificate in `--roots` (your TPMs' manufacturers'), and that the attestation key is in that TPM, then pins the key with `required: true`, and `ima: true` with `--ima`. `--allow-uncertified` enrolls a TPM without an EK certificate, such as a virtual TPM. From then on the server fails without a quote from its own TPM, and with `--ima`, without an IMA log that replays to the quote.

### 5. Open a pull request

Check the file in your fork before you open the pull request:

```sh
pnpm install
node scripts/cli.js registry validate
node scripts/cli.js registry readme
```

`registry readme` adds your project to the table in `README.md`. CI runs both checks on the pull request. Open it from an account that maintains the audited repository, or say in it how the maintainers can confirm that you run these servers.

### 6. After the merge

The next hourly run verifies your servers. The results:

| What           | Where                                                                                                                                                                                                                            |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Report         | `https://github.com/auditstatus/auditstatus.com/blob/status/projects/<project>/report.md`                                                                                                                                        |
| Report as JSON | `https://raw.githubusercontent.com/auditstatus/auditstatus.com/status/projects/<project>/report.json`                                                                                                                            |
| Badge          | `https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fauditstatus%2Fauditstatus.com%2Fstatus%2Fprojects%2F<project>%2Fbadge.json`                                                                       |
| Every project  | `https://raw.githubusercontent.com/auditstatus/auditstatus.com/status/index.json`, and the [projects page](https://auditstatus.com/projects/)                                                                                    |
| Each run       | The [Registry workflow](https://github.com/auditstatus/auditstatus.com/actions/workflows/registry.yml): each project's report is kept as the run's artifact `report-<project>` for 90 days, and in the `status` branch's history |
| When it fails  | An issue "[<project>] Audit Status is not passing" in auditstatus/auditstatus.com, mentioning `project.github`, closed when it passes again                                                                                      |

Add the badge to your README:

```markdown
[![Audit Status](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fauditstatus%2Fauditstatus.com%2Fstatus%2Fprojects%2Fexample%2Fbadge.json)](https://github.com/auditstatus/auditstatus.com/blob/status/projects/example/report.md)
```

Anyone can check that the registry's workflow wrote a report, and that it is recent:

```sh
git clone --depth 1 --branch status https://github.com/auditstatus/auditstatus.com.git audit-status
npx auditstatus verify-report --dir audit-status/projects/example \
  --signer auditstatus/auditstatus.com/.github/workflows/registry.yml@refs/heads/main
```


## The registry file

A registry file is a [verifier configuration](configuration.md#verifier-configuration) with a `project` section, `setup`, and each server's host keys. It may not set anything that changes what the result is compared with.

| Section      | What                                                                                                                                                                                        |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `project`    | `name`, `url` (your website, `https://`), `contact` (an email address for problems with your audit), and optional `description` and `github` (a GitHub account the failure issue mentions). |
| `setup`      | `apt`: Ubuntu packages your build needs (compilers, headers). `node`: the Node.js version builds run with, 18 or later (your servers' version; default `22`).                               |
| `repository` | `url` (`https://`), `branch`, `webUrl`, and `version`: what the servers must run. See [Versions](#versions).                                                                                |
| `services`   | As in a verifier configuration, with `root`, `lockfiles`, `artifact`, `image`, `executables` (signatures by Sigstore or minisign).                                                          |
| `build`      | `command`, `outputs`, `env`, `timeoutSeconds` (at most 7200). Builds run as the registry's build account with the public repository and the package registries.                             |
| `policy`     | As in a verifier configuration, without `attesters`. `allowUntracked` may not match every file.                                                                                             |
| `references` | `npmProvenance` only. Every other reference is the public one.                                                                                                                              |
| `ssh`        | `user` (default `auditstatus`), `port`, `timeoutSeconds`.                                                                                                                                   |
| `servers`    | `name`, `host` (a public host name or IPv4 address), `port`, `user`, `hostKeys`, `minProcesses`, `services`, `tpm`, `confidential`.                                                         |

Not allowed in a registry file: other references (registry or mirror URLs, keyrings, tokens), other transports than SSH, `build.passEnv` and `build.user`, `ssh.knownHosts` and `ssh.command`, `kubernetes`, `output`, and servers at private, loopback or link-local addresses. `auditstatus registry validate` names each mistake.


## Examples

| File                                                  | Verifies                                                                                         |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [minimal.yml](../examples/registry/minimal.yml)       | A git checkout against its public repository                                                     |
| [node-pnpm.yml](../examples/registry/node-pnpm.yml)   | A Node.js app built with pnpm, its `node_modules`, the build output, the latest release          |
| [node-pm2.yml](../examples/registry/node-pm2.yml)     | PM2 cluster workers: process count, memory, the Node.js binary, global npm and pm2, a pinned tag |
| [python.yml](../examples/registry/python.yml)         | A Django app in a uv virtual environment, a pinned commit                                        |
| [ruby.yml](../examples/registry/ruby.yml)             | A Rails app with `vendor/bundle`                                                                 |
| [go-release.yml](../examples/registry/go-release.yml) | A Go binary from an attested release, deployed without git                                       |
| [containers.yml](../examples/registry/containers.yml) | Docker containers against their images                                                           |
| [hardware.yml](../examples/registry/hardware.yml)     | TPM 2.0 quotes with Linux IMA                                                                    |
| [forwardemail.yml](../registry/forwardemail.yml)      | Forward Email: 15 servers, the latest release, the build, npm provenance                         |


## Versions

`repository.version` sets what the servers must run: any commit of the branch (the default), the branch's latest commit (`latest`), the latest GitHub release (`latest-release`), a tag, or a commit. A server that runs another commit fails (`policy.versionMismatch`). With `latest` and `latest-release`, `policy.versionGraceSeconds` gives a deploy in progress time: a server that still runs an earlier commit is a warning for that long. See [version](configuration.md#version).


## Security

**The key.** A workflow generated each of Audit Status's keys on a GitHub-hosted runner and stored the private key as a secret of the `verifier` environment, which admits the `main` branch only. Nobody has seen it, and an attestation shows which workflow generated each public key ([verifier/README.md](../verifier/README.md)). On your servers the key runs the attester and nothing else: someone holding a copy could ask your servers for the evidence the registry publishes, and nothing more.

**No project code where the key is.** The audit job holds the key and runs no build: it reads builds from the cache. Builds run in another job, without the key, as an account that cannot read the runner's files or write the cache. A registry file cannot add references, keyrings, tokens or other transports, so a project cannot change what its result means.

**Your servers.** The registry connects only to the hosts and host keys your file pins. Remove the key from `authorized_keys` and your file from `registry/` to leave.

**What a result proves.** As with any Audit Status verifier: software evidence holds against mistakes, drift and attackers without root, not against root; a TPM with IMA or a confidential VM extends it. Every report and badge names the level it reached. See [How it works](how-it-works.md#a-forged-answer) and the [threat model](threat-model.md#the-public-registry).


## Maintainers

* Protect `main`: pull requests with a review, and code owners for `.github/`, `registry/` and `verifier/`. Every registry file and workflow change is then reviewed in public.
* Review each registry file: the contact, that the pull request comes from the project, and the build command (the repository and its lockfiles only, nothing downloaded from elsewhere).
* Set up the `verifier` and `verifier-key` environments and the key as [verifier/README.md](../verifier/README.md) describes. Turn off administrator bypass for both environments.
* GitHub turns off scheduled workflows in a public repository after 60 days without activity. A commit to `main` resets the count; a disabled workflow is turned on again from the Actions tab.
