# Audit Status

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/logo-dark.svg">
  <img src="./assets/logo.svg" width="400" alt="Audit Status">
</picture>

[![CI](https://github.com/auditstatus/auditstatus.com/actions/workflows/ci.yml/badge.svg)](https://github.com/auditstatus/auditstatus.com/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/auditstatus/auditstatus.com/badge.svg)](https://coveralls.io/github/auditstatus/auditstatus.com)
[![npm version](https://img.shields.io/npm/v/auditstatus.svg)](https://www.npmjs.com/package/auditstatus)

Audit Status verifies that production servers run exactly the code in a public repository. An attester on each server reports the deployed files, installed packages, containers and running processes; a verifier in CI compares them with references it fetches itself and publishes a report and a badge. With a TPM, IMA or a confidential VM, the evidence is backed by hardware. Without hardware, a result is software evidence: it catches mistakes, drift and attackers without root, but root on a server can forge it, and every report and badge says which level a result reached ([A forged answer](docs/how-it-works.md#a-forged-answer)).

<a href="https://forwardemail.net">
  <img src="https://forwardemail.net/img/logo-square.svg" width="100" alt="Forward Email">
</a>

Audit Status is a project by [Forward Email](https://forwardemail.net), the 100% open-source, privacy-focused email service. It publishes, on the [Forward Email status page](https://status.forwardemail.net), whether the production servers run the code in the public repository.

Website: <https://auditstatus.com/>


## Projects

The [public registry](docs/registry.md) verifies these projects' servers every hour from this repository's GitHub Actions, as a third party. Each badge shows the latest result and links to its report.

<!-- registry:start -->

| Project                                   | Source                                                                            | Status                                                                                                                                                                                                                                                                                   | Configuration                                 |
| ----------------------------------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| [Forward Email](https://forwardemail.net) | [forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net) | [![Forward Email audit status](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fauditstatus%2Fauditstatus.com%2Fstatus%2Fprojects%2Fforwardemail%2Fbadge.json)](https://github.com/auditstatus/auditstatus.com/blob/status/projects/forwardemail/report.md) | [forwardemail.yml](registry/forwardemail.yml) |

<!-- registry:end -->

[Add your project](docs/registry.md#add-your-project): one YAML file in [registry/](registry/), and Audit Status's key on your servers.


## Quick start

### Add your project to the public registry

Audit Status verifies registered projects every hour from its own GitHub Actions and publishes each report and badge. Nothing runs in your CI.

On each server, install the attester, allow Audit Status's SSH key ([verifier/auditstatus.pub](verifier/auditstatus.pub)) to run the attester and nothing else, and check the setup. `npx auditstatus init` writes `attester.config.yml` for your repository.

```sh
curl -fsSLO https://github.com/auditstatus/auditstatus.com/releases/latest/download/install.sh
bash install.sh
sudo useradd --system --create-home --shell /bin/sh auditstatus
sudo chgrp auditstatus /usr/local/bin/auditstatus
sudo chmod 0750 /usr/local/bin/auditstatus
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep /usr/local/bin/auditstatus
sudo install -D -o root -g root -m 0644 attester.config.yml /etc/auditstatus/config.yml
curl -fsSLo auditstatus.pub https://raw.githubusercontent.com/auditstatus/auditstatus.com/main/verifier/auditstatus.pub
sudo install -d -o root -g auditstatus -m 0755 ~auditstatus/.ssh
sed 's|^|command="/usr/local/bin/auditstatus ssh",restrict |' auditstatus.pub | sudo tee ~auditstatus/.ssh/authorized_keys
sudo -u auditstatus auditstatus doctor
```

Then add `registry/<project>.yml` to this repository in a pull request, with each server's SSH host key:

```yaml
project:
  name: Example
  url: https://example.com
  contact: security@example.com
repository:
  url: https://github.com/example/app.git
  branch: main
services:
  - name: app
    root: /srv/app
servers:
  - name: web1
    host: web1.example.com
    hostKeys:
      - ssh-ed25519 AAAA...
```

The next hourly run after the merge publishes your report and badge. [Public registry](docs/registry.md) lists every setting, with examples for builds, lockfiles, PM2, containers and hardware.

### Run your own verifier

A workflow in your repository verifies your servers with a key you create and publishes the report to a branch of your repository:

```sh
npm install -g auditstatus
auditstatus init --host app1.example.com
```

The [getting started guide](docs/getting-started.md) walks through the rest.


## Languages and ecosystems

| Language | What is checked                                                                                                                                     | Guide                                  |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| Node.js  | `node_modules` against `package-lock.json` or `pnpm-lock.yaml`; the Node.js binary against the official release; global npm, corepack, pnpm and pm2 | [node](docs/languages/node.md)         |
| Python   | Virtual environments against `uv.lock`, `pylock.toml`, `poetry.lock`, `Pipfile.lock` or `requirements.txt`                                          | [python](docs/languages/python.md)     |
| Ruby     | `vendor/bundle` against `Gemfile.lock`                                                                                                              | [ruby](docs/languages/ruby.md)         |
| Elixir   | `deps/` against `mix.lock`                                                                                                                          | [elixir](docs/languages/elixir.md)     |
| PHP      | `vendor/` against `composer.lock`                                                                                                                   | [php](docs/languages/php.md)           |
| Java     | Dependency jars against Gradle verification metadata or a Maven lockfile                                                                            | [java](docs/languages/java.md)         |
| .NET     | Publish output against `packages.lock.json`                                                                                                         | [dotnet](docs/languages/dotnet.md)     |
| Go       | The dependencies built into the binary against `go.sum`                                                                                             | [go](docs/languages/go.md)             |
| Rust     | The crates cargo-auditable records against `Cargo.lock`                                                                                             | [rust](docs/languages/rust.md)         |
| Binaries | Attested release manifests, pinned hashes, signed checksum lists                                                                                    | [binaries](docs/languages/binaries.md) |

Containers (Docker, containerd, CRI-O) are compared with their images, fetched by digest: see [Containers](docs/containers.md). System binaries and libraries are compared with the signed Debian or Ubuntu archive.


## Evidence levels

| Level                  | Backed by                                                                                          | Holds against root on the server                                  |
| ---------------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Software evidence      | The attester's report, bound to a fresh nonce by its digest                                        | No                                                                |
| TPM                    | A TPM 2.0 quote over the nonce and digest, with an enrolled key; boot state with pinned PCR values | No: it proves freshness and which machine answered                |
| TPM + IMA              | The kernel's measurement log, replayed to the quoted PCR 10                                        | For the files the IMA policy measures                             |
| AMD SEV-SNP, Intel TDX | A confidential VM report signed by the CPU vendor                                                  | Protects against the host operator, not against root in the guest |

See [How it works](docs/how-it-works.md#evidence-levels) and the [threat model](docs/threat-model.md).


## Documentation

* [Getting started](docs/getting-started.md)
* [Public registry](docs/registry.md)
* [How it works](docs/how-it-works.md)
* [Attester](docs/attester.md)
* [Verifier](docs/verifier.md)
* [Configuration](docs/configuration.md)
* [Containers](docs/containers.md)
* [Kubernetes](docs/kubernetes.md)
* [Hardware evidence](docs/hardware.md)
* [Monitor](docs/monitor.md)
* [Reports](docs/reports.md)
* [Threat model](docs/threat-model.md)
* [Adopters](docs/adopters.md)
* [Languages](docs/README.md#languages)

The evidence format is specified by [Attestium](https://github.com/attestium/attestium.com/blob/main/SPEC.md).


## Command line

```text
auditstatus init        write starting configuration for a repository
auditstatus doctor      check a setup (--role attester|verifier)
auditstatus verify      verify every configured server and write the report
auditstatus tpm-verify  enroll a server's TPM and print the key to pin
auditstatus check       print a summary of local evidence (on a server)
auditstatus help        every command and option
```

Exit status: `0` passed (possibly with warnings), `1` failed, `2` usage or configuration error, `3` inconclusive.


## Development

```sh
pnpm install
pnpm test            # lint, then node --test
pnpm run coverage    # c8: 100% statements, branches, functions and lines
```

The tests are end to end. They build a public repository, stand-ins for the registries and nodejs.org, and a deployed checkout with running processes, then verify it. They use a real `sshd` with a forced command, `swtpm` with `tpm2-tools` for TPM quotes and IMA replay, and real processes with preloaded libraries and replaced binaries. Tests that need a tool that is not installed (Docker, Go, Helm and others) are skipped. On Debian or Ubuntu:

```sh
sudo apt-get install swtpm swtpm-tools tpm2-tools openssh-server openssh-client git
```

`scripts/build-binary.sh` builds the single executable for the current machine.


## Security

Report security issues at <https://forwardemail.net/security>.


## License

[MIT](LICENSE) © Audit Status Community
