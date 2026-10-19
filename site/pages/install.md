<!--
title: Install Audit Status: every method compared
description: Install the Audit Status attester and verifier: GitHub Action, release binary, npm, Docker, Helm chart or Ansible role, compared.
label: Install
keywords: install audit status, auditstatus install, attester install, verifier github action, helm chart, ansible role, release binary
-->

<!--lint disable no-heading-punctuation-->

# Install Audit Status

Audit Status has two parts: the attester, which runs on each server you want verified, and the verifier, which checks those servers from somewhere else on a schedule. Pick one method for each part. Every method runs the same code from the same repository, so you can mix them: Ansible for the attester and the GitHub Action for the verifier, for example.

If you would rather not run a verifier at all, add your project to the [public registry](/docs/registry/). You install only the attester, and Audit Status's own GitHub Actions verify your servers every hour.


## Which method should you use?

| Method                                              | Installs                                       | Runs on                            | Use it when                                                                    |
| --------------------------------------------------- | ---------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------ |
| [GitHub Action](/install/github-action/)            | The verifier                                   | GitHub Actions in your repository  | You want an hourly report, a badge and an issue when a server fails            |
| [Release binary](/install/binary/)                  | The attester (one executable)                  | Each Linux server                  | You manage a few servers by hand or with your own scripts                      |
| [npm package](/install/npm/)                        | The command line tool and the verifier         | Your machine, or any CI            | You want `auditstatus init` and `doctor` locally, or a verifier outside GitHub |
| [Docker](/install/docker/)                          | The attester on the host, with container rules | Linux servers running containers   | Your services run in Docker, containerd, CRI-O or Podman containers            |
| [Helm chart](/install/helm/)                        | The attester as a DaemonSet                    | Every node of a Kubernetes cluster | Your services run in Kubernetes                                                |
| [Ansible role](/install/ansible/)                   | The attester, its account and SSH key          | Many Debian or Ubuntu servers      | You already manage servers with Ansible                                        |
| [Public registry](/docs/registry/#add-your-project) | Nothing in your CI                             | Audit Status's GitHub Actions      | Your repository is public and you want a third party to run the verifier       |


## The attester, on each server

The attester reads the deployed files, installed packages, containers and running processes, and answers the verifier with that evidence. It only reads: it never runs what it inspects. Audited servers run Linux, since the attester reads each process through `/proc`.

Install the release binary on servers, by hand, with the [installer](/install/binary/), with [Ansible](/install/ansible/), or in the [Helm chart's image](/install/helm/). Do not run the npm package as the attester. The verifier compares the attester's own executable with the release's `SHA256SUMS` file, and an npm installation runs a Node.js binary that is not in that list, so the result fails by default (`policy.unverifiedAuditor`).


## The verifier, away from the servers

The verifier sends each server a fresh nonce, receives the evidence, fetches its own references (the public commit, the registries, the container images, the official runtimes) and writes `report.md`, `report.json` and `badge.json`. Run it somewhere the audited servers cannot reach or change:

* in GitHub Actions, with the [GitHub Action](/install/github-action/);
* in any other CI or on a schedule of your own, with [`auditstatus verify` from npm](/install/npm/);
* in Audit Status's GitHub Actions, through the [public registry](/docs/registry/).


## Supported platforms

| Package                   | Platforms                                                                |
| ------------------------- | ------------------------------------------------------------------------ |
| Release binary            | `linux-x64`, `linux-arm64`, `darwin-arm64` (macOS, for the command line) |
| Attester container image  | `linux/amd64`, `linux/arm64`, as `ghcr.io/auditstatus/attester`          |
| npm package `auditstatus` | Node.js 18 or later                                                      |
| Ansible role              | Ansible 2.15 or later; Debian 12 and 13, Ubuntu 22.04 and 24.04          |
| Helm chart                | Helm 3 (chart API version 2); containerd or CRI-O nodes                  |

Each release publishes the binaries, a `SHA256SUMS` file, the `install.sh` script and build provenance for every file on the [releases page](https://github.com/auditstatus/auditstatus.com/releases). The container image carries build provenance too.


## After you install

1. Run `auditstatus doctor` on a server, as the account the verifier uses. It checks the configuration, the permissions, each service's processes and packages, and the TPM, and prints a `fix:` line for each problem.
2. Run `auditstatus doctor --role verifier` where the verifier runs. It checks the pinned host keys, the SSH key and that every repository is reachable.
3. Run a first verification and read the report. [Reports](/docs/reports/) explains each finding and what to do about it.

The [getting started guide](/docs/getting-started/) walks through all of this for one server, from `auditstatus init` to a first published report.
