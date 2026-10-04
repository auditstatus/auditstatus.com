<!--
title: Verify that production matches the source code
description: Check that production servers run exactly the commit in a public repository: deployed files, packages, processes and every running executable.
label: Production matches source
keywords: verify production code, deployed code matches repository, production drift, git commit verification, lockfile verification
-->

# Verify that production matches the source code

Audit Status checks that each production server runs exactly the code in a public repository: the deployed files match a commit on the audited branch, the installed packages match the lockfile, and every running program and library is explained by a reference the verifier fetches itself.


## What is compared with what

| On the server                    | Compared with                                                                  | Reference source                      |
| -------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------- |
| Deployed files of a git checkout | Every tracked file at the reported commit, which must be on the audited branch | A clone of the public repository      |
| Files the deploy generates       | A build of the same commit that the verifier runs itself                       | The verifier's own checkout           |
| A release deployed without git   | Its `.attestium-manifest.json`, attested by the configured workflow            | GitHub's attestation API and Sigstore |
| Installed packages               | The package each lockfile at the deployed commit pins                          | The registries                        |
| Node.js binaries                 | The official release archive                                                   | `nodejs.org/dist`                     |
| Containers                       | The image, fetched by digest                                                   | The container registry                |
| System binaries and libraries    | The file of the owning Debian or Ubuntu package                                | The signed distribution archive       |
| Other programs                   | A pinned SHA-256 or a signed checksum list                                     | The project's release page            |

The lockfile is read from the verifier's clone at the deployed commit, never from the server. See [How it works](/docs/how-it-works/).


## One run

1. The verifier, usually a scheduled GitHub Actions workflow, sends a fresh nonce to each server over SSH. The server's `authorized_keys` forces the command, so the key can only run the attester.
2. The attester hashes the deployed files, installed packages and every running executable and library, inspects every process of each service, computes a digest of the evidence, and asks a TPM or the CPU to sign it when available.
3. The verifier checks the nonce and the digest, fetches every reference itself, and compares.
4. It writes `report.md`, `report.json` and `badge.json`, and can publish them to a branch and open an issue when a server fails.


## What a passing report claims

At the moment of the audit, a passing server:

* runs a commit on the audited branch of the public repository, with every tracked file unchanged and nothing added that the commit does not ignore;
* has installed packages that match its lockfiles, build output that matches a reproduced build, and container files that match their images;
* runs only executables and libraries that some reference explains;
* has no known code-injection vector open in the inspected processes, such as a preload in `NODE_OPTIONS` or `LD_PRELOAD`, an open inspector port or an attached debugger.

It does not claim that the public code is free of bugs. It shows that what runs is what anyone can read. See [Threat model](/docs/threat-model/).


## Drift, mistakes and attacks

Most failures are not attacks: a hotfix edited on the server, a deploy that did not finish, a dependency installed without the lockfile, a process started before the last deploy. The report names each one with what to do about it. See [Reports](/docs/reports/).

Against an attacker with root on the server, software evidence is not enough: root controls the attester. A TPM quote, IMA and confidential VMs raise the bar. The report states the evidence level of every server.


## Start

```sh
npm install -g auditstatus
auditstatus init --host app1.example.com
```

[Getting started](/docs/getting-started/) goes from `auditstatus init` to a first published report.
