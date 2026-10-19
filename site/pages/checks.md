<!--
title: What Audit Status checks on a production server
description: Every check Audit Status runs on a server: evidence freshness, deployed files, builds, packages, processes, running code, containers, TPM, IMA and more.
label: What it checks
keywords: audit status checks, what audit status verifies, production verification checks, deployed files lockfile processes, runtime code verification
-->

<!--lint disable no-heading-punctuation-->

# What Audit Status checks

Audit Status checks that every file a production server runs comes from a reference the verifier fetched itself: the public commit, a build of that commit, the packages its lockfiles pin, the container images by digest, the official runtimes, or the signed Linux distribution archive. Each check below appears in the report under its name, with a severity of `fail`, `warn`, `error` (could not complete) or `info`.


## Is the evidence fresh and unchanged?

| Check       | What it verifies                                                                                                                                          |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `evidence`  | The evidence answers this run's 32-byte nonce, its digest matches its contents, its timestamp is in the accepted window, and it fits the evidence schema. |
| `transport` | The verifier reached the attester: over SSH, with the server's host key pinned in `known_hosts`, or through a Kubernetes port-forward.                    |
| `attester`  | The attester's own executable matches the release's `SHA256SUMS`, so a modified attester is caught.                                                       |

A replayed answer fails, and a server that does not answer is inconclusive, never passing.


## Does the server run the public code?

| Check                  | What it verifies                                                                                                                                            |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `source`               | The deployed commit exists and is on the audited branch, and every tracked file matches it: no file differs, is missing, or was added outside `.gitignore`. |
| `build`                | Files the deploy generates (a bundle, compiled assets) match a build of the same commit that the verifier runs itself.                                      |
| `artifact`             | A release deployed without git matches its `.attestium-manifest.json`, which must carry a GitHub artifact attestation by the configured workflow.           |
| `service`, `processes` | Each configured service is reported, and at least `minProcesses` of its processes run.                                                                      |


## Are the installed packages the ones the lockfile pins?

The `packages:<ecosystem>` checks compare every installed package, file by file, with the package the lockfile at the deployed commit pins, fetched from its registry and checked by hash. The lockfile comes from the verifier's own clone, never from the server.

| Ecosystem | Installed in                       | Lockfile                                                                    |
| --------- | ---------------------------------- | --------------------------------------------------------------------------- |
| npm       | `node_modules`                     | `package-lock.json`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`                |
| PyPI      | A virtual environment              | `uv.lock`, `pylock.toml`, `poetry.lock`, `Pipfile.lock`, `requirements.txt` |
| RubyGems  | `vendor/bundle`                    | `Gemfile.lock`                                                              |
| Hex       | `deps/`                            | `mix.lock`                                                                  |
| Composer  | `vendor/`                          | `composer.lock`                                                             |
| Maven     | Dependency jars                    | Gradle verification metadata, a Maven lockfile                              |
| NuGet     | .NET publish output                | `packages.lock.json`                                                        |
| Go, Cargo | Dependencies built into the binary | `go.sum`, `Cargo.lock`                                                      |

`globalPackages` does the same for `npm`, `corepack`, `pnpm` and `pm2` installed next to Node.js. With `references.npmProvenance`, `provenance` also verifies the npm provenance attestations of packages that have them. See [Languages](/docs/languages/).


## Is every running process clean?

The `process` check inspects every process of each service. It reports, among others:

* code-loading settings such as `LD_PRELOAD`, `/etc/ld.so.preload`, `NODE_OPTIONS` preloads and inspector flags, and PM2's `node_args`;
* an attached debugger, an open inspector port, code changed in memory, or code run from a memory-only file;
* an executable replaced after the process started;
* tracked files, build output or packages changed after the process started, which means the process may run code that is no longer on disk.

Command lines are never shown in the report, since they can hold secrets.


## Is every executable and library explained?

The `code` check hashes every executable and library that an inspected process runs or maps, and matches each one with a reference: the commit, the build, a verified package, the container image, the official Node.js release, a pinned hash or signed checksum list, or the file of its Debian or Ubuntu package in the signed archive. A file that contradicts its reference fails. A file that matches none is unexplained, a warning by default (`policy.unexplainedCode`).


## Do containers match their images?

The `container` check fetches the image each container runs from its registry, by digest, and compares every file of the container's root filesystem with it. Files that differ, are missing or were added fail by default, as do mounts that hide files of the image. With an image signer configured, the image must carry a GitHub artifact attestation from that workflow. See [Docker](/install/docker/) and [Containers](/docs/containers/).


## What did the hardware measure?

| Check          | What it verifies                                                                                                                          |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `tpm`          | A TPM 2.0 quote over the nonce and digest, signed by the attestation key pinned for this server; optionally the expected boot state.      |
| `ima`          | The kernel's IMA log replays to the quoted PCR 10, and the files the kernel measured match the commit and the packages.                   |
| `confidential` | An AMD SEV-SNP or Intel TDX report, signed by the CPU vendor's key chain, binds the nonce and digest, with the pinned launch measurement. |

These checks set the result's evidence level. Without them, a result is software evidence, which root on the server can forge. See [Hardware evidence](/docs/hardware/).


## What ran between two audits?

With the monitor enabled on the server, the `monitor` check explains every program started and every library loaded in the window before the audit, recorded with eBPF. A program that ran and is no longer on disk is reported. See [Runtime integrity monitoring](/runtime-integrity-monitoring/).


## What does Audit Status not check?

* Files the commit ignores (`.env`, logs, uploads) are listed by directory but not compared, unless a build produces them.
* Code outside files, such as evaluated strings or JIT output, is not verified.
* Volumes mounted into containers are not compared with the image.
* The kernel and firmware are trusted at every evidence level.

The [threat model](/docs/threat-model/) lists what an attacker can hide at each evidence level, and [Reports](/docs/reports/) lists every finding with what to do about it.
