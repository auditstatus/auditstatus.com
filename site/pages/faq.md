<!--
title: Audit Status FAQ: verification, install and security
description: Answers about Audit Status: what it verifies, installing it, Docker, TPMs, languages, PM2, Kubernetes, root on the server, Attestium, Keylime and cost.
label: FAQ
kind: faq
keywords: audit status faq, verify production code, remote attestation questions, tpm required, pm2, kubernetes
-->

<!--lint disable no-heading-punctuation-->

# Frequently asked questions

Short answers, with links to the documentation for the details.


## What does Audit Status verify?

That each production server runs exactly the code in a public repository: the deployed files match a commit on the audited branch, installed packages match the lockfile, containers match their images, and every running executable and library is explained by a reference the verifier fetches itself. See [How it works](/docs/how-it-works/).


## Can Audit Status verify my servers without anything in my CI?

Yes, through the [public registry](/docs/registry/). Install the attester on your servers, allow Audit Status's SSH key, and add one YAML file to the Audit Status repository in a pull request. Audit Status's own GitHub Actions workflow then verifies your servers every hour as a third party, publishes your signed report and serves your badge. The [projects page](/projects/) lists every registered project.


## What is remote attestation?

A verifier checks what another machine runs without trusting that machine's own opinion. The attester on the server reports facts; the verifier checks that the report is fresh and unchanged and compares every fact with outside references. Audit Status is built on [Attestium](https://attestium.com), which defines the evidence format.


## How do I install Audit Status?

Install the attester on each server and a verifier somewhere else. Servers run the release binary, installed by hand, with `install.sh`, with the Ansible role, or as a DaemonSet with the Helm chart. The verifier runs as a GitHub Action or with `auditstatus verify` from npm. [Install](/install/) compares every method.


## Is there a Docker image?

Yes, `ghcr.io/auditstatus/attester`, for `linux/amd64` and `linux/arm64`. It holds the release binary, `crictl` and `tpm2-tools`, and the Helm chart runs it on every Kubernetes node. On a server that runs Docker without Kubernetes, install the release binary on the host so it can see every container. See [Docker](/install/docker/).


## Which operating systems are supported?

Audited servers run Linux, on x64 or arm64: the attester reads each process through `/proc`. Releases also include a macOS arm64 binary for the command line tool, and the npm package runs wherever Node.js 18 or later runs. System packages are checked against the Debian and Ubuntu archives.


## What leaves my servers?

Paths and SHA-256 hashes of files, never their contents, plus facts about packages, processes and containers. Environment values stay on the server. Command lines reach the verifier but never the published report. See [What leaves the server](/docs/threat-model/#what-leaves-the-server-and-what-is-published).


## How does Audit Status relate to Attestium?

Attestium is the open evidence format and the Node.js library that collects and checks evidence. Audit Status is the ready-made attester, verifier, GitHub Action and public registry built on it. An attester or verifier in another language interoperates by following the Attestium specification. See [Audit Status and Attestium](/attestium/).


## Does it need a TPM?

No. Without hardware, the report is software evidence: it catches drift, failed deploys, modified files and packages, injected libraries and programs that no reference explains. A TPM proves which machine answered and how it booted; IMA adds the kernel's record of loaded files; a confidential VM protects the server from its host. See [Hardware evidence](/docs/hardware/).


## Which languages are supported?

Node.js, Python, Ruby, Elixir and Erlang, PHP, Java and the JVM, .NET, Go and Rust, and compiled or bundled releases of any language through attested release manifests. See [Languages](/docs/languages/).


## Does it work with PM2 and git deploys?

Yes. Forward Email deploys with git and PM2. The attester reads the commit from the checkout, inspects every PM2 worker process, the Node.js binary, `node_modules` and the global `pm2`, `npm` and `pnpm`. See [Git deploys and PM2](/docs/attester/#git-deploys-and-pm2).


## Does it work with containers and Kubernetes?

Yes. Docker, containerd, CRI-O and Podman containers are compared with their images, fetched by digest. In Kubernetes, a Helm chart runs the attester as a DaemonSet, and the verifier reaches it through port-forward. See [Kubernetes attestation](/kubernetes-attestation/).


## What can the verifier's SSH key do?

Only run the attester. The server's `authorized_keys` forces the command, which allows three operations: `check`, `enroll` and `activate`. See [The SSH forced command](/docs/attester/#the-ssh-forced-command).


## What can root on the server hide?

With software evidence, root controls the attester and can make a report pass. A TPM quote stops root from answering for another machine or replaying an old answer; with IMA, root cannot remove the kernel's measurements of files it loaded. The report states each server's evidence level. See [Threat model](/docs/threat-model/).


## What happens when a registry or server does not answer?

The result is inconclusive, never passing. The report shows the server as inconclusive, and the workflow can retry. An attacker who blocks the verifier cannot turn a failure into a pass.


## Does it catch code that ran and was deleted before the audit?

With the monitor, yes. It records every program started and every file mapped executable with eBPF, and each audit checks the window before it. See [Runtime integrity monitoring](/runtime-integrity-monitoring/).


## How is it different from Keylime?

Keylime checks TPM quotes and IMA logs against policies the operator writes. Audit Status derives what should run from public sources on each run (the commit, the lockfiles, the images, the signed distribution archive), works without a TPM, and publishes a report for outside readers. See [Compare](/compare/).


## How is it different from SLSA and Sigstore?

SLSA provenance describes how an artifact was built; Sigstore records who signed it. Neither shows that a server runs the artifact. Audit Status checks the server, and uses provenance and signatures as references. See [Compare](/compare/).


## Where does the verifier run?

Usually in GitHub Actions, on a schedule, with the published action. It can also run anywhere with `auditstatus verify`. It should run somewhere the audited servers cannot reach. See [Verifier](/docs/verifier/).


## How do users see the result?

The workflow publishes `report.md`, `report.json` and a badge to a branch. A status page can show the badge or read `report.json`. See [Open source transparency](/open-source-transparency/).


## What does it cost, and under which license?

Nothing. Audit Status is open source under the MIT license. It runs on your servers and in your CI.
