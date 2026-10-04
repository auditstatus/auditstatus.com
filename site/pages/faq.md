<!--
title: Frequently asked questions
description: Answers about Audit Status: what it verifies, TPM requirements, languages, PM2, containers, Kubernetes, root on the server, Keylime and SLSA, and cost.
label: FAQ
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
