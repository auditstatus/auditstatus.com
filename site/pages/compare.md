<!--
title: Audit Status compared with Keylime, System Transparency, SLSA and Sigstore
description: How Audit Status relates to Keylime, System Transparency, SLSA provenance and Sigstore: what each checks, where they overlap, and how they combine.
label: Compare
keywords: Keylime alternative, System Transparency, SLSA provenance, Sigstore, remote attestation comparison, runtime verification tools
-->

# Audit Status compared with other tools

Several projects make software more verifiable. They answer different questions, and most combine with Audit Status rather than replace it. This page describes each as factually as possible; the projects' own documentation is authoritative.

|                     | Question it answers                                           | Checks the running server |
| ------------------- | ------------------------------------------------------------- | ------------------------- |
| Audit Status        | Does this server run the code in this public repository, now? | Yes                       |
| Keylime             | Does this machine's measured boot and IMA log match a policy? | Yes                       |
| System Transparency | Did this server boot a signed, published OS image?            | At boot                   |
| SLSA provenance     | How and from which source was this artifact built?            | No                        |
| Sigstore            | Who signed this artifact, and is the signature logged?        | No                        |


## Keylime

[Keylime](https://keylime.dev) is a CNCF project for TPM-based remote attestation. An agent on each machine reports TPM quotes, the measured boot log and the IMA log; the verifier checks them against policies of expected boot measurements and allowed file hashes, continuously.

Audit Status also verifies TPM quotes and replays IMA logs to the quoted PCR 10. The difference is where the expected values come from. Keylime compares measurements with policies the operator writes. Audit Status derives the expected code from public sources for each run: the files of a git commit, the packages a lockfile pins, the image a container runs, the signed Debian or Ubuntu archive, official runtime releases. It also inspects processes for injection and works without a TPM, at the software evidence level, and publishes a report for outside readers.


## System Transparency

[System Transparency](https://www.system-transparency.org) makes the operating system a server boots verifiable: the server boots a signed OS package, and the published packages can be rebuilt and checked by others.

It covers the boot of the system image. Audit Status covers what runs after boot: application files, installed packages, processes, containers and the system files they use. With a TPM and pinned PCR values, Audit Status can also check the measured boot state; a system booted through System Transparency and audited with Audit Status is covered at both ends.


## SLSA provenance

[SLSA](https://slsa.dev) defines levels of build integrity, and provenance: a signed statement of how, where and from which source an artifact was built.

Provenance describes the artifact; it does not show that a server runs it. Audit Status uses provenance as a reference: a release deployed without git is explained by its manifest, which must carry a GitHub artifact attestation (SLSA provenance) from the configured workflow and commit, and npm provenance can be required for npm packages. See [Verifier](/docs/verifier/).


## Sigstore

[Sigstore](https://www.sigstore.dev) signs artifacts with short-lived certificates tied to an identity, and records signatures in the Rekor transparency log.

A signature proves who signed. Audit Status verifies Sigstore bundles, requires the signer identity it is configured with (repository, workflow and ref), and uses them to explain release manifests, container images, checksum lists and packages. It then checks that the signed artifact is what the server runs.


## Using them together

* Build with SLSA provenance and sign with Sigstore; Audit Status requires both for releases and images.
* Pin the measured boot state (for example of a System Transparency image) with a TPM; Audit Status checks the quote.
* For continuous TPM policy enforcement across a fleet, Keylime; for publishing proof that production runs public code, Audit Status.

See [How it works](/docs/how-it-works/) and the [Threat model](/docs/threat-model/).
