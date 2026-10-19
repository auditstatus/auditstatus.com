<!--
title: Audit Status and Attestium: how they fit together
description: Attestium is the open evidence format and Node.js library; Audit Status is the ready-made attester, verifier and public registry built on it.
label: Audit Status and Attestium
keywords: attestium, audit status attestium, remote attestation library, evidence format, attestium vs audit status, language-agnostic attestation
-->

<!--lint disable no-heading-punctuation-->

# Audit Status and Attestium

Attestium is an open evidence format and a Node.js library for remote attestation. Audit Status is a ready-made tool built on it: an attester for your servers, a verifier for CI, a GitHub Action, and a public registry that publishes reports and badges. Use Audit Status when you want your servers verified without writing code; use Attestium when you want to build your own attester or verifier, or check one kind of evidence on its own.

Both are open source under the MIT license, kept in separate repositories, and run by the team behind [Forward Email](https://forwardemail.net).


## What does each project provide?

|                 | Attestium                                                             | Audit Status                                                                              |
| --------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| What it is      | A library and a specification                                         | A command line tool, a GitHub Action, a Helm chart, an Ansible role and a public registry |
| Main output     | Evidence documents and the result of each check                       | `report.md`, `report.json`, `badge.json`, an issue when a server fails                    |
| Install         | `npm install attestium`                                               | [Every install method](/install/)                                                         |
| Configuration   | Your code                                                             | `auditstatus.config.yml` and `/etc/auditstatus/config.yml`, with [JSON Schemas](/schema/) |
| Transport       | Up to you                                                             | SSH with a forced command, or a Kubernetes port-forward                                   |
| Other languages | A written specification, a JSON Schema and test vectors               | Interoperates with any attester or verifier that follows the specification                |
| Source          | [attestium/attestium.com](https://github.com/attestium/attestium.com) | [auditstatus/auditstatus.com](https://github.com/auditstatus/auditstatus.com)             |


## Which parts of Audit Status come from Attestium?

The evidence format, the hashing of file trees, and the checks against each kind of reference. The attester collects evidence with Attestium, and the verifier appraises it with Attestium's checks: packages against their registries, containers against their images, TPM quotes, IMA logs, confidential VM reports, Sigstore bundles and the signed Debian and Ubuntu archives. Audit Status adds what a team needs to run this every hour:

* the attester's SSH forced command and its HTTP mode for Kubernetes;
* the verifier configuration, with services, servers, builds and policies;
* the report, the badge, the signed report and the issue;
* `auditstatus init` and `auditstatus doctor`;
* the GitHub Action, the Helm chart, the Ansible role and the release binaries;
* the [public registry](/docs/registry/), which verifies registered projects from Audit Status's own GitHub Actions.


## The evidence format is language-agnostic

Audit Status sends Attestium's evidence format, version 2. The [specification](https://attestium.com/spec/) defines every field, the canonical JSON encoding, the SHA-256 evidence digest, and how a TPM quote or a confidential VM report binds the nonce and the digest. A [JSON Schema](https://attestium.com/schema/evidence.schema.json) describes it for machines.

An attester written in Go, Rust or Python that follows the specification can answer the Audit Status verifier, and a verifier in another language can check evidence from the Audit Status attester. The verifier accepts evidence only from attesters it trusts: other implementations are listed in `policy.attesters`, each with the SHA-256 of its binary or a checksum list it publishes. Attestium's [other languages guide](https://attestium.com/docs/other-languages/) has the rules and test vectors.


## When should you use Attestium directly?

* To verify one thing in your own program: a TPM quote, a container image, a Sigstore bundle, or a `node_modules` tree against its lockfile.
* To build an attester or verifier for a platform Audit Status does not cover.
* To implement the evidence format in another language.
* To embed the checks in your own deployment or monitoring tools.

For everything else, start with Audit Status: [install it](/install/), or [add your project to the public registry](/docs/registry/#add-your-project).


## Where to read more

* [How it works](/docs/how-it-works/): the roles, one verification, and what each evidence level proves.
* [Attestium documentation](https://attestium.com/docs/): concepts, ecosystems, hardware evidence, forged answers and the security model.
* [Attestium whitepaper](https://attestium.com/attestium-whitepaper.pdf): the architecture and what each kind of result does and does not prove.
