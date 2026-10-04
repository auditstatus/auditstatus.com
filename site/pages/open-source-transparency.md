<!--
title: Prove that a SaaS runs its open source code
description: Publish verifiable proof on a status page that a hosted service runs the code in its public repository, checked on a schedule by an independent verifier.
label: Open source transparency
keywords: open source transparency, status page, SaaS transparency, verifiable hosting, prove production code, trust
-->

# Prove that a SaaS runs its open source code

A hosted service that publishes its source asks users to trust that production runs it. Audit Status replaces that trust with a result anyone can check: a verifier compares every production server with the public repository on a schedule and publishes the report and a badge next to the status page.


## Why a public repository is not enough

Users of a hosted service cannot see its servers. The code in the repository may differ from what runs: a patched file, an extra package, an older commit, a program started by hand. A published report with the evidence level of each server closes that gap for anyone who reads it.


## What to publish

| Publish                                                      | Why                                                                    |
| ------------------------------------------------------------ | ---------------------------------------------------------------------- |
| The verifier configuration and `known_hosts`                 | Readers see which servers, services, branches and policies are checked |
| Pinned TPM keys, expected PCR values and launch measurements | Readers see what the hardware evidence is checked against              |
| The workflow, pinned to an Audit Status release              | Readers see which verifier ran                                         |
| The report branch                                            | `report.md`, `report.json` and `badge.json`, with their history        |
| The workflow runs                                            | The log and summary of each verification                               |

Never publish the SSH private key or a Kubernetes token.


## The badge and the status page

With `publish-branch: audit-status`, the workflow commits each report to a branch. The badge is a Shields endpoint:

```md
[![Audit Status](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPOSITORY/audit-status/badge.json)](https://github.com/OWNER/REPOSITORY/blob/audit-status/report.md)
```

A status page can also read `report.json` and show each server's `status` and `level`. Show when the report was generated, and treat a report much older than the schedule as unknown: a verifier that stopped running should not keep a passing badge. The [report schema](/schema/report.schema.json) describes every field.


## Independent verification

Anyone given their own key with the same forced command can run `auditstatus verify` with the published configuration and collect fresh evidence of their own. The server cannot tell one verifier from another, so a third party does not have to trust the operator's CI.


## Say what the result proves

State the evidence level with the result. Software evidence shows that nothing without root changed what runs; a TPM quote, IMA or a confidential VM each add to what holds against the operator's own root user. See [Evidence levels](/docs/how-it-works/#evidence-levels) and the [Threat model](/docs/threat-model/).


## Reference adopter

[Forward Email](https://forwardemail.net) is the [public registry](/docs/registry/)'s first project: Audit Status verifies its production servers every hour, and [status.forwardemail.net](https://status.forwardemail.net) shows the result. Its servers deploy the public repository with git and run it with PM2; the attester inspects every PM2 worker, the Node.js binary, `node_modules` and the global tools. See [Adopters](/docs/adopters/).
