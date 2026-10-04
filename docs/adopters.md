# Adopters

Any service that runs open-source code can use Audit Status to show its users that production runs the published code: a hosted email provider, a SaaS built on an open-source stack such as Supabase, or anyone who deploys from a public repository. This page lists the steps, what to publish, how to show the result on a status page, and how Forward Email, the reference adopter, does it.


## Steps

1. **Deploy only public code.** Deploy from a branch of the public repository: a git checkout, a release built and attested by a workflow in that repository, or container images pushed to a registry and deployed by digest. Commit the lockfiles, and make builds reproducible (same commit, same bytes).
2. **Install the attester** on every production server with the [Ansible role](attester.md#the-ansible-role), your own configuration management, or the [Helm chart](kubernetes.md) for Kubernetes. `auditstatus init` writes its configuration: a service for each application and container. Run `auditstatus doctor` on each server and fix what it reports.
3. **Choose the verifier.**
   * **The public registry** (simplest): allow Audit Status's SSH key on your servers and add `registry/<project>.yml`, with each server and its host key, to the Audit Status repository in a pull request. Audit Status's workflow verifies your servers every hour as a third party and publishes your report and badge. See [Public registry](registry.md).
   * **Your own verifier**, in a public repository: commit `auditstatus.config.yml`, `known_hosts` and the workflow, and store the SSH key (and a kubeconfig, for Kubernetes) as secrets. See [Getting started](getting-started.md) and [Verifier](verifier.md).
4. **Clear the findings.** Run the verification until it passes. Allow what is expected (`policy.allowUntracked`, `image.allowChanges`, pinned `executables`) and fix the rest. Keep `policy` strict: a finding turned into a warning is still shown, but no longer fails.
5. **Add hardware evidence** where the hardware allows: enroll TPMs, enable IMA, or run in confidential VMs. See [Hardware evidence](hardware.md).
6. **Publish** the badge on your status page, linked to the report.


## What to publish

With the public registry, your registry file and the registry's `status` branch publish all of this for you. With your own verifier, publish:

| Publish                                                      | Why                                                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| The verifier configuration and `known_hosts`                 | Readers see which servers, services, branches and policies are checked.                     |
| Pinned TPM keys, expected PCR values and launch measurements | They are public keys and hashes; readers see what the hardware evidence is checked against. |
| The workflow, pinned to an Audit Status release              | Readers see which verifier ran.                                                             |
| The report branch (`publish-branch`)                         | `report.md`, `report.json` and `badge.json`, with their history.                            |
| The workflow runs                                            | The job log and summary of each verification.                                               |

Never publish the SSH private key or the Kubernetes token.

To let an outside party verify independently, give it its own key with the same forced command. It runs `auditstatus verify` with your published configuration and gets fresh evidence of its own.


## The status page badge

From the public registry, for the project `<project>`:

```md
[![Audit Status](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fauditstatus%2Fauditstatus.com%2Fstatus%2Fprojects%2F<project>%2Fbadge.json)](https://github.com/auditstatus/auditstatus.com/blob/status/projects/<project>/report.md)
```

From your own verifier, with `publish-branch: audit-status`:

```md
[![Audit Status](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPOSITORY/audit-status/badge.json)](https://github.com/OWNER/REPOSITORY/blob/audit-status/report.md)
```

A status page can also read `report.json` from the same branch and show each server's `status` and `level`. Show the report's `generatedAt` too, and treat a report much older than the workflow's schedule as unknown: a verifier that stopped running should not keep a passing badge. Explain the evidence level next to the result; "software evidence" and "TPM + IMA" mean different things (see [How it works](how-it-works.md#what-each-level-proves)).

When the audit fails or is inconclusive, the workflow opens an issue titled "Audit Status is not passing" ("\[<project>] Audit Status is not passing" in the registry) and closes it when it passes again. Keep that issue public: it is part of the record.


## Forward Email

[Forward Email](https://forwardemail.net) is the reference adopter. We publish the result for our production servers on the [Forward Email status page](https://status.forwardemail.net). Forward Email is also the [public registry](registry.md)'s first project ([registry/forwardemail.yml](../registry/forwardemail.yml)): Audit Status's workflow verifies its 15 production servers every hour against the latest GitHub release, with the build reproduced and npm provenance checked. Our servers deploy the public [forwardemail.net](https://github.com/forwardemail/forwardemail.net) repository with git and run it with PM2. The attester inspects every PM2 worker process, the Node.js binary, `node_modules`, and the global `pm2`, `npm` and `pnpm`; the verifier compares them with the public commit, the lockfile, and the official releases. See [Git deploys and PM2](attester.md#git-deploys-and-pm2).
