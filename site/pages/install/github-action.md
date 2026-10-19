<!--
title: Audit Status GitHub Action: verify servers from CI
description: Run the Audit Status verifier in GitHub Actions every hour: SSH key secret, pinned host keys, report branch, signed report, badge and failure issue.
label: GitHub Action
kind: howto
keywords: audit status github action, verify servers github actions, scheduled verification workflow, attestation github action, status badge
-->

<!--lint disable no-heading-punctuation-->

# Set up the Audit Status GitHub Action

The Audit Status GitHub Action runs the verifier in your repository's GitHub Actions. On a schedule, it connects to each server over SSH, checks the evidence against references it fetches itself, writes the report to the job summary, commits it to a branch, signs it, and opens an issue when a server does not pass.

You need a public repository that your servers deploy, the attester on each server ([release binary](/install/binary/), [Ansible](/install/ansible/) or [Helm](/install/helm/)), and the command line tool on your machine ([npm](/install/npm/)).


## 1. Generate the workflow

In your repository, run `auditstatus init`. It looks for lockfiles, a `Dockerfile` or compose file and the `origin` remote, then writes the verifier configuration, the attester configuration and the workflow:

```sh
npm install -g auditstatus
auditstatus init --host app1.example.com --root /srv/app --user app
```

It writes `auditstatus.config.yml`, `auditstatus/attester.config.yml` and `.github/workflows/auditstatus.yml`, and leaves any of them that already exist alone (`--force` replaces them).


## 2. Give the verifier an SSH key

Create a key for the verifier on your machine:

```sh
ssh-keygen -t ed25519 -N "" -f auditstatus_key
```

On each server, allow the public key to run the attester and nothing else. The `auditstatus` account and the attester come from the [install step](/install/binary/):

```sh
sudo install -d -o root -g auditstatus -m 0755 ~auditstatus/.ssh
echo "command=\"/usr/local/bin/auditstatus ssh\",restrict $(cat auditstatus_key.pub)" | sudo tee ~auditstatus/.ssh/authorized_keys
```

Store the private key as a repository secret named `AUDITSTATUS_SSH_KEY`. The forced command accepts three operations (`check`, `enroll` and `activate`), so the key cannot open a shell.


## 3. Pin each server's host key

The verifier refuses a server whose host key it does not know. Pin the keys next to the configuration and compare the fingerprints with the ones each server shows:

```sh
ssh-keyscan -t ed25519 app1.example.com >> known_hosts
ssh-keygen -lf known_hosts
```

Commit `known_hosts`. Do not hash the entries with `ssh-keyscan -H`: `auditstatus doctor` looks for the plain host name.


## 4. Pin the action and push

Pin `auditstatus/auditstatus.com` to the full commit SHA of a release, since a tag can be moved. Then commit `auditstatus.config.yml`, `known_hosts` and the workflow, and push. The generated workflow runs every hour, on a push to `main` or `master`, and on demand.

```yaml
- uses: auditstatus/auditstatus.com@<release commit> # v2
  with:
    config: auditstatus.config.yml
    ssh-key: ${{ secrets.AUDITSTATUS_SSH_KEY }}
```


## 5. Read the report

Each run commits `report.md`, `report.json` and `badge.json` to the `audit-status` branch. `report.md` has one row per server, with its status and evidence level, then each finding. [Reports](/docs/reports/) explains every finding and what to do about it.

Add the badge to your README or status page:

```md
[![Audit Status](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPOSITORY/audit-status/badge.json)](https://github.com/OWNER/REPOSITORY/blob/audit-status/report.md)
```


## Why does the workflow have two jobs?

A configured `build` runs your repository's build scripts, and the install scripts of its dependencies, in the job that holds the SSH key. The generated workflow keeps that job read-only: the `verify` job runs the verifier with `contents: read` and uploads the report, and the `publish` job, which runs no code from your repository and holds no SSH key, commits the report and manages the issue. The action also runs builds as an unprivileged `auditstatus-build` account on Linux runners.


## Main inputs

| Input            | Default                  | What it does                                                                 |
| ---------------- | ------------------------ | ---------------------------------------------------------------------------- |
| `config`         | `auditstatus.config.yml` | The verifier configuration.                                                  |
| `ssh-key`        | empty                    | The private key the servers' forced command allows.                          |
| `publish-branch` | empty                    | Commit the report to this branch. Empty skips publishing.                    |
| `issue`          | `'true'`                 | Open an issue when the audit does not pass, close it when it passes again.   |
| `fail-on`        | `error`                  | Fail the job on `fail`, on `error` (failed or inconclusive), or `never`.     |
| `attest-report`  | `auto`                   | Sign the report files with the workflow's identity (`report.sigstore.json`). |

The action's outputs are `status` (`pass`, `warn`, `fail` or `error`), `report` (the path of `report.json`) and `attestation`. Every input, output and permission is in [The GitHub action](/docs/verifier/#the-github-action).


## How do readers check a published report?

Anyone who can push to the report branch can edit it, so the publish job signs the report with a GitHub artifact attestation. A reader checks a copy of the branch with `auditstatus verify-report`, which confirms the signing workflow, that the files are the ones it signed, and that the signature is recent:

```sh
auditstatus verify-report --dir audit-status \
  --signer example/app/.github/workflows/auditstatus.yml@refs/heads/main
```

See [Checking a published report](/docs/verifier/#checking-a-published-report).
