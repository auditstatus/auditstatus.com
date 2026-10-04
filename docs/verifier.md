# Verifier

The verifier runs away from the audited servers, usually in GitHub Actions: in your own workflow, as this page describes, or in Audit Status's, through the [public registry](registry.md). It sends each server a fresh nonce, receives the evidence, compares it with references it fetches itself, and writes a report. This page covers the verifier configuration, the GitHub action and its inputs and outputs, running `auditstatus verify` yourself, the output files, publishing, the badge, issues, exit codes and caching.


## The verifier configuration

The verifier reads `auditstatus.config.yml` in the current directory by default (`--config` for another file). Relative paths in it (`known_hosts`, the cache directory, keyrings) are resolved against the file's directory. `auditstatus init` writes a starting one. A minimal configuration:

```yaml
version: 2
services:
  - name: web
    repository:
      url: https://github.com/example/app.git
      branch: main
ssh:
  knownHosts: known_hosts
servers:
  - name: web1
    host: web1.example.com
```

Check it:

```sh
auditstatus validate --config auditstatus.config.yml
auditstatus doctor --role verifier
```

`validate` checks the file only. `doctor --role verifier` also checks the pinned host key of every SSH server, that an SSH key is set, that `kubectl` is installed when a server uses Kubernetes, that each repository is reachable (`git ls-remote`), that builds run as an account of their own (a warning if not) that can be used, that each server has a pinned TPM key (a warning if not), and that each file in `references.tpmRoots` exists. See [Configuration](configuration.md#verifier-configuration) for every setting.


## How the verifier reaches servers

Each server has a `transport`:

| Transport       | How                                                                                  | Needs                                                                   |
| --------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `ssh` (default) | Runs `ssh user@host "check <nonce>"`; the server's forced command runs the attester. | `host`, a pinned host key in `ssh.knownHosts`, and a private key.       |
| `kubernetes`    | `kubectl port-forward` to the attester pod on the node, then an HTTP request.        | `kubernetes.node` or `kubernetes.pod`. See [Kubernetes](kubernetes.md). |
| `local`         | Collects evidence in the verifier's own process. For a machine that verifies itself. | `attesterConfig`, the path of an attester configuration.                |

Servers are verified four at a time.

### SSH

The private key comes from the `AUDITSTATUS_SSH_KEY` environment variable (written to a private temporary file for the run) or from `ssh.identityFile`. Host keys must be pinned in `ssh.knownHosts` beforehand: an unknown or changed host key fails the connection, so the verifier cannot be pointed at an impostor.

```sh
ssh-keyscan -t ed25519 web1.example.com >> known_hosts
```

Collect host keys over a path you trust and compare the fingerprints (`ssh-keygen -lf known_hosts`) with the server's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server). For a port other than 22, the entry is `[host]:port` (`ssh-keyscan -p 2222 host` writes it that way).

SSH runs with `-F /dev/null`, `BatchMode=yes`, `StrictHostKeyChecking=yes`, the pinned `known_hosts` only, `IdentitiesOnly=yes`, no password or keyboard-interactive authentication, no agent or X11 forwarding, no TTY, and a connection timeout of 30 seconds. A server that does not answer within `ssh.timeoutSeconds` (600 by default) is inconclusive. Each server can override `ssh.user` and `ssh.port` with its own `user` and `port`.


## The GitHub action

The action installs the verifier from the ref it is pinned to, runs `auditstatus verify`, writes the report to the job summary, and optionally publishes the report and manages an issue. `auditstatus init` writes this workflow, which verifies in a read-only job and publishes from a second one (see [Verifying without write access](#verifying-without-write-access)):

```yaml
name: Audit Status

on:
  schedule:
    - cron: '17 * * * *'
  workflow_dispatch:
  push:
    branches: [main, master]

permissions:
  contents: read

concurrency:
  group: auditstatus
  cancel-in-progress: false

# Pin auditstatus/auditstatus.com to the full commit SHA of a release (a tag
# can be moved): uses: auditstatus/auditstatus.com@<commit> # v2

jobs:
  # A configured build runs the audited repository's build scripts here, so
  # this job's token is read-only; the report goes to the publish job.
  verify:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    permissions:
      contents: read
      attestations: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false

      - uses: auditstatus/auditstatus.com@v2
        with:
          config: auditstatus.config.yml
          ssh-key: ${{ secrets.AUDITSTATUS_SSH_KEY }}
          publish-branch: ''
          issue: 'false'
          fail-on: never
          # The publish job attests the report it publishes.
          attest-report: 'false'
          # The Node.js version any configured build runs with; match the servers.
          node-version: '22'

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: audit-status
          path: audit-status/

  # Publishes the report and opens or closes the issue; runs no code from
  # the audited repository and holds no SSH key.
  publish:
    needs: verify
    runs-on: ubuntu-24.04
    permissions:
      contents: write
      issues: write
      # Sign the report with this workflow's identity (attest-report).
      id-token: write
      attestations: write
    steps:
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          name: audit-status
          path: audit-status

      - uses: auditstatus/auditstatus.com@v2
        with:
          verify: 'false'
          publish-branch: audit-status
```

Pin the action to the full commit SHA of a release rather than a tag. `examples/workflows/audit-status.yml` is the same workflow with comments.

### Inputs

| Input            | Default                  | Meaning                                                                                                                                                                                                                                                                                                        |
| ---------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `config`         | `auditstatus.config.yml` | Verifier configuration file.                                                                                                                                                                                                                                                                                   |
| `ssh-key`        | `''`                     | Private key allowed by the attester's forced command on each server (a secret). Passed as `AUDITSTATUS_SSH_KEY`.                                                                                                                                                                                               |
| `servers`        | `''`                     | Space-separated server names to verify. Empty verifies all.                                                                                                                                                                                                                                                    |
| `output`         | `audit-status`           | Directory for `report.json`, `report.md` and `badge.json`, relative to the workspace or absolute. Overrides `output.dir`.                                                                                                                                                                                      |
| `publish-branch` | `''`                     | Commit the report to this branch (created if missing). Empty to skip.                                                                                                                                                                                                                                          |
| `issue`          | `'true'`                 | Open an issue when the audit does not pass, and close it when it passes again.                                                                                                                                                                                                                                 |
| `fail-on`        | `error`                  | Fail the job on: `fail` (a server failed), `error` (failed or inconclusive), or `never`. A configuration or usage error fails the job unless this is `never`.                                                                                                                                                  |
| `node-version`   | `'22'`                   | Node.js version to run the verifier with, and any configured builds.                                                                                                                                                                                                                                           |
| `build-user`     | `auditstatus-build`      | Unprivileged account that configured builds run as, created on Linux runners (no password, sudo or other groups; denied cron and at). Empty runs builds as the runner user.                                                                                                                                    |
| `verify`         | `'true'`                 | `'false'` publishes the report already in `output` without running the verifier: for a job that publishes what a read-only job verified (see below).                                                                                                                                                           |
| `attest-report`  | `auto`                   | Sign `report.json`, `report.md` and `badge.json` with the workflow's identity and add the bundle as `report.sigstore.json` (see [Checking a published report](#checking-a-published-report)). `auto` signs when the job has `id-token: write` and `attestations: write`; `true` requires it; `false` skips it. |

### Outputs

| Output        | Meaning                                                                                                                                   |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `status`      | Overall status: `pass`, `warn`, `fail` or `error`. `error` also when `report.json` could not be read (for example a configuration error). |
| `report`      | Absolute path to `report.json`.                                                                                                           |
| `attestation` | URL of the report's attestation, when it was attested.                                                                                    |

### Permissions and tokens

| Permission                               | Needed for                                                            |
| ---------------------------------------- | --------------------------------------------------------------------- |
| `contents: write`                        | `publish-branch`.                                                     |
| `issues: write`                          | `issue`.                                                              |
| `attestations: read`                     | Reading GitHub artifact attestations of release manifests and images. |
| `id-token: write`, `attestations: write` | `attest-report`.                                                      |

The action passes the job's `GITHUB_TOKEN` to the verifier, which uses it for GitHub's API (`references.githubTokenEnv`). For a private container registry, set the variable named by `containerRegistries.<registry>.tokenEnv` in the job's `env`.

### Verifying without write access

A configured `build` runs the audited repository's build scripts, and its dependencies' install scripts, in the job that holds the SSH key and the job's token. The action runs them as `auditstatus-build`, which cannot read either; on runners where that account is not used (`build-user: ''`, or not Linux), the build runs as the runner user, so treat it as able to read both. Either way, verify in a job whose token is read-only, and publish from a second job that runs no code from the audited repository:

```yaml
jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<commit> # v4
        with:
          persist-credentials: false
      - uses: auditstatus/auditstatus.com@<release commit> # v2
        with:
          ssh-key: ${{ secrets.AUDITSTATUS_SSH_KEY }}
          publish-branch: ''
          issue: 'false'
          fail-on: never
          # The publish job attests the report it publishes.
          attest-report: 'false'
      - uses: actions/upload-artifact@<commit> # v4
        with:
          name: audit-status
          path: audit-status/

  publish:
    needs: verify
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      # Sign the report with this workflow's identity (attest-report).
      id-token: write
      attestations: write
    steps:
      - uses: actions/download-artifact@<commit> # v4
        with:
          name: audit-status
          path: audit-status
      - uses: auditstatus/auditstatus.com@<release commit> # v2
        with:
          verify: 'false'
          publish-branch: audit-status
```

The report branch holds the report and nothing else: the action refuses to publish to the branch the workflow runs from.

### Checking a published report

Anyone who can push to the report branch can edit the report there. With `attest-report`, the job that publishes signs the report files with the workflow's identity (a GitHub artifact attestation, recorded in Sigstore's transparency log for public repositories) and publishes the bundle next to them as `report.sigstore.json`. `report.json` names the verifier's version, the action's ref (`verifier.action`) and the run (`verifier.run`).

A reader checks a copy of the branch with:

```sh
auditstatus verify-report --dir audit-status \
  --signer example/app/.github/workflows/auditstatus.yml@refs/heads/main
```

It verifies that the bundle is signed by that workflow, at that ref, for the repository; that `report.json`, and `report.md` and `badge.json` when present, are what it signed; that the run `report.json` names is the run that signed it (another attempt of the same run counts: a job run again); and that the signature is at most `--max-age` seconds old (86400 by default), so an older passing report put back on the branch is refused. The exit status is `0` for a verified passing report, `1` for a failing or unverified one, `3` for an inconclusive one. `--trusted-root` uses a Sigstore `trusted_root.json` instead of fetching it.

`gh attestation verify audit-status/report.json --repo example/app --signer-workflow example/app/.github/workflows/auditstatus.yml` checks the signature too, but not the other files or the age.

Choose `--max-age` from the workflow's schedule: a report signed more than one run ago means runs stopped publishing. The signature proves which workflow wrote the report, not that the workflow was honest: whoever can change the workflow or the verifier configuration on that branch can make it write anything (see the [threat model](threat-model.md#whom-you-trust)).

### Job result

The last step fails the job according to `fail-on`:

| `fail-on` | Job fails when the status is                                      |
| --------- | ----------------------------------------------------------------- |
| `fail`    | `fail`, or the verifier stopped on a configuration or usage error |
| `error`   | `fail` or `error` (a configuration error included)                |
| `never`   | never                                                             |

With `fail-on: fail`, an inconclusive result does not fail the job, but a configuration or usage error (exit status 2) does: nothing was verified.

On Linux runners the action also installs `debian-archive-keyring` when `/usr/share/keyrings/debian-archive-keyring.gpg` is missing, so the system packages of Debian servers can be compared with the signed Debian archive. When it cannot be installed, a warning says so.


## Running the verifier yourself

```sh
AUDITSTATUS_SSH_KEY="$(cat auditstatus_key)" auditstatus verify --config auditstatus.config.yml
```

| Option     | Default                  | Meaning                                      |
| ---------- | ------------------------ | -------------------------------------------- |
| `--config` | `auditstatus.config.yml` | The verifier configuration.                  |
| `--server` | all servers              | Verify only this server. Repeat for several. |
| `--output` | `output.dir`             | Where to write the report files.             |

It prints one line per server, then each finding that is not informational, then the overall status:

```text
web1: failing
  [fail] web source: Files differ from the public commit
Overall: failing. Reports written to /home/runner/work/status/status/audit-status
```

Text from the evidence is printed on one line, with control characters replaced by spaces, so a server cannot write CI workflow commands (`::`) or terminal escapes. Builds configured in `build` print their output on standard error.

### Exit status

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| `0`  | Passed, possibly with warnings.               |
| `1`  | At least one server failed.                   |
| `2`  | Usage or configuration error.                 |
| `3`  | Inconclusive: a check could not be completed. |


## Output files

`auditstatus verify` writes three files to the output directory:

| File          | Content                                                                  |
| ------------- | ------------------------------------------------------------------------ |
| `report.json` | Every server, service summary and finding, for machines and archives.    |
| `report.md`   | The same for people; GitHub renders it.                                  |
| `badge.json`  | A [Shields.io endpoint](https://shields.io/badges/endpoint-badge) badge. |

Values from the evidence are escaped before they reach Markdown, so a server cannot inject links or markup into a published report. Findings name executables, never command lines, which can hold secrets. See [Reports](reports.md) for how to read them.


## Publishing to a branch

With `publish-branch`, the action copies the output directory to the root of that branch and commits it as `chore: audit status report` when anything changed. The branch holds only the latest report files; its history keeps earlier ones. It is created as an orphan branch the first time.


## Badge

`badge.json` is a Shields.io endpoint. With `publish-branch: audit-status`:

```md
[![Audit Status](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPOSITORY/audit-status/badge.json)](https://github.com/OWNER/REPOSITORY/blob/audit-status/report.md)
```

| Message                 | Color        | Meaning                                          |
| ----------------------- | ------------ | ------------------------------------------------ |
| `passing`               | bright green | Every server passed.                             |
| `passing with warnings` | yellow       | Passed, with findings worth attention.           |
| `failing`               | red          | At least one server differs from its references. |
| `inconclusive`          | orange       | At least one check could not be completed.       |
| `unknown`               | light grey   | The report has no known status.                  |

When more than one server is verified and the status is not `passing`, the message adds how many passed, for example `failing (3/4)`. A passing message also names the evidence of its least-backed server, for example `passing, software evidence` or `passing, TPM + IMA` (`hardware evidence` when the servers are backed by different hardware), so the badge never claims more than every server showed. Software evidence can be forged by root on the server; see [A forged answer](how-it-works.md#a-forged-answer). The label is `output.label` (`audit` by default). To make a badge from an existing report:

```sh
auditstatus badge --report audit-status/report.json --output badge.json --label audit
```


## Issues

With `issue: 'true'`, when the status is `fail` or `error` and no open issue titled "Audit Status is not passing" exists, the action opens one with `report.md` as its body. When the status is `pass` or `warn` again, it closes that issue with the comment "Passing again."


## Retries

A deploy replaces files and rebuilds for a few minutes, and a server audited meanwhile looks tampered with. With `policy.retryAfterSeconds` (`0`, no retry, by default), a server that fails or is inconclusive is collected again after that many seconds with a new nonce. The second result is reported. What the first attempt found stays in it as a `retry` warning, so a server that restores itself in the meantime is not reported clean. A server that fails and is then inconclusive (it could not be collected again) stays failing: the `retry` finding is then a failure. Keep the job's `timeout-minutes` above the delay.


## Builds

With a `build` section, the verifier checks out the deployed commit, runs `build.command` there with `/bin/sh -c`, and compares every file that matches `build.outputs` with the server's copy. The command runs with a minimal environment: `PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ`, `TMPDIR`, `CI`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, the proxy variables, `build.env`, and the names in `build.passEnv`. Nothing else of the verifier's environment (tokens, the SSH key) is passed on.

The build runs the audited repository's own build scripts, and the install scripts of its dependencies. Run it as an account of its own with `build.user` (or `AUDITSTATUS_BUILD_USER`; the GitHub action creates `auditstatus-build` on Linux runners and sets it). The verifier, as root or through `sudo -n`, then:

1. checks that the account exists, is not root or the verifier's user, and that `fs.protected_hardlinks` is on, and that the cache is not writable by the account;
2. checks the commit out into a new directory outside the cache, in the system's temporary directory, and gives the checkout, a new `HOME` and a new `TMPDIR` to the account;
3. kills every process of the account, then runs the build with `setpriv` as the account's uid and gid, no supplementary groups, and no new privileges;
4. when the build ends (or times out), kills every process of the account again, including those that left the build's session, takes the directory back, hashes the outputs itself, writes the cached result, and removes the directory.

The account cannot read the environment of the verifier's processes (where the SSH key and tokens are), the temporary SSH key file or other files only the verifier's user can read, or write the cache, and nothing it starts outlives the build. It can read what any user of the machine can, and reach the network. The repository clone in the cache is shared with the checkout (read-only), so Go's `-buildvcs` and similar tools work; the cache must be readable, not writable, by the account.

Without an account, the build runs as the verifier's user. It can then read what that user can, including the SSH key and tokens, and change the verifier's cache for later runs; `auditstatus doctor --role verifier` warns about it. The build runs only for commits on the audited branch, so a server cannot make the verifier run other code. The build must be reproducible: same inputs, same bytes. A warning notes when it ran with a different Node.js version than the server runs; set the action's `node-version` to match. Results are cached per commit and build configuration, and a failed build is not repeated within a run.


## Caching

References are cached in `references.cacheDir` (`.cache/auditstatus` next to the configuration file by default): repository clones, reproduced builds, Node.js and package manifests, downloaded package references, and the Sigstore trust root. Git reads the clones with replace refs ignored (`GIT_NO_REPLACE_OBJECTS`), so a clone with `refs/replace/*` cannot make one commit read as another. The action resolves that directory from the configuration and saves and restores it with `actions/cache`, wherever the configuration is. A run that verifies every server removes checkouts of commits no server reported.


## Other verifier commands

| Command                  | Options                                                                    | What it does                                                                                        |
| ------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `auditstatus tpm-verify` | `--server name`, `--config file`, `--allow-uncertified`                    | Enrolls a server's TPM and prints the key to pin. See [Hardware evidence](hardware.md).             |
| `auditstatus validate`   | `--config file`, `--role attester\|verifier` (default `verifier`)          | Validates a configuration file and prints `<file> is a valid <role> configuration`.                 |
| `auditstatus badge`      | `--report file`, `--output file`, `--label text`                           | Writes a badge from a report.                                                                       |
| `auditstatus manifest`   | `--dir build`, `--repository owner/name`, `--commit sha`, `--exclude glob` | Writes `.attestium-manifest.json` for a release built in CI. See [Binaries](languages/binaries.md). |
