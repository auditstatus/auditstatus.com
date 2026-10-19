<!--
title: Install the Audit Status CLI from npm
description: Install the auditstatus command line tool from npm on Node.js 18 or later, then run init, doctor, validate and verify from your machine or any CI.
label: npm package
kind: howto
keywords: auditstatus npm, npm install -g auditstatus, audit status cli, auditstatus verify, run verifier in ci, auditstatus init
-->

<!--lint disable no-heading-punctuation-->

# Install the Audit Status command line tool from npm

The `auditstatus` package on npm installs the command line tool: `init` to write a starting configuration, `doctor` and `validate` to check a setup, and `verify` to run the verifier. It runs anywhere Node.js 18 or later runs, so you can verify servers from your own machine or from a CI system other than GitHub Actions.

Use the npm package for the verifier and for local work. Servers run the [release binary](/install/binary/) as the attester: the verifier compares the attester's own executable with the release's `SHA256SUMS`, and an npm installation runs a Node.js binary that is not in that list.


## 1. Install the package

```sh
npm install -g auditstatus
auditstatus help
```

`auditstatus help` lists every command and option. The package has two dependencies, `attestium` and `js-yaml`.


## 2. Write a starting configuration

In the repository your servers deploy:

```sh
auditstatus init --host app1.example.com --root /srv/app --user app
```

`init` detects the languages from the lockfiles, a `Dockerfile` or compose file, and the `origin` remote. It prints what it found and writes what is missing:

```text
Detected: Node.js (package-lock.json)
  wrote auditstatus.config.yml
  wrote auditstatus/attester.config.yml
  wrote .github/workflows/auditstatus.yml
```

Open both configuration files and read the comments. Check `root` and `user` in the attester configuration, and `host` in the verifier configuration.


## 3. Check the configuration

`validate` checks a file against the same rules as the verifier, and `doctor --role verifier` also checks the pinned host keys, the SSH key and that each repository is reachable:

```sh
auditstatus validate --config auditstatus.config.yml
auditstatus validate --role attester --config auditstatus/attester.config.yml
AUDITSTATUS_SSH_KEY="$(cat auditstatus_key)" auditstatus doctor --role verifier
```

Editors with the YAML language server can check the files as you type, with the [JSON Schemas](/schema/).


## 4. Run a verification

```sh
AUDITSTATUS_SSH_KEY="$(cat auditstatus_key)" auditstatus verify
```

It prints one line per server and each finding that is not informational, then writes `report.json`, `report.md` and `badge.json` to `audit-status/`:

```text
web1: failing
  [fail] web source: Files differ from the public commit
Overall: failing. Reports written to /home/runner/work/status/status/audit-status
```

The exit status is `0` when every server passed (possibly with warnings), `1` when one failed, `2` on a usage or configuration error, and `3` when a check could not be completed. A CI system or a cron job can act on it without parsing the output.


## Which commands come with the package?

| Command                     | What it does                                                                      |
| --------------------------- | --------------------------------------------------------------------------------- |
| `auditstatus init`          | Detects the project's languages and writes the configuration and a workflow.      |
| `auditstatus doctor`        | Checks a setup (`--role attester` or `--role verifier`) and prints how to fix it. |
| `auditstatus validate`      | Validates a configuration file.                                                   |
| `auditstatus verify`        | Verifies every configured server and writes the report.                           |
| `auditstatus verify-report` | Checks a published report's signature, files and age.                             |
| `auditstatus tpm-verify`    | Enrolls a server's TPM and prints the key to pin.                                 |
| `auditstatus badge`         | Writes a badge from a report.                                                     |
| `auditstatus manifest`      | Writes a release manifest for a release built in CI.                              |

The attester commands (`ssh`, `serve`, `collect`, `check`, `monitor`) are in the package too, for development, but production servers should run the release binary.


## Where should the verifier run?

Somewhere the audited servers cannot reach or change, with the SSH private key stored as a secret. The verifier caches references (repository clones, reproduced builds, downloaded packages) in `.cache/auditstatus` next to the configuration; keep that directory between runs to save time. In GitHub Actions, the [GitHub Action](/install/github-action/) does all of this for you. See [Running the verifier yourself](/docs/verifier/#running-the-verifier-yourself).
