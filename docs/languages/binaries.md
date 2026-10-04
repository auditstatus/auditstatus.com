# Compiled and bundled releases

Any language works when the release is built in CI and deployed without git: C, C++, Zig, Swift, Haskell, a Go or Rust binary, a .NET publish directory, an Elixir release, a JavaScript bundle, or a Node.js single executable. CI writes a manifest of the release directory with `auditstatus manifest`, attests it with GitHub artifact attestations, and the directory is deployed with the manifest at its root. The verifier checks that the attestation was made by the configured repository and workflow for the commit the manifest names, that the commit is on the audited branch, and that every file on the server matches the manifest.


## What gets verified

| What                                                                                 | Reference                                                                                                           | Check                           |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `.attestium-manifest.json`                                                           | A GitHub artifact attestation (a Sigstore bundle) for its SHA-256, signed by the configured repository and workflow | `artifact`                      |
| The commit the manifest names                                                        | Must equal the commit in the attestation, exist in the public repository, and be on the audited branch              | `artifact`, `source`            |
| Every file in the release directory                                                  | Its SHA-256 and mode in the manifest; files not in the manifest fail                                                | `artifact`                      |
| Installed packages in the release (`node_modules`, a virtual environment, `vendor/`) | The lockfile at the manifest's commit, as for a checkout                                                            | `packages:*`                    |
| Go and Rust binaries in the release                                                  | Their build information against `go.sum` or `Cargo.lock` at the commit ([go](go.md), [rust](rust.md))               | `packages:go`, `packages:cargo` |
| Third-party programs the service runs                                                | Hashes pinned under `executables`, or a published checksum list with its signature                                  | `code`                          |
| Shared libraries from the distribution                                               | The file in the owning Debian or Ubuntu package, from the signed archive                                            | `code`                          |
| Each process                                                                         | The runtime's code-loading variables and options, preloaded libraries, tracers, memory maps                         | `process`                       |


## Requirements

* Build in a GitHub Actions workflow from a commit on the audited branch, with `id-token: write` and `attestations: write` permissions.
* Write the manifest after the build, into the directory you deploy.
* Deploy the directory unchanged, with `.attestium-manifest.json` at the service root.
* Keep logs, uploads and other runtime files out of the release directory, or list them in `policy.allowUntracked`.
* Give the verifier a GitHub token to fetch attestations (`references.githubTokenEnv`, default `GITHUB_TOKEN`) and, in its workflow, `attestations: read`.


## The manifest

```sh
auditstatus manifest --dir dist [--repository owner/name] [--commit sha] [--exclude glob]...
```

* `--dir` is required. `--repository` and `--commit` default to `GITHUB_REPOSITORY` and `GITHUB_SHA`; the commit must be a full 40-character id.
* It writes `dist/.attestium-manifest.json` and prints its SHA-256 and path.
* Every file is listed with its SHA-256 (or `symlink:<target>`) and mode. `.git` and the manifest itself are left out.
* `--exclude` leaves matching paths out; repeat it for several patterns.

The attester lists installed package directories (`node_modules`, a virtual environment, `vendor/bundle`, `deps/`, `vendor/`, jar directories, a .NET publish directory) apart from the other files, and compares them with the lockfile. Leave them out of the manifest, for example `--exclude node_modules`; otherwise their files are reported missing.

The format is described in the [Attestium specification](https://github.com/attestium/attestium.com/blob/main/SPEC.md#release-manifests).


## Attester configuration

```yaml
version: 2
services:
  - name: app
    root: /opt/app/current
    user: app
    ecosystems: false
```

`root` is the deployed release directory. Set `ecosystems` to a list (or leave it `auto`) when the release carries installed packages.


## Verifier configuration

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/app.git
      branch: main
    artifact:
      signer:
        repository: example/app
        workflow: .github/workflows/release.yml
    # Third-party programs the service runs, by published checksums:
    executables:
      - path: /usr/local/bin/helper
        checksums:
          url: https://example.com/releases/1.2.3/SHA256SUMS
          signature:
            type: minisign
            publicKey: RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
servers:
  - name: app1
    host: app1.example.com
```

`artifact.signer`:

| Key          | Meaning                                                                                                                                      |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `repository` | Required. The `owner/name` whose workflow signed the attestation.                                                                            |
| `workflow`   | The workflow file, such as `.github/workflows/release.yml`. When unset, any workflow in the repository is accepted.                          |
| `ref`        | The git ref the workflow ran on, such as `refs/heads/main`. When unset, any ref is accepted; the commit must still be on the audited branch. |

`executables` entries:

| Key                             | Meaning                                                                                                               |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `path`                          | Absolute path of the program as the process runs it.                                                                  |
| `sha256`                        | A list of accepted SHA-256 values.                                                                                    |
| `checksums.url`                 | A checksum list, such as `SHA256SUMS`, that must contain the file's hash.                                             |
| `checksums.signature.type`      | `gpg`, `minisign` or `sigstore`.                                                                                      |
| `checksums.signature.url`       | The signature. Default: the list's URL with `.sig` (gpg), `.minisig` (minisign) or `.sigstore.json` (sigstore) added. |
| `checksums.signature.keyring`   | The GPG keyring file (`gpg`).                                                                                         |
| `checksums.signature.publicKey` | The minisign public key (`minisign`).                                                                                 |
| `checksums.signature.identity`  | Certificate claims to match, as strings or `/regex/` (`sigstore`).                                                    |

See [configuration](../configuration.md) and [the verifier guide](../verifier.md).


## Build and deploy

The example release workflow ([release.yml](../../examples/workflows/release.yml)):

```yaml
permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      # Build into dist/ (any language).

      - uses: actions/setup-node@v4
        with:
          node-version: '22'

      - name: Write the release manifest
        run: npx --yes auditstatus@2 manifest --dir dist

      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: dist/.attestium-manifest.json

      - name: Package
        run: tar -C dist -czf "api-${GITHUB_SHA}.tar.gz" .
```

Deploy by unpacking the archive into a new release directory and switching the service root to it (a `current` link, a package, or rsync). Restart the service afterwards.

To check an attestation by hand: `gh attestation verify dist/.attestium-manifest.json --repo example/app`.

### Single executables

A single executable, such as a Node.js single executable application, is one file in the release directory. It is compared with the manifest before anything else, so a Node.js single executable is not compared with the official Node.js release.

PM2 can still run several copies. Its cluster mode needs a JavaScript entry point, so run the executable in fork mode with several instances:

```js
module.exports = {
  apps: [{
    name: 'app',
    script: '/opt/app/current/app',
    interpreter: 'none',
    exec_mode: 'fork',
    instances: 4,
    cwd: '/opt/app/current',
  }],
};
```

Every instance whose working directory is inside the service root is inspected. The program can also start its own workers (for example with Node.js `cluster`); they are inspected the same way.


## Common findings

| Finding                                                                                        | Cause and fix                                                                                                                                                                               |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `The server deploys a release manifest, but no artifact signer is configured for this service` | Add `artifact.signer` to the service.                                                                                                                                                       |
| `The release manifest .attestium-manifest.json is missing`                                     | The service root has no manifest. Deploy it with the release.                                                                                                                               |
| `The release manifest is not attested by <repository>: ...`                                    | No attestation matches the manifest's hash, or it was signed by another repository, workflow or ref. Check `artifact.signer`, and that the attest step used the manifest as `subject-path`. |
| `The attestation is for commit ..., the manifest names ...`                                    | The manifest was written with another `--commit` than the workflow ran on.                                                                                                                  |
| `Commit ... is not on the public <branch> branch`                                              | The release was built from another branch. Build releases from the audited branch.                                                                                                          |
| `Files differ from the attested release`                                                       | A file was changed after deploy. Deploy the release again.                                                                                                                                  |
| `Files of the attested release are missing`                                                    | A file was removed, or an installed package directory was listed in the manifest. Use `--exclude` for package directories.                                                                  |
| `Files not in the attested release are present`                                                | A file written after deploy. Move it out of the release directory, or list it in `policy.allowUntracked`.                                                                                   |
| `Executables or libraries that no reference explains`                                          | A program or library outside the release and the distribution's packages. Pin it under `executables`.                                                                                       |


## Limits

* The attestation proves which workflow built the release, from which commit. It does not prove the build itself was reproducible; review the workflow.
* Only GitHub artifact attestations are read.
* Code the program loads from outside the release directory is covered only by the code check (programs and mapped libraries), not by the file check.

See [how it works](../how-it-works.md) for the overall flow, and [containers](../containers.md) to ship the release as an image instead.
