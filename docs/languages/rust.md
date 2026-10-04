# Rust

A Rust service is one binary. Its hash is what proves what it is, and it can be checked in two ways: the verifier builds the same commit itself and compares the bytes, or CI builds the binary, writes a release manifest and attests it. Build with `cargo auditable` so the binary also records every crate compiled into it; the verifier compares that list with `Cargo.lock` at the deployed commit.


## What gets verified

| What                                         | Reference                                                                                                                                                                                        | Check            |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------- |
| Tracked files (checkout)                     | The deployed commit, on the audited branch                                                                                                                                                       | `source`         |
| The binary (checkout)                        | The same file from a build of the commit the verifier runs (`build`)                                                                                                                             | `build`          |
| Every file of a release, the binary included | The attested `.attestium-manifest.json` ([binaries](binaries.md))                                                                                                                                | `artifact`       |
| Each crate recorded by cargo-auditable       | The entry with the same name and version in `Cargo.lock`: same kind of source (crates.io, another registry, git, local), a pinned `checksum` for registry crates, a pinned commit for git crates | `packages:cargo` |
| Each process                                 | Preloaded libraries, `LD_PRELOAD`, `LD_AUDIT`, tracers, memory maps                                                                                                                              | `process`        |

The crate list is written by the build, so it proves nothing by itself. It shows which crates went into a binary whose hash was proved another way. A binary built without cargo-auditable has no list, and gets no `packages:cargo` finding.


## Requirements

* Commit `Cargo.lock`.
* Install cargo-auditable where the binary is built: `cargo install cargo-auditable --locked`.
* Build with the lockfile enforced: `cargo auditable build --locked --release`.
* For a build by the verifier, the bytes must be the same on both sides: the same toolchain (pin it in `rust-toolchain.toml`), the same profile and the same `RUSTFLAGS`. Paths can end up in the binary; strip debug information in the release profile, and build where `CARGO_HOME` is the same path or map it with `--remap-path-prefix` in `RUSTFLAGS`.


## Attester configuration

```yaml
version: 2
services:
  - name: app
    root: /srv/api/current
    user: api
    ecosystems: false
```

Rust has no installed packages to scan; the crate list is read from each running binary.


## Verifier configuration

### Attested release

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/api.git
      branch: main
    artifact:
      signer:
        repository: example/api
        workflow: .github/workflows/release.yml
servers:
  - name: app1
    host: app1.example.com
```

`repository` is needed for the crate check: `Cargo.lock` is read from the commit the manifest names. For a workspace whose `Cargo.lock` is not at the repository root, set `lockfiles.cargo`:

```yaml
    lockfiles:
      cargo: server/Cargo.lock
```

### Build by the verifier

The tested setup, with this release profile in `Cargo.toml`:

```toml
[profile.release]
debug = false
strip = true
```

and this service setting:

```yaml
    build:
      command: cargo auditable build --release --locked -q && cp target/release/app app
      outputs: [app]
      passEnv: [PATH, HOME, CARGO_HOME, RUSTUP_HOME, RUSTFLAGS]
      timeoutSeconds: 1200
```

The verifier runs the command in a clean clone of the deployed commit and compares `app` with the server's copy. The environment has only the base variables, `build.env` and the names in `passEnv`, so pass the toolchain's variables through. Raise `timeoutSeconds` for large builds (default 3600, at most 21600). See [configuration](../configuration.md).


## Build and deploy

Attested release: follow [the release workflow](../../examples/workflows/release.yml), with the build step for Rust:

```yaml
      - name: Build
        run: |
          cargo install cargo-auditable --locked
          mkdir -p dist
          cargo auditable build --locked --release
          cp target/release/api dist/

      - name: Write the release manifest
        run: npx --yes auditstatus@2 manifest --dir dist

      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: dist/.attestium-manifest.json
```

Deploy the contents of `dist` (with `.attestium-manifest.json`) as the service root. See [binaries](binaries.md) for the manifest and the signer checks.

Build on the server, as tested:

```sh
cargo generate-lockfile                   # in the repository, then commit Cargo.lock
git clone https://github.com/example/api.git /srv/api/current
cd /srv/api/current
cargo auditable build --release --locked -q && cp target/release/app app
```

with `/target` and `/app` in `.gitignore`. Restart the service after each deploy.


## Common findings

| Finding                                                  | Cause and fix                                                                                                                                     |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Build output differs from a build of the public commit` | The build is not reproducible: another toolchain, profile, `RUSTFLAGS`, or paths recorded in the binary. Align them, and strip debug information. |
| `not in Cargo.lock`                                      | The binary holds a crate the committed lockfile does not list. Build with `--locked`.                                                             |
| `built from ..., Cargo.lock says ...`                    | The crate came from another source than the lockfile names.                                                                                       |
| `Cargo.lock pins no checksum`                            | A registry crate without a checksum in `Cargo.lock` (`policy.unverifiablePackages`, default `fail`).                                              |
| `Cargo.lock pins no commit for this git source`          | A git dependency whose source in `Cargo.lock` has no full commit.                                                                                 |
| `the build information could not be read`                | The binary's crate list is damaged or unreadable (warn).                                                                                          |
| `No Cargo.lock found`                                    | No lockfile at the commit, or `lockfiles.cargo` is wrong.                                                                                         |
| `The release manifest ... is not attested by ...`        | See [binaries](binaries.md).                                                                                                                      |


## Limits

* The crate check shows which crates were compiled in. The binary's hash, from a reproduced build or an attested release, is what proves the binary.
* Crates are compared by name, version, source and pin; their source code is not downloaded.
* A binary linked against system libraries relies on the distribution's signed archive or `executables` to explain them.

See [how it works](../how-it-works.md) for the overall flow.
