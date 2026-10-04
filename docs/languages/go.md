# Go

A Go service is one static binary. Its hash is what proves what it is, and it can be checked in two ways: the verifier builds the same commit itself and compares the bytes, or CI builds the binary, writes a release manifest and attests it. In both cases the verifier also reads the build information Go records in the binary (module, commit, `vcs.modified`, and every dependency with its `go.sum` hash) and compares it with `go.mod` and `go.sum` at the deployed commit.


## What gets verified

| What                                         | Reference                                                            | Check         |
| -------------------------------------------- | -------------------------------------------------------------------- | ------------- |
| Tracked files (checkout)                     | The deployed commit, on the audited branch                           | `source`      |
| The binary (checkout)                        | The same file from a build of the commit the verifier runs (`build`) | `build`       |
| Every file of a release, the binary included | The attested `.attestium-manifest.json` ([binaries](binaries.md))    | `artifact`    |
| The main module recorded in the binary       | The `module` line of `go.mod` in `goModule`                          | `packages:go` |
| `vcs.revision` recorded in the binary        | The deployed commit                                                  | `packages:go` |
| `vcs.modified` recorded in the binary        | Must not be `true`                                                   | `packages:go` |
| Each dependency recorded in the binary       | Its `h1:` hash in `go.sum` at the deployed commit (after `replace`)  | `packages:go` |
| Each process                                 | Preloaded libraries, `LD_PRELOAD`, `LD_AUDIT`, tracers, memory maps  | `process`     |

The build information is written by the build, so it proves nothing by itself. It shows which dependencies went into a binary whose hash was proved another way.


## Requirements

* Commit `go.mod` and `go.sum`.
* Build from a clean checkout of a commit on the audited branch, so the binary records that commit and `vcs.modified=false`. Keep build output out of the working tree or ignored by `.gitignore`: an untracked file that is not ignored marks the tree modified.
* Build with `-trimpath` and `CGO_ENABLED=0`, so the bytes do not depend on paths or the C toolchain.
* Use the same Go version everywhere (`GOTOOLCHAIN=local`, and the same `go` release on the build machine and the verifier).
* Do not set `-buildvcs=false`: without a recorded commit, the binary cannot be tied to one.


## Attester configuration

```yaml
version: 2
services:
  - name: app
    root: /srv/api/current
    user: api
    ecosystems: false
```

Go has no installed packages to scan; the build information is read from each running binary.


## Verifier configuration

### Attested release

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/api.git
      branch: main
    # The binary is built by CI from a commit; the release directory holds
    # it and its attested manifest.
    artifact:
      signer:
        repository: example/api
        workflow: .github/workflows/release.yml
    goModule: .
servers:
  - name: app1
    host: app1.example.com
```

`goModule` is the directory, relative to the repository root, that holds `go.mod` (default `.`). `repository` is needed for the build information check: `go.mod` and `go.sum` are read from the commit the manifest names.

### Build by the verifier

The tested setup builds on the server in the checkout and has the verifier build the same commit:

```yaml
    build:
      command: go build -o app .
      outputs: [app]
      passEnv: [CGO_ENABLED, GOFLAGS, GOTOOLCHAIN, GOPATH, GOCACHE, HOME, PATH]
```

with `CGO_ENABLED=0`, `GOFLAGS=-trimpath` and `GOTOOLCHAIN=local` set in the verifier's environment and on the server. Fixed values can go in `build.env` instead of `passEnv`. The verifier builds in a clone of the repository, so Go records the same version control information as on the server. See [configuration](../configuration.md).


## Build and deploy

Attested release, from [the release workflow](../../examples/workflows/release.yml):

```yaml
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Build
        run: |
          mkdir -p dist
          CGO_ENABLED=0 go build -trimpath -o dist/api ./cmd/api
          cp -R config dist/

      - name: Write the release manifest
        run: npx --yes auditstatus@2 manifest --dir dist

      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: dist/.attestium-manifest.json
```

Deploy the contents of `dist` (with `.attestium-manifest.json`) as the service root, by rsync, a package or an image. See [binaries](binaries.md) for the manifest and the signer checks.

Build on the server, as tested:

```sh
go mod tidy                               # in the repository, then commit go.mod and go.sum
git clone https://github.com/example/api.git /srv/api/current
cd /srv/api/current
CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local go build -o app .
```

with `/app` in `.gitignore`. Restart the service after each deploy.


## Common findings

| Finding                                                                  | Cause and fix                                                                                                                 |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `Build output differs from a build of the public commit`                 | The build is not reproducible: a different Go version, `CGO_ENABLED`, flags, or `-ldflags`. Build the same way on both sides. |
| `... was built from a modified working tree`                             | The build ran with uncommitted or untracked files. Build from a clean checkout and ignore build output.                       |
| `... was built from commit ..., not the deployed ...`                    | The binary does not come from the deployed commit. Rebuild.                                                                   |
| `... was built from module ..., not ...`                                 | `goModule` points at another module, or the binary is another program.                                                        |
| `... is not in go.sum` / `hash ... differs from go.sum`                  | A dependency that the committed `go.sum` does not pin. Run `go mod tidy`, commit, and rebuild.                                |
| `replaced by the local directory ...`                                    | A `replace` with a local path. It cannot be checked (`policy.unverifiablePackages`, default `fail`).                          |
| `records no commit (built with -buildvcs=false or outside a repository)` | Build inside a git checkout, without `-buildvcs=false` (info).                                                                |
| `was built without -trimpath`                                            | Add `-trimpath` (info).                                                                                                       |
| `The release manifest ... is not attested by ...`                        | See [binaries](binaries.md).                                                                                                  |


## Limits

* The build information check shows which dependencies were built in. The binary's hash, from a reproduced build or an attested release, is what proves the binary.
* Binaries built with cgo link against system libraries; those are explained as code only by the distribution's signed archive or by `executables`.

See [how it works](../how-it-works.md) for the overall flow.
