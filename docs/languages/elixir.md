# Elixir and Erlang

Deploy in one of two ways. Deploy a git checkout and fetch dependencies with Mix, so their sources land in `deps/`. Or deploy a release built by CI, with an attested manifest. For a checkout, the attester hashes every file and every dependency source, and the verifier compares each dependency with the Hex tarball whose checksum `mix.lock` pins. For a release, the verifier checks every file against the attested manifest. In both cases each BEAM process is inspected.


## What gets verified

| What                                 | Reference                                                                                                                                                            | Check          |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| Tracked files (checkout)             | The deployed commit, on the audited branch                                                                                                                           | `source`       |
| Each dependency in `deps/`           | The tarball repo.hex.pm serves, checked against the outer checksum in `mix.lock`                                                                                     | `packages:hex` |
| Every file of a release              | The attested `.attestium-manifest.json` (see [binaries](binaries.md))                                                                                                | `artifact`     |
| Compiled code in `_build` (checkout) | A build of the same commit, when `build` is set and the build is reproducible                                                                                        | `build`        |
| Each process                         | `ERL_FLAGS`, `ERL_AFLAGS` and `ERL_ZFLAGS` with `-eval`, `-s`, `-run`, `-pa`, `-pz`, `-boot` or `-config`; `ERL_LIBS`; distribution (`-name`, `-sname`); memory maps | `process`      |


## Requirements

* Commit `mix.lock`, written by a current Mix, so each entry carries the outer checksum (the SHA-256 of the tarball). An entry with only the inner checksum cannot be verified.
* Fetch exactly the lockfile: `mix deps.get --only prod` with `MIX_ENV=prod`.
* Ignore `deps/` and `_build/` in `.gitignore`.
* Use packages from the public Hex repository (`hexpm`). Git dependencies and other Hex repositories cannot be verified.
* The BEAM JIT maps its generated code through a memory file named `vmem`. In a BEAM process that memory file is recognized and reported as `memfd-exec` with severity info; any other memory file fails. `+JMsingle true` turns the dual mapping off if you prefer no memory file at all.


## Attester configuration

For a checkout:

```yaml
version: 2
services:
  - name: app
    root: /srv/app/current
    user: app
    ecosystems: [hex]
```

`deps/` is found when the service root holds both `mix.lock` and `deps/`. Sources are hashed without each dependency's `_build` and `ebin` directories.

For a release, set `ecosystems: false` and point `root` at the release directory, which holds `.attestium-manifest.json`.


## Verifier configuration

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/app.git
      branch: main
    # A release built by CI (`mix release`) instead of a checkout: attest
    # its manifest (see ../binary-release).
servers:
  - name: app1
    host: app1.example.com
```

For a release, add the signer:

```yaml
    artifact:
      signer:
        repository: example/app
        workflow: .github/workflows/release.yml
```

Set `references.registries.hex` for a Hex mirror. See [configuration](../configuration.md).


## Build and deploy

The tested checkout setup:

```sh
mix deps.get                              # in the repository (MIX_ENV=prod), then commit mix.lock
git clone https://github.com/example/app.git /srv/app/current
cd /srv/app/current
MIX_ENV=prod mix deps.get --only prod
```

The dependency check covers sources only. What runs is compiled into `_build`, which git ignores, so it is listed but not compared. To compare it, set `build` to the same `mix compile` command with `outputs` under `_build/prod/`; this works only when the compiled files are byte for byte the same on the verifier.

For a release, build in CI with `mix release`, copy the release directory into `dist`, and follow the release workflow in [binaries](binaries.md): `auditstatus manifest --dir dist`, `actions/attest-build-provenance`, then deploy the directory.


## Common findings

| Finding                                                                                                                 | Cause and fix                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `memfd-exec` (process, fail)                                                                                            | A memory file other than the JIT's `vmem` is mapped executable in a BEAM process. Investigate: it is not the runtime's.                                                                                      |
| `mix.lock has only the inner checksum (update it with a current Mix)`                                                   | Run `mix deps.get` with a current Mix and commit `mix.lock`.                                                                                                                                                 |
| `dependency is not in mix.lock`                                                                                         | `deps/` holds a dependency the lockfile does not list. Remove `deps/` and fetch again.                                                                                                                       |
| `fetched from ..., not Hex`                                                                                             | A git or path dependency. It cannot be checked (`policy.unverifiablePackages`, default `fail`).                                                                                                              |
| `files differ from the Hex tarball`                                                                                     | A dependency source was changed after fetch. Fetch again.                                                                                                                                                    |
| `Dependency sources are checked; the compiled code that runs (_build or a release) is checked by reproducing the build` | Informational. Configure `build` to compare the compiled code.                                                                                                                                               |
| `A hex lockfile is at the deployed commit, but the server reported no installed hex packages`                           | For a checkout, check that `deps/` is in the service root. A release verified by its manifest reports `A hex lockfile is at the released commit; the release has no installed hex packages` as info instead. |
| `beam-distribution` (process)                                                                                           | Distributed Erlang is on; any node with the cookie can run code in this one. Turn it off if the app does not need it.                                                                                        |


## Limits

* Dependency sources are verified; the BEAM files compiled from them are verified only through a reproduced build or an attested release.
* Git and path dependencies, and private Hex repositories, are not verified.

See [how it works](../how-it-works.md) for the overall flow.
