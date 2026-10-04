# .NET

Turn on NuGet lock files so `packages.lock.json` pins each package's content hash, and deploy the output of `dotnet publish`. The attester hashes every file in the checkout and every file in the publish directory, and inspects each .NET process. The verifier downloads every locked package from nuget.org, checks its content hash, and requires each assembly and native library in the publish directory to be a file one of those packages ships, unchanged. Files the build produces (the application's own assembly, its apphost, `deps.json` and `runtimeconfig.json`) are compared with a build the verifier runs: the attester hashes them with the publish directory, and the package check leaves the ones `build.outputs` names to the build.


## What gets verified

| What                                                                       | Reference                                                                                                                                                                 | Check            |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| Tracked files                                                              | The deployed commit, on the audited branch                                                                                                                                | `source`         |
| Each `.dll`, `.exe`, `.so`, `.dylib` or `.a` file in the publish directory | The file of the same name in a locked package, the package checked against the content hash (SHA-512) in `packages.lock.json`                                             | `packages:nuget` |
| The application's own assembly and other build output                      | A build of the same commit (`build`)                                                                                                                                      | `build`          |
| `deps.json`, `runtimeconfig.json` and the apphost                          | A build of the same commit; otherwise listed with a warning                                                                                                               | `packages:nuget` |
| Each process                                                               | `DOTNET_STARTUP_HOOKS`, `DOTNET_ADDITIONAL_DEPS`, `DOTNET_SHARED_STORE`, profilers (`CORECLR_ENABLE_PROFILING`), diagnostic ports (`DOTNET_DiagnosticPorts`), memory maps | `process`        |


## Requirements

* Set `RestorePackagesWithLockFile` in each project and commit `packages.lock.json`:

  ```xml
  <PropertyGroup>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  ```

* Publish with the lock file enforced: `dotnet publish -c Release -o publish -p:RestoreLockedMode=true -p:ContinuousIntegrationBuild=true`.

* Publish into a directory named `publish` or `out`. The attester finds it by its `*.runtimeconfig.json` and `*.deps.json` files, up to eight levels below the service root.

* Ignore `bin/`, `obj/` and `publish/` in `.gitignore`.

* Pin the SDK version (`global.json`) so the verifier's build gives the same bytes, and build with `-p:ContinuousIntegrationBuild=true` (on the server and in `build.command`): without it the assembly and `.pdb` record the absolute source path, which differs between the server and the verifier's checkout.


## Attester configuration

```yaml
version: 2
services:
  - name: app
    root: /srv/app/current
    user: app
    ecosystems: [nuget]
```


## Verifier configuration

The example configuration:

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/app.git
      branch: main
    # The application's own assemblies: rebuild them here or attest the
    # published output (see ../binary-release).
servers:
  - name: app1
    host: app1.example.com
```

The tested build, for a project `App.csproj`:

```yaml
    build:
      command: dotnet publish -c Release -o publish -p:RestoreLockedMode=true -p:ContinuousIntegrationBuild=true
      outputs:
        - publish/App.dll
        - publish/App.pdb
        - publish/App.deps.json
        - publish/App.runtimeconfig.json
        - publish/App
```

Every `packages.lock.json` up to four levels below the repository root is read (not under `bin/`, `obj/`, `.git/` or `node_modules/`). Set `lockfiles.nuget` to read one file only, and `references.registries.nuget` for a mirror. See [configuration](../configuration.md).


## Build and deploy

The tested setup:

```sh
dotnet restore                            # in the repository, then commit packages.lock.json
git clone https://github.com/example/app.git /srv/app/current
cd /srv/app/current
dotnet publish -c Release -o publish -p:RestoreLockedMode=true -p:ContinuousIntegrationBuild=true
dotnet publish/App.dll
```

Restart the service after each deploy. A tracked file or build output changed after the process started fails (`policy.modifiedAfterStart`).


## Common findings

| Finding                                                                                            | Cause and fix                                                                                                                    |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `no locked package ships this file, and no build reproduces it`                                    | The application's own assembly, or a file no locked package has. Add it to `build.outputs`.                                      |
| `differs from the file of the same name in the locked packages`                                    | A package assembly was replaced or changed. Publish again.                                                                       |
| `Build output that decides what the runtime loads (deps.json, runtimeconfig.json) is not compared` | Add these files to `build.outputs`.                                                                                              |
| `Locked packages that could not be checked`                                                        | A package could not be downloaded, or it does not match its content hash (fail).                                                 |
| `no packages.lock.json pins the application's packages`                                            | No lock file at the commit. Set `RestorePackagesWithLockFile` and commit it.                                                     |
| `DOTNET_STARTUP_HOOKS`, `dotnet-profiler`, `dotnet-diagnostic-port` (process)                      | A hook, profiler or diagnostic port is configured for the service. Remove it.                                                    |
| `memfd-exec`, `memfd-open` (process, fail)                                                         | A memory file other than the runtime's `doublemapper` is mapped or open in a .NET process. Investigate: it is not the runtime's. |


## Limits

* The .NET runtime maps its JIT code twice (W^X) from a memory file named `doublemapper`. In a .NET process that memory file is recognized and reported as `memfd-exec` and `memfd-open` with severity info; any other memory file fails. Do not turn W^X off (`DOTNET_EnableWriteXorExecute=0`): writable and executable memory is reported instead.
* The shared runtime in `/usr/lib/dotnet` or `/usr/share/dotnet` is explained as code only when a distribution package owns it or its hashes are pinned under `executables`. Install the runtime from the distribution's packages.
* Only assemblies and native libraries are matched to packages. Other files in the publish directory are listed with a warning unless `build.outputs` covers them; `.pdb`, `.xml`, `.md` and `.txt` files are not listed.

See [how it works](../how-it-works.md) for the overall flow, and [binaries](binaries.md) to ship the publish directory as an attested release.
