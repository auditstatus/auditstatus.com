# Node.js

Deploy a git checkout, install dependencies from the lockfile, and run the app with PM2 or systemd. The attester hashes every file in the checkout, every package in `node_modules`, the running `node` binary and the global tools next to it, and inspects each Node.js process. The verifier compares the files with the public commit, each package with the tarball the lockfile pins, the `node` binary with the official Node.js release, and build output with a build it runs itself.


## What gets verified

| What                                                   | Reference                                                                                                                                                                            | Check            |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------- |
| Tracked files                                          | The deployed commit in the public repository, which must be on the audited branch                                                                                                    | `source`         |
| Build output the repository ignores (`dist/`, bundles) | A build of the same commit run by the verifier (`build`)                                                                                                                             | `build`          |
| Packages in `node_modules`                             | The registry tarball whose integrity `package-lock.json`, `npm-shrinkwrap.json` or `pnpm-lock.yaml` pins                                                                             | `packages:npm`   |
| Dependencies pinned to a GitHub commit                 | The archive GitHub serves for that commit                                                                                                                                            | `packages:npm`   |
| pnpm patches                                           | The registry tarball with the patch from `pnpm.patchedDependencies` applied                                                                                                          | `packages:npm`   |
| The `node` binary                                      | The binary inside the official release archive listed in `SHASUMS256.txt` on nodejs.org                                                                                              | `code`           |
| Global `npm` and `corepack`                            | The copy shipped in the official Node.js archive of the running version                                                                                                              | `globalPackages` |
| Global `pnpm`, `pm2` and others                        | The registry tarball of the installed version                                                                                                                                        | `globalPackages` |
| Each process                                           | `NODE_OPTIONS` preloads and inspector flags, `--require` and `--import`, inspector ports, PM2 `node_args` and `interpreter_args`, `NODE_PATH`, a rewritten command line, memory maps | `process`        |
| Package build provenance (optional)                    | npm provenance attestations (`references.npmProvenance: true`)                                                                                                                       | `provenance`     |


## Requirements

* Commit `package-lock.json` or `npm-shrinkwrap.json` (lockfile version 2 or 3; the same format) or `pnpm-lock.yaml` (lockfile version 6 to 9) at the repository root. The first found of `pnpm-lock.yaml`, `npm-shrinkwrap.json` and `package-lock.json` is read. For a project in a subdirectory, set `lockfiles.npm` in the verifier configuration (for example `web/package-lock.json`); the `package.json` next to it holds the pnpm patches.
* `yarn.lock` is not read. A Yarn project has no reference for its packages; switch to npm or pnpm. `auditstatus init` says so when it finds one.
* Install exactly what the lockfile pins: `npm ci` or `pnpm install --frozen-lockfile`.
* Install `node_modules` in the service root, or list its directory under `installs` in the attester configuration.
* Run an official Node.js build from nodejs.org (the release tarball, unchanged). A binary that embeds the nodejs.org release URL but differs from the release fails (`policy.unofficialNode`, default `fail`).
* Ignore build output and `node_modules` in `.gitignore`. Anything untracked and not ignored fails.
* Restart or reload the app after each deploy. A tracked file, build output or file in `node_modules` written after a process started fails (`policy.modifiedAfterStart`), and so does one restored afterwards.
* After upgrading PM2, run `pm2 update`: PM2's files written after its daemon started fail the same way.


## Attester configuration

`/etc/auditstatus/config.yml` on each server:

```yaml
version: 2
services:
  - name: app
    root: /srv/app/current
    user: app
    ecosystems: [npm]
```

Global tools are found next to the first official `node` binary a process runs (`<prefix>/lib/node_modules`). To change the list or the directory:

```yaml
runtimes:
  node:
    globalDir: /usr/local/lib/node_modules
    globalPackages: [npm, corepack, pnpm, pm2]
```

`[npm, corepack, pnpm, pm2]` is the default list. See [the attester guide](../attester.md) for every setting.


## Verifier configuration

`auditstatus.config.yml`:

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/app.git
      branch: main
    # Build output the repository ignores, rebuilt by the verifier:
    # build:
    #   command: pnpm install --frozen-lockfile && pnpm run build
    #   outputs: [dist/**]
servers:
  - name: app1
    host: app1.example.com
```

`build.outputs` cannot name files under `node_modules`: the attester reports installed packages separately, and they are compared with the lockfile instead. See [configuration](../configuration.md) for `build.env`, `build.passEnv`, `build.timeoutSeconds` and the `policy` settings.


## Build and deploy

* Deploy with `git clone`, `git pull` or `pm2 deploy`, then `npm ci` or `pnpm install --frozen-lockfile`.
* With `pm2 deploy` (or any layout with a `current` link), set `root` to the link. The attester resolves it, so only processes running from the current release are inspected. Processes left running from an older release are listed, not inspected.
* PM2 cluster mode: each worker is its own process whose working directory is the service root, so every worker is inspected. The options in the PM2 configuration (`node_args`, `interpreter_args`) are read from the `pm2_env` variable of each worker and checked like command-line options. The PM2 daemon keeps the directory it was first started in; outside the service root it is listed as another process of the user, not inspected. Start it outside the service root (for example `(cd / && pm2 ping)` before `pm2 startOrGracefulReload`): a daemon started inside it is inspected, and its renamed command line is reported as `argv-rewritten`, since any process can take its title. The global `pm2` package it runs is compared with the registry.
* Build output: run the same command on the server and in `build.command`. The build must produce the same bytes from the same commit. The verifier warns when it built with a different Node.js version than the server runs; set the same version in the verification workflow (`node-version` input of the action).
* Install scripts: a package that writes files while installing (a native addon compiled with `node-gyp`, or a prebuilt one downloaded by `prebuild-install`, as `better-sqlite3` does) no longer matches its tarball and fails. List it in `package.json` under `pnpm.onlyBuiltDependencies` to allow it to add build output; the list applies to npm installs (`package-lock.json`) too. Packages that ship their prebuilt addons in the tarball (`bcrypt`, `sharp` and its `@img/*` packages) match without it. It still may not change the files it shipped, except to replace one with the same file of an installed, verified optional dependency (esbuild copies its platform package's `bin/esbuild` over its launcher). The added files are not verified.


## Common findings

| Finding                                                                               | Cause and fix                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Files not in the public commit (and not ignored by it) are present`                  | A file the deploy wrote that `.gitignore` does not cover. Ignore it in the repository, or list it in `policy.allowUntracked`.                                                                       |
| `Files differ from the public commit`                                                 | A hot fix, or a checkout of another commit. Deploy from the audited branch.                                                                                                                         |
| `No lockfile at the deployed commit pins these packages`                              | No `package-lock.json` or `pnpm-lock.yaml` at the commit. Commit one.                                                                                                                               |
| `installed package is not in the lockfile or any bundle`                              | `npm install` instead of `npm ci`, or a package added by hand. Reinstall with the lockfile.                                                                                                         |
| `files differ from reference tarball`                                                 | A package was edited after install, or an install script added files. Reinstall, or list the package in `pnpm.onlyBuiltDependencies`.                                                               |
| `resolved from ..., not the registry`                                                 | The lockfile resolves the package from a tarball URL, a directory or a git host other than a pinned GitHub commit. These cannot be checked (`policy.unverifiablePackages`, default `fail`).         |
| `Files in node_modules that belong to no package`                                     | Leftover hidden files or directories, for example from an older install (`warn`). Remove `node_modules` and install again.                                                                          |
| `Files in node_modules that Node.js can load in place of a package`                   | A file directly in a `node_modules` directory (`alpha.js` next to `alpha/`) is what `require('alpha')` loads first, so it can replace a package's code. Fails. Remove it and find out who wrote it. |
| `Python bytecode caches in installed packages are not verified`                       | `node-gyp` ran Python inside a package. Remove the `__pycache__` directories after install (`policy.bytecode`, default `warn`).                                                                     |
| `differs from the official Node.js ... release`                                       | A Node.js build that is not the unchanged nodejs.org binary. Install the official release.                                                                                                          |
| `The build was reproduced with Node.js ...; the server runs ...`                      | Match the Node.js version of the build with the servers.                                                                                                                                            |
| `argv-rewritten`                                                                      | The process changed `process.title` outside PM2, which hides its start options.                                                                                                                     |
| `tracked files, build output or installed packages changed after the process started` | The app was not restarted after a deploy. Reload it. If no deploy explains it, a file was changed and perhaps restored: find out who did it.                                                        |
| `The PM2 daemon (pid N): PM2's files changed after it started`                        | PM2 was upgraded while its daemon ran. Run `pm2 update`.                                                                                                                                            |


## Limits

* Native addons compiled on the server (`.node` files) have no reference; they are allowed only for packages in `pnpm.onlyBuiltDependencies`, and are not verified.
* For a dependency pinned to a GitHub commit, every installed file must be in the commit's archive unchanged, but a file removed after packing (other than `package.json`) is not detected.
* Code the app loads at run time from outside the checkout (downloaded plugins, `eval`) is not covered by the file checks. Memory checks cover anonymous executable code, which V8 creates for its JIT and which is counted, not flagged.

See [how it works](../how-it-works.md) for the overall flow, and [binaries](binaries.md) for a Node.js app shipped as a bundle or a single executable.
