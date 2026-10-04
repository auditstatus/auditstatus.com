# Node.js (npm, pnpm; PM2 or systemd)

Deploy with git (`git clone`, `git pull`, or `pm2 deploy`), install with the lockfile (`npm ci` with `package-lock.json` or `npm-shrinkwrap.json`, `pnpm install --frozen-lockfile` with `pnpm-lock.yaml`), and run with PM2 (cluster mode included) or systemd. `yarn.lock` is not read: a Yarn project's packages have no reference, so use npm or pnpm.

Checked: every tracked file against the commit, `node_modules` against the lockfile (tarball integrity, `github:` dependencies against the commit archive, pnpm patches), build output against a rebuild, the Node.js binary against the official release, global tools (npm, corepack, pnpm, pm2) against the Node.js archive and the registry, and each process for `NODE_OPTIONS`, `--require`/`--import`, inspector flags and PM2's `node_args`.

A package that adds files when it is installed (a native module compiled by `node-gyp`) differs from its tarball and fails, unless `pnpm.onlyBuiltDependencies` in `package.json` lists it: then the files it shipped must still match, and the files its build added are accepted without comparison. `policy.builtPackages` does not apply to npm packages (it covers gems with native extensions).

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
