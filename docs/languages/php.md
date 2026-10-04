# PHP

Deploy a git checkout and install dependencies with Composer. `composer.lock` pins each package to a commit of its source repository, and a commit names its file tree, so that tree is the reference. The attester hashes every file in the checkout and every file in `vendor/`, and inspects each PHP process. The verifier reads each package's tree at the pinned commit and compares every installed file with it, allowing for files the package marks `export-ignore`.


## What gets verified

| What                                                                                | Reference                                                                                                                                                                                                              | Check               |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| Tracked files                                                                       | The deployed commit, on the audited branch                                                                                                                                                                             | `source`            |
| Each package in `vendor/<vendor>/<name>`                                            | The git tree of the commit `composer.lock` pins (from `source.reference`, or a GitHub zipball URL in `dist`)                                                                                                           | `packages:composer` |
| Files missing from a package                                                        | Allowed only when the package's `.gitattributes` marks them `export-ignore` (a dist install)                                                                                                                           | `packages:composer` |
| Files in `vendor/` outside any package                                              | None allowed                                                                                                                                                                                                           | `packages:composer` |
| Files Composer generates (`vendor/autoload.php`, `vendor/composer/`, `vendor/bin/`) | A build of the same commit, when `build` covers them; otherwise listed with a warning                                                                                                                                  | `packages:composer` |
| Each process                                                                        | `PHP_INI_SCAN_DIR`, `PHPRC`, `-d` settings that load code (`auto_prepend_file`, `auto_append_file`, `extension`, `zend_extension`, `include_path`, `opcache.preload`), `-r`, `-B`, `-R`, `-E`, `-z`, `-c`, memory maps | `process`           |


## Requirements

* Commit `composer.lock`. Every package must pin a source commit (packages from Packagist and GitHub do).
* Install from the lockfile: `composer install --no-dev`. Dist (`--prefer-dist`) and source (`--prefer-source`) installs both work. A source install's `.git` directories are skipped.
* Ignore `vendor/` in `.gitignore`.
* Run PHP-FPM workers from the service root: set `chdir` in the pool to the service root. The attester inspects processes whose working directory is inside the root (or the service's `cwd`).
* Reload PHP-FPM after each deploy. A tracked file changed after a worker started fails (`policy.modifiedAfterStart`).


## Attester configuration

```yaml
version: 2
services:
  - name: app
    root: /var/www/app/current
    user: www-data
    ecosystems: [composer]
```

`vendor/` is found when the service root holds both `composer.lock` and `vendor/composer/`.


## Verifier configuration

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/app.git
      branch: main
servers:
  - name: app1
    host: app1.example.com
```

The generated autoloader runs first in every request. To compare it with a build of the same commit, add:

```yaml
    build:
      command: composer install --no-dev --classmap-authoritative
      outputs: [vendor/composer/**, vendor/autoload.php]
```

The build command must match the one the deploy runs, flag for flag. See [configuration](../configuration.md).


## Build and deploy

The tested setup:

```sh
composer update --no-install              # in the repository, then commit composer.lock
git clone https://github.com/example/app.git /var/www/app/current
cd /var/www/app/current
composer install --no-dev --prefer-source --no-interaction
```

Package trees are fetched from each package's repository and cached by the verifier.


## Common findings

| Finding                                                                                  | Cause and fix                                                                                                                                |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `Files Composer generates (the autoloader runs first in every request) are not compared` | No `build` covers them. Add the build above (default severity `warn`).                                                                       |
| `installed package is not in composer.lock`                                              | `vendor/` holds a package the lockfile does not list. Run `composer install` again from the lockfile.                                        |
| `composer.lock pins no source commit for this package`                                   | A package from a path, an artifact or a private host without a commit. It cannot be checked (`policy.unverifiablePackages`, default `fail`). |
| `files differ from <url> at <commit>`                                                    | A package file was changed, added, or removed after install. Reinstall.                                                                      |
| `Files in vendor/ that belong to no package`                                             | Leftover or hand-added files. Remove `vendor/` and install again.                                                                            |
| `could not read <url> at <commit>`                                                       | The package repository or commit is unreachable. The result is inconclusive until it is reachable.                                           |
| `argv-ini` (process)                                                                     | A `-d` setting that loads code, such as `auto_prepend_file`. Move it to reviewed configuration, or remove it.                                |
| `PHP_INI_SCAN_DIR` or `PHPRC` (process)                                                  | The service sets these. Remove them.                                                                                                         |


## Limits

* Each package repository must be reachable by the verifier at the pinned commit.
* PHP extensions and the PHP binary are explained as code only when a distribution package owns them or their hash is pinned under `executables`; see [the verifier guide](../verifier.md).
* `php.ini` and pool files outside the service root are not compared.

See [how it works](../how-it-works.md) for the overall flow.
