# PHP (Composer; PHP-FPM, Laravel, Symfony)

Deploy with git and `composer install --no-dev --classmap-authoritative`. Composer's lockfile pins each package's git commit; the verifier compares every installed file with that commit (respecting the package's `export-ignore`), and the autoloader files Composer generates are listed.

Checked: `vendor/` against each package's source commit, and each process for `PHP_INI_SCAN_DIR`, `PHPRC` and `-d` options (such as `auto_prepend_file`).

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
