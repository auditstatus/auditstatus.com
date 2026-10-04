# Go (static binaries)

Build in CI with `-trimpath` from a clean checkout, write the manifest with `auditstatus manifest`, and attest it (see `.github/workflows/release.yml` in ../binary-release). Deploy the release directory (rsync, a package, or an image).

Checked: the binary's hash against the attested release, the module, commit and `vcs.modified` recorded in the binary, and every dependency's hash against `go.sum` at that commit.

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
