# Rust (Cargo)

Build in CI with `cargo auditable build --release --locked` so the binary records its crates, write the manifest with `auditstatus manifest`, and attest it.

Checked: the binary's hash against the attested release, and every crate recorded in it against `Cargo.lock` at the commit (version, source and pinned checksum).

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
