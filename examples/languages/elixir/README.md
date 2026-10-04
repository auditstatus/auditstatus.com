# Elixir and Erlang (Mix, releases)

Deploy with git and `mix deps.get --only prod` (dependencies in `deps/`), or deploy a release built in CI with an attested manifest.

Checked: every file in `deps/` against the Hex tarball whose checksum `mix.lock` pins, and each BEAM process for `ERL_FLAGS`, `ERL_AFLAGS`, `ERL_ZFLAGS`, `ERL_LIBS` and an open distribution port.

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
