# Any compiled program (C, C++, Zig, Swift, Haskell, ...)

Any language: build in CI, write a manifest of the release directory with `auditstatus manifest --dir dist`, attest it with `actions/attest-build-provenance`, and deploy the directory. The verifier checks every file against the manifest and the attestation against the workflow and branch that must have built it.

Shared libraries from the distribution are compared with the signed Debian or Ubuntu archive; anything else is pinned under `executables`.

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
