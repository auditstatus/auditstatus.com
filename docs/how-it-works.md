# How it works

Audit Status has three roles: an attester on each server that reports what runs there, a verifier in CI that compares that report with references it fetches itself, and a public report anyone can read. This page explains what the attester collects, what the verifier compares it with, how freshness is guaranteed, and what each evidence level proves.


## Roles

The roles follow the IETF remote attestation architecture ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)).

| Role          | What runs                                                                                       | What it does                                                                                                                                    |
| ------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Attester      | `auditstatus ssh` (or `auditstatus serve` in Kubernetes) on each server                         | Collects facts about the server and reports them as evidence. It never decides whether the server passes.                                       |
| Verifier      | `auditstatus verify`, usually in GitHub Actions: yours, or the [public registry](registry.md)'s | Sends a fresh nonce, receives the evidence, and compares every fact with a reference it obtains itself. It never uses the server's own opinion. |
| Relying party | Anyone reading `report.md`, `report.json` or the badge                                          | Sees, per server, whether it runs the public code and how strong the evidence is.                                                               |

The evidence format is Attestium's evidence format, version 2 (see the [Attestium specification](https://github.com/attestium/attestium.com/blob/main/SPEC.md)). An attester or verifier written in another language can interoperate by following it.


## One verification

```text
 verifier (CI)                                  server
 nonce = 32 random bytes
 ssh auditstatus@server "check <nonce>"  ---->  authorized_keys forces: auditstatus ssh
                                                  hash the deployed files, installed packages,
                                                  every running executable and library;
                                                  inspect every process of each service;
                                                  digest = SHA-256(canonical evidence)
                                                  TPM quote and confidential VM report
                                                    over (nonce, digest), when available
                                                  IMA log, read after the quote
 evidence (JSON)                        <----
 compare with references the verifier fetches:
   the public commit, a reproduced build, registry packages,
   container images by digest, official runtimes,
   the signed distribution archive, attested release manifests
 write report.json, report.md, badge.json
```

The attester never executes what it inspects. Binaries are hashed and scanned for build information, never run. The running executable is read through `/proc/<pid>/exe`, so a binary replaced on disk after the process started is still the one checked.

The attester reads files that other users control without letting them choose what it reads. It opens only regular files, so a FIFO or a device in their place is reported as an error instead of stalling collection. Sockets (a server's, such as Puma's `tmp/sockets/puma.sock` or PostgreSQL's in `/run/postgresql`) are left out: they cannot be opened, so nothing can be read or loaded from them. Symbolic links a process in a container controls resolve inside the container's root, never on the host. A path another user chose (a monitor log entry, Bundler's directory on `RUBYLIB`) is followed only through links owned by root, and a release manifest that is a symbolic link is not read. A walk enters each directory through its parent's open descriptor, so a directory replaced by a link during the walk is not followed.


## What is compared with what

Every file that an inspected process runs or maps executable must be explained by one of these references. A file that matches none is "unexplained" (a warning by default, `policy.unexplainedCode`); a file that contradicts its reference fails.

| On the server                                         | Compared with                                                                                                                              | Reference source                                                       |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| Deployed files of a git checkout                      | Every tracked file at the reported commit, which must be on the audited branch                                                             | A blobless clone of the public repository                              |
| Files the deploy generates and the repository ignores | A build of the same commit that the verifier runs itself (`build`)                                                                         | The verifier's own checkout                                            |
| A release deployed without git                        | Its `.attestium-manifest.json`, whose SHA-256 must carry a GitHub artifact attestation by the configured workflow, for the commit it names | GitHub's attestation API and Sigstore                                  |
| Installed packages                                    | The package each lockfile at the deployed commit pins, per ecosystem (see below)                                                           | The registries                                                         |
| Go and Rust binaries                                  | The dependencies built into them, against `go.sum` or `Cargo.lock` at the commit                                                           | The public repository                                                  |
| Node.js binaries                                      | The official release archive                                                                                                               | `nodejs.org/dist`                                                      |
| npm, corepack, pnpm, pm2 next to Node.js              | npm and corepack against the Node.js archive; the others against the registry                                                              | `nodejs.org/dist`, the npm registry                                    |
| Containers                                            | The image the container runs, fetched by digest; optionally its attestation                                                                | The container registry                                                 |
| System binaries and libraries                         | The file of the Debian or Ubuntu package that owns it                                                                                      | The distribution's signed archive (a snapshot for superseded versions) |
| Other programs                                        | A pinned SHA-256, or a project's published and signed checksum list (`executables`)                                                        | The project's release page                                             |
| The attester itself                                   | The release's `SHA256SUMS`                                                                                                                 | Audit Status releases                                                  |

### Installed packages per ecosystem

| Ecosystem | Installed in                                                                             | Lockfile at the commit                                                                                    | Reference                                                    |
| --------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| npm       | `node_modules`                                                                           | `pnpm-lock.yaml`, `npm-shrinkwrap.json`, `package-lock.json` (at the repository root, or `lockfiles.npm`) | The tarball whose integrity the lockfile names               |
| PyPI      | A virtual environment's `site-packages`                                                  | `uv.lock`, `pylock.toml`, `poetry.lock`, `Pipfile.lock`, `requirements.lock`, `requirements.txt`          | The wheel named by the lockfile's hash, through its `RECORD` |
| RubyGems  | `vendor/bundle/ruby/<version>`, `.bundle/ruby/<version>`                                 | `Gemfile.lock`, `gems.locked`                                                                             | The `.gem` whose checksum the lockfile pins                  |
| Hex       | `deps/`                                                                                  | `mix.lock`                                                                                                | The Hex tarball by its outer checksum                        |
| Composer  | `vendor/`                                                                                | `composer.lock`                                                                                           | The git tree of the pinned commit (with `export-ignore`)     |
| Maven     | `target/lib`, `target/dependency`, `lib/`, `libs/`, `build/install/*/lib`, `WEB-INF/lib` | `gradle/verification-metadata.xml`, `lockfile.json`                                                       | The jar hash the lockfile pins                               |
| NuGet     | .NET publish output                                                                      | `packages.lock.json`                                                                                      | The package whose content hash the lockfile pins             |

The [language pages](README.md#languages) describe each one in detail.


## Freshness

Each verification sends a new random nonce of 32 bytes. The attester includes it in the evidence and computes `evidenceDigest`, a SHA-256 over the canonical JSON of the evidence. The verifier accepts evidence only when:

* the nonce is the one it sent,
* `collectedAt` is no more than 60 seconds in the future and no older than `policy.maxEvidenceAgeSeconds` (900 by default),
* the digest it recomputes equals `evidenceDigest`.

The nonce is what makes evidence fresh; `collectedAt` is the server's clock, and the window only catches a clock that is wrong. A new nonce is drawn for every server and every attempt.

When the server has a TPM or runs in a confidential VM, the attester also binds the nonce and digest into a hardware-signed statement: a TPM quote over `SHA-256(nonce || digest)`, or a confidential VM report over `SHA-512(nonce || digest)`. Old evidence cannot be replayed, and hardware-signed evidence cannot be edited after it was signed. Only a TPM quote with a key pinned for that server shows which machine answered: without one, a server could relay the nonce to another server and return its evidence (see the [threat model](threat-model.md#with-root-software-evidence)).


## A forged answer

The attester runs on the server, so whoever controls the server's root account can replace it with a program that returns what the verifier expects: the verifier's nonce, the current time, the commit's file hashes instead of the deployed ones, and a digest computed over that forged document. The nonce, time and digest checks all pass. The digest is a hash, not a signature. No transport changes this: SSH proves which machine answered, not that its software tells the truth.

```text
 verifier (CI)                     server, root runs modified code
 nonce = 32 random bytes
 ssh auditstatus@server   ---->    forged attester:
   "check <nonce>"                   reports the commit's hashes,
                                     copies the nonce,
                                     collectedAt = now,
                                     digest = SHA-256(forged evidence)
 evidence                 <----

 software evidence only:
   nonce, time, digest and files match                  -> pass
 tpm.publicKey:
   quote over (nonce, digest) with the pinned key       -> same machine, now
 tpm.expectedPcrs:
   PCR 0-7 (8, 9) equal the pinned values               -> expected boot
 tpm.ima:
   the IMA log replays to the quoted PCR 10, and the
   kernel measured other contents than the evidence     -> fail
```

| Forgery                                                                         | What makes it fail                                                                                                                                             | Software evidence alone              |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| Replay an earlier answer                                                        | A new 32-byte nonce for every server and attempt                                                                                                               | Fails                                |
| Change the answer on the way, or answer in the server's place                   | SSH with the host keys pinned in `known_hosts`, and the digest                                                                                                 | Fails                                |
| Report the commit's hashes while modified project files run                     | `servers[].tpm.ima`, with an IMA policy that measures the files the service reads: the kernel measured the modified file, and its hash differs from the commit | Passes                               |
| Report genuine packages while a modified one runs                               | The same: files the kernel measured under the service's root are compared with the package's reference, not with the evidence                                  | Passes                               |
| Run a modified attester that reports the genuine one's hash                     | `servers[].tpm.ima`: the kernel measured the program that ran at the attester's path                                                                           | Passes                               |
| Leave out the quote, or claim there is no TPM                                   | `servers[].tpm.publicKey`: a server with a pinned key fails without a valid quote                                                                              | Passes                               |
| Switch IMA off, or boot with a policy that measures none of the service's files | `servers[].tpm.ima`: no verified log, or no measurement under the service's root, fails                                                                        | Passes                               |
| Quote with another key, or from another machine (a relay)                       | One attestation key pinned per server; the configuration refuses a key pinned twice                                                                            | Passes                               |
| Boot a modified kernel, boot loader or kernel command line                      | `servers[].tpm.expectedPcrs` (PCR 0 to 7; 8 and 9 for the command line and initramfs)                                                                          | Passes                               |
| Leave out the processes that run modified code                                  | `servers[].minProcesses` (1 by default), and IMA measurements of what ran                                                                                      | Fails below `servers[].minProcesses` |
| Run modified code, then restore the genuine file                                | The IMA log keeps every measurement since boot; earlier contents are reported                                                                                  | Passes                               |

So a result is only as strong as its evidence level, and the report and the badge always name it (`passing, software evidence`). With software evidence, a pass means the server's root reported the published code; it holds against mistakes, drift and attackers without root, not against the operator or anyone with root. What still passes with TPM and IMA (code the IMA policy does not measure, such as code run by a user its rules leave out or code evaluated from data; code run from outside the service's root by a process the evidence leaves out; and a compromised kernel or firmware), and the limits of confidential VMs, are in the [threat model](threat-model.md#with-root-tpm-and-ima) and [Hardware evidence](hardware.md#ima). [Forged answers](https://github.com/attestium/attestium.com/blob/main/docs/forged-answers.md) in Attestium explains each step in detail.

### Why SSH, and no HTTP endpoint

The verifier reaches each server only through SSH, as a dedicated user whose `authorized_keys` entry forces the attester command and allows nothing else (`restrict`, no shell, no forwarding). The server publishes nothing on the network for Audit Status:

* only the holder of the verifier's private key can ask for evidence; an HTTP endpoint answers anyone who can reach it, and shows them the server's files, packages and processes;
* the server is authenticated by its host key pinned in `known_hosts`, not by a certificate any public CA could issue, and no proxy or CDN in front of it can answer in its place;
* the nonce reaches the attester as the command's argument and is validated before anything is collected; there is no request parser, headers or routing to attack.

For Kubernetes, the attester (`auditstatus serve`) listens only on its pod's loopback interface, and the verifier reaches it with `kubectl port-forward`, through the API server, with credentials limited to `pods/portforward` in the attester's namespace. Nothing outside the pod can connect without those credentials. `kubectl exec` would also work, but its permission runs any command in the privileged attester pod; a port-forward can only ask for evidence. The port-forward passes through the API server's connection to the node's kubelet, which is authenticated only when the API server verifies the kubelet's certificate ([Kubernetes](kubernetes.md#who-can-answer-for-a-node)).

Neither transport makes software evidence trustworthy against root: they decide who may ask and who answered. What makes a forged answer fail is the hardware above.


## Evidence levels

Each server's result carries the level its evidence reached. The report shows it in the "Evidence" column.

| Level            | Shown as               | Backed by                                                                                               |
| ---------------- | ---------------------- | ------------------------------------------------------------------------------------------------------- |
| `software`       | software evidence      | The attester's own report, bound to the nonce by its digest                                             |
| `tpm`            | TPM                    | A TPM 2.0 quote over the nonce and digest, verified with an attestation key you pinned after enrollment |
| `tpm+ima`        | TPM + IMA              | The above, and the kernel's IMA log replayed to the quoted PCR 10                                       |
| `sev-snp`, `tdx` | AMD SEV-SNP, Intel TDX | A confidential VM report signed by the CPU vendor's key chain, binding the nonce and digest             |

Levels combine: a confidential VM with a pinned TPM key shows `TPM + IMA + AMD SEV-SNP`, for example.

### What each level proves

| Level        | Proves                                                                                                                                                                                                                                       | Does not prove                                                                                                                                                                                                                                     |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Software     | The server's attester answered this nonce with this evidence. It detects drift, unreviewed hot fixes, stale processes, tampered dependencies, and attacks that do not control root.                                                          | Anything against root on the server: root can run a modified attester or feed it false data.                                                                                                                                                       |
| TPM          | The evidence came, fresh, from the machine holding the enrolled TPM. With pinned PCR values (`expectedPcrs`), the machine booted the expected firmware and boot chain.                                                                       | That the evidence is true. Root on a machine with the expected boot state can still misreport files and processes, and the TPM signs what it is given.                                                                                             |
| TPM + IMA    | The above, and the kernel's record of every file it measured since boot, which root cannot edit without the replay failing. Files the kernel measured under the service's root must match the commit, the packages' references or the build. | Files outside the IMA policy (with the `tcb` policy, the scripts of an interpreted service), or a compromised kernel or firmware. Files measured outside the service's root are compared only for the executables and libraries the processes run. |
| SEV-SNP, TDX | The evidence came from a confidential VM whose launch measurement you pinned, and the host operator could not read or change its memory.                                                                                                     | Anything about root inside the guest: the report protects the guest from the host, not from itself.                                                                                                                                                |

See the [threat model](threat-model.md) for the full picture, and [Hardware evidence](hardware.md) to set up each level.


## Statuses

A server's status is the worst of its findings: `fail` if any finding fails, otherwise `error` (shown as inconclusive) if a check could not complete, otherwise `warn` if any finding warns, otherwise `pass`. A check that could not run never counts as passing. The overall status is the worst server's status. See [Reports](reports.md).
