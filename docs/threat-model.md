# Threat model

Audit Status answers one question: does this server run exactly the public code? This page describes who might try to make the answer look better than it is, what they can and cannot hide at each evidence level, whom you trust when you read a report, and the limits of the approach.


## What a passing report claims

A passing server, at the moment of the audit:

* runs a commit that is on the audited branch of the public repository (or a release a configured workflow built and attested from such a commit), with every tracked file unchanged and nothing added that the commit does not ignore;
* has installed packages that match its lockfiles, build output that matches a reproduced build, and container files that match their images;
* runs only executables and libraries that some reference explains (or that the policy accepts as warnings);
* has no known code-injection vector open in the inspected processes.

It does not claim that the public code is free of bugs or backdoors. It shows that what runs is what anyone can read.


## Attackers

### Without root

An attacker who controls the application's account (for example through a remote code execution bug) but not root:

| Action                                                                                                              | Detected                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Edit, add or delete deployed files                                                                                  | Yes: files differ from the commit, or are untracked.                                                                                                                                                                                                                                                                                                                                                                                               |
| Edit files and restore them before the audit                                                                        | Yes, while the process runs: a file of the service, of its installed packages or of PM2 whose status changed after the process started fails, even if its contents and modification time were restored (`policy.modifiedAfterStart`, `policy.metadataChangedAfterStart`). Linux sets the status-change time on every change, and only root can set the clock back. A restore within 50 ms of the start cannot be told from a write just before it. |
| Add a file that is loaded in place of another, then remove it                                                       | Yes, while the process runs: its directory changed after the process started (`policy.metadataChangedAfterStart`). For example `lib/foo.js`, which `require('./lib/foo')` finds before `lib/foo/index.js`, or `node_modules/foo.js` before a package `foo` without `exports`.                                                                                                                                                                      |
| Load a library or module through an environment variable or option                                                  | Yes, for the injection vectors of each runtime (`LD_PRELOAD`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, and others), once the process restarts with it.                                                                                                                                                                                                                                                                                                 |
| Change code in memory, or run code from `memfd` or anonymous writable and executable memory                         | Yes: executable pages are compared with their files, and such mappings are reported. The JIT memory files of the .NET runtime (`doublemapper`) and the BEAM (`vmem`) are recognized by name, in those runtimes only, and reported as context; code in them is not compared.                                                                                                                                                                        |
| Attach a debugger or open an inspector port                                                                         | While attached or listening. Between two audits, the application's user can attach a debugger where `kernel.yama.ptrace_scope` is 0 (Ubuntu's default, 1, allows only a parent), or open the inspector of Node.js 18 or 20 with `SIGUSR1`, change memory, and detach. Node.js 22.14 and later refuse the signal with `--disable-sigusr1`.                                                                                                          |
| Run another program                                                                                                 | Listed as another program of the same user; with the [monitor](monitor.md), recorded and checked, even if deleted afterwards.                                                                                                                                                                                                                                                                                                                      |
| Evaluate code held only in memory inside an interpreter (for example JavaScript `eval` of data fetched at run time) | No. Such code is not a file and runs inside a verified interpreter.                                                                                                                                                                                                                                                                                                                                                                                |
| Change the attester, its configuration, or the monitor log                                                          | No: they are owned by root.                                                                                                                                                                                                                                                                                                                                                                                                                        |

### With root, software evidence

Root can run a modified attester, feed the real one false data, or edit the evidence before it leaves. The attester's own hash is self-reported. Software evidence does not hold against root ([A forged answer](how-it-works.md#a-forged-answer) shows how, and which settings make it fail). It still detects mistakes, unreviewed hot fixes, stale processes, tampered dependencies, and attackers who do not control root.

Software evidence also names no machine. Root on one server can forward the verifier's nonce to another, honest server running the same code and return that server's evidence (a relay): it answers the nonce and passes. The host name and addresses in the evidence are reported by the attester, not checked. Only a pinned TPM key ties evidence to a machine.

### With root, TPM

With a pinned attestation key, root cannot forge a quote, replay an old one, or answer from another machine: the quote covers this nonce and this evidence digest, and only the enrolled TPM can sign it. Evidence relayed from another server carries that server's quote, which the pinned key does not verify. This holds only while each server pins its own key; the configuration refuses one key pinned for two servers. With pinned PCR values, the machine also booted the expected firmware and boot loader.

Root can still misreport files and processes: the TPM signs whatever evidence it is given, and PCRs 0 to 7 say nothing about what happened after boot.

### With root, TPM and IMA

The kernel measures every file it executes or maps executable (under the IMA policy) and extends PCR 10. Root cannot remove an entry without the replay failing. A modified program that ran since boot is in the log.

Root can still:

* run a modified program and then put the genuine file back at the same path: the log holds both, and for executables and libraries outside the project the verifier requires only that the reported hash was measured there, and warns when it was not the last one;
* load code after the attester listed the processes and before the quote, at a path the evidence does not list (the log records it, but only project files and the listed executables and libraries are compared);
* run code the IMA policy does not measure: files outside the policy's rules (with the `tcb` policy, every script a Node.js, Python, Ruby or PHP service reads as its own user; with a `uid=` rule, code run by another user), or code evaluated in an interpreter. The verifier reports a service under whose root the kernel measured nothing, and fails it when `servers[].tpm.ima` is set, but it cannot see the policy itself ([Hardware evidence](hardware.md#enable-ima) shows a policy for interpreted services and how to bind it to the boot measurements);
* compromise the kernel or firmware, which produce the measurements;
* rely on what Audit Status does not compare with the kernel's record: the verifier checks every file the kernel measured under each service's root (tracked files against the commit, package files and build output against their references) and the hashes reported for the processes' executables and libraries against what the kernel measured at those paths; the attester's own executable is compared with what the kernel measured at its path; files the kernel measured elsewhere that the evidence does not list (code run from outside the service's root by a process the evidence leaves out, a program started and stopped between audits, which the [monitor](monitor.md) records) are not compared, because the IMA log does not say which user or process read them.

### Confidential VMs

In an AMD SEV-SNP or Intel TDX guest, the host operator (a cloud provider, or whoever controls the hypervisor) cannot read or change the guest's memory or forge its report, and the pinned launch measurement shows which firmware and boot image started. Inside the guest, root can do as much as on any server: the report protects the guest from the host, not from itself. Measurements taken after launch (TDX runtime measurement registers) are not checked.

The launch measurement identifies an image, not an instance: root in one guest can relay the nonce to another guest started from the same image and return its report. Pin a TPM key per server to tie evidence to a machine.

### In Kubernetes

The verifier reaches a node's attester through a pod of the attester DaemonSet. It uses a pod only when the DaemonSet, by its UID, controls it, it is the only one on the node, and it runs the DaemonSet's pod template with no debugging containers: a pod that someone else created with the attester's labels cannot answer. Whoever can create pods in the attester's namespace, run commands in them, or change the DaemonSet or its configuration can still make a node's evidence say anything, as root can on a server. The port-forward also passes through the API server's connection to the node's kubelet, which many clusters do not authenticate (`--kubelet-certificate-authority` unset); someone on that network can then answer in the node's place, where SSH would have failed on the pinned host key. A TPM key pinned for each node makes such an answer fail (see [Kubernetes](kubernetes.md#who-can-answer-for-a-node)).

### Maintainers of the audited repository

The public repository defines what passes. Its maintainers can make code that is not in it run and still pass, and the report cannot show it:

* a build step or install script that downloads code (a script, a binary, a package without a lockfile hash): the verifier's own build downloads the same thing and matches it, unless the server is served different content;
* a lockfile that pins a package they publish: the package is compared with its registry tarball, whose code is not in the repository;
* a release workflow (an attested release manifest, or the signer of an image) that adds code while building: the attestation proves which workflow built it, not what the workflow downloaded;
* code the application loads at run time from a network or a database, which is data to the verifier.

Each of these is visible in the repository as the step or URL that fetches, not as the code that runs. Review build scripts, workflows and lockfile changes as code. Installed files that no lockfile explains are reported (`policy.builtPackages`, `policy.unexplainedCode`), as warnings by default; set them to `fail` where builds should not produce code of their own.

A deployed commit that later disappears from the branch (history rewritten by a force push) fails the next audit ("not on the public branch"). Earlier reports record the commit. Protect the audited branch against force pushes, so that what passed stays reviewable.

### Anyone who can push to the report branch

The report, `report.md` and the badge are files on a branch: anyone who can push there can replace them with a passing report, or put back an earlier passing one. With `attest-report`, the action signs them with the workflow's identity; `auditstatus verify-report` checks the signature, that it covers the files, the run the report names, and its age (see [Checking a published report](verifier.md#checking-a-published-report)). The badge image alone is not signed: a reader who relies on it should check the report it comes from.


## Whom you trust

| Party                                                                     | Trusted for                                      | If it is compromised                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The verifier (the CI runner, and the Audit Status code the workflow pins) | Comparing honestly, and publishing what it found | It can publish any result. Anyone can review the configuration, the pinned Audit Status version and the workflow runs. To let a third party verify independently, give it its own forced-command key; the evidence is collected fresh for each verifier. |
| The repository with the verifier configuration                            | Which servers, keys and references are used      | It can point the verifier at an impostor or pin the wrong keys. Review changes to it like code.                                                                                                                                                          |
| The audited repository and its branch                                     | Defining the public code                         | Anyone who can push to the audited branch can deploy code that passes. The code is public, so the change is visible.                                                                                                                                     |
| The attester's Kubernetes namespace and its DaemonSet                     | Running the attester on each node                | Whoever can create or change pods there, or change the DaemonSet, can answer for any node. Keep only the attester there.                                                                                                                                 |
| The report branch                                                         | Holding the published report                     | Anyone who can push there can replace the report; the attestation (`attest-report`) shows which run wrote it.                                                                                                                                            |
| Registries                                                                | Serving packages                                 | Packages are compared with the hashes the lockfile pins, so a registry cannot substitute content. Packages the lockfile does not pin by hash (`policy.unpinnedPackages`) trust the registry.                                                             |
| Container registries                                                      | Serving images                                   | Images are fetched by digest, so a registry cannot substitute content.                                                                                                                                                                                   |
| nodejs.org                                                                | Official Node.js releases                        | Checked by SHA-256 from the release's checksum list over HTTPS, and with `references.nodeKeyring`, by its signature.                                                                                                                                     |
| Debian and Ubuntu archives                                                | System binaries and libraries                    | The archive's `Release` file is checked with the keyring on the verifier.                                                                                                                                                                                |
| Sigstore and GitHub                                                       | Artifact attestations and npm provenance         | A forged attestation would let an unreviewed build pass.                                                                                                                                                                                                 |
| TPM manufacturers, AMD, Intel                                             | Hardware keys                                    | A leaked vendor key defeats hardware evidence for that hardware.                                                                                                                                                                                         |
| Audit Status releases                                                     | The attester binary and its `SHA256SUMS`         | Each release carries build provenance; verify it with `gh attestation verify`.                                                                                                                                                                           |

The verifier's build step runs the audited repository's own build scripts, and the install scripts of the packages its lockfiles pin. It runs only for commits on the audited branch, and its environment leaves out the SSH key and tokens. With `build.user` (the GitHub action's default on Linux), it runs as an unprivileged account of its own, in a checkout outside the cache, with no supplementary groups and no new privileges; every process of the account is killed after the build, and the verifier hashes the outputs and writes the cached result itself. The account cannot read the environment of the verifier's processes (`/proc/<pid>/environ`), the temporary SSH key file, or other files of the verifier's user, cannot write the cache (`references.cacheDir`), which later runs reuse, and leaves no process behind. It is not a full sandbox: the build can read what any user of the machine can and reach the network, and it relies on the kernel's user separation and `fs.protected_hardlinks`. Without an account, a process of the same user can read the secrets and change the cache: configure `build` only for repositories whose build scripts and dependencies you trust as much as the verifier's secrets.

### The public registry

With the [public registry](registry.md), Audit Status's own workflow is the verifier, and the table above applies to it: you trust its maintainers and GitHub to run the registry's workflows as published. In return:

* **The key is no one's.** A workflow generated each key on a GitHub-hosted runner and stored the private key as a secret of the `verifier` environment, which admits the `main` branch only. Nobody saw it, an attestation names the workflow that generated each public key, and only the registry's jobs on `main` receive it ([verifier/README.md](../verifier/README.md)). A maintainer who changed a workflow to read the key would do it in a public commit.
* **No project code runs where the key is.** The audit jobs collect and appraise with builds from the cache only. Builds run in jobs without the key, as an unprivileged account that cannot write the cache, so one project's build cannot change another project's result, read the key, or alter its own cached result.
* **A registry file cannot change what its result means.** It may not set references, keyrings, tokens, other transports or build variables from the runner, its servers must be public hosts with pinned host keys, and its policy can lower a check to a warning, never below. Each file and each change is reviewed in a public pull request.
* **The results are signed.** The publish job, which holds no key, signs every file it writes with a GitHub artifact attestation; `auditstatus verify-report` checks one against the registry's workflow.

A project's own maintainers keep the power the section on them describes: their repository, lockfiles and build scripts define what passes.


## What the verifier's key can do

The verifier's SSH key can only run the three attester operations: `check`, `enroll` and `activate`. Whoever holds it can collect evidence, which includes paths, hashes of every file under each service's root (including ignored files such as `.env`), process lists and the first 32 arguments of each command line. The published report leaves out command lines and the hashes of ignored files, but treat the key as a secret. In Kubernetes, the verifier's token can only list the attester pods and port-forward to them.


## What leaves the server, and what is published

* **Environment variables** of the service's processes are read on the server, to look for code-loading settings (`NODE_OPTIONS`, `LD_PRELOAD` and the like). Their values do not leave the server, except the part of a code-loading setting that a finding is about, such as the path a `--require` loads.
* **Command lines** of the service's processes (at most 32 arguments of 512 characters) are in the evidence the verifier receives over SSH. The verifier keeps them in memory, and writes no evidence to disk, logs, artifacts or reports. Do not pass secrets as arguments: every local user can read them with `ps` anyway.
* **File contents** never leave the server, only their SHA-256 hashes and paths. The release manifest (`.attestium-manifest.json`) is the one file sent whole.
* **The report** (`report.json`, `report.md`, `badge.json`, the job summary, the issue) holds statuses, counts, paths, hashes, versions and the findings' details. It holds no environment values, no command lines and no credentials.
* **The verifier's credentials** (`AUDITSTATUS_SSH_KEY`, `GITHUB_TOKEN`, `GH_TOKEN`, the variables named by `references.githubTokenEnv` and `containerRegistries.*.tokenEnv`, and GitHub's runtime and OIDC tokens) are read once and removed from the environment that programs the verifier starts inherit (ssh, git, kubectl, builds). The SSH key reaches ssh as a 0600 file in a private temporary directory, removed when the connection ends. Builds get only the variables listed in `build.passEnv` and `build.env`, and with `build.user`, run as an account that can read neither the verifier's memory and environment nor its files.
* **On GitHub Actions**, secrets are passed to steps through `env`, never written into a script, and GitHub masks their values in logs. The checkout keeps no credentials (`persist-credentials: false`), the cache holds only public data (repository mirrors, registry packages, hashes), and the publish job, which has write access, never holds the SSH key.


## Limits

* An audit sees one moment. Between audits, code can run and disappear; the [monitor](monitor.md) (software evidence) and IMA (hardware evidence) record what ran.
* Files ignored by the commit are listed, not compared, unless a build produces them or `policy.codePaths` marks them as code. Configuration and data files can change behavior.
* Code outside files (evaluated strings, JIT output, data interpreted as code) is not verified.
* Volumes mounted into containers are not compared with the image.
* Kernel and firmware are trusted at every level.
* An attacker can block the verifier's connection. The result is then inconclusive, never passing.
* Freshness comes from the nonce, not from clocks. The server's `collectedAt` must be at most 60 seconds ahead of the verifier's clock and at most `policy.maxEvidenceAgeSeconds` behind it; the window only catches a wrong clock (a server whose clock is off by more fails), since evidence that answers this run's nonce cannot be older than the run. A report's own age is its signature's time in the transparency log (`auditstatus verify-report --max-age`), not `generatedAt`.
