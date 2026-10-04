# Hardware evidence

Software evidence can be defeated by an attacker with root on the server. Hardware evidence binds each report to a key the server's software cannot extract: a TPM 2.0 quote, the kernel's IMA log replayed to the TPM, or a confidential VM report signed by the CPU vendor. This page covers TPM enrollment and pinning, IMA setup, and confidential VMs (AMD SEV-SNP and Intel TDX). See the [threat model](threat-model.md) for what each level proves.


## TPM

With a TPM, the attester adds a quote whose qualifying data is `SHA-256(nonce || evidenceDigest)`, signed by an attestation key (AK) that cannot leave the TPM. The verifier checks the quote with a public key you pinned after enrolling the server.

### Prepare the server

1. Install `tpm2-tools`.
2. Give the attester's account access to `/dev/tpmrm0`, usually by adding it to the `tss` group (`auditstatus_tpm: true` in the [Ansible role](attester.md#the-ansible-role)).
3. Keep `tpm.enabled: auto` (quote when a TPM is present), or set `true` to report a missing TPM as a failure.
4. Run `auditstatus doctor`. It reports "TPM available but no attestation key yet" until enrollment creates the key.

Attester settings: `tpm.tcti`, `tpm.handle` (`0x81010002`), `tpm.bank` (`sha256`), `tpm.pcrs` (0 to 7, plus 10 with IMA), `tpm.ekAlgorithm` (`rsa`). See [Configuration](configuration.md#tpm).

### Enroll

Enrollment proves that the AK is a restricted signing key inside a genuine TPM, then gives you its public key to pin. Run it on the verifier:

```sh
AUDITSTATUS_SSH_KEY="$(cat auditstatus_key)" auditstatus tpm-verify --server web1
```

It asks the server for its enrollment over the same transport as a verification (the `enroll` operation). The server returns the AK, creating it at `tpm.handle` if there is none, and the endorsement key (EK) with its manufacturer certificate. Then the verifier:

1. checks that the AK's attributes make it a restricted signing key that cannot leave the TPM (`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`), and that its public key matches its public area;
2. checks that the EK certificate is for the TPM's EK and chains to a certificate in `references.tpmRoots`;
3. encrypts a random secret to the EK, bound to the AK's name (MakeCredential), and asks the server to decrypt it (the `activate` operation). Only the TPM holding both keys can.

On success it prints what to add to the server's entry in the verifier configuration:

```text
# The attestation key of web1 is in the TPM whose EK certificate chains to <CA subject>.
# Add to servers[name=web1] in auditstatus.config.yml:
tpm:
  publicKey: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
  ekCertificate: MIIE...
```

From then on, every verification of that server requires a valid quote from that key; without one it fails.

Each server pins its own key. The quote is what ties the evidence to a machine: a compromised server that forwards the verifier's nonce to another server and returns that server's answer (a relay) fails, because the quote is signed by the other server's key. Two servers pinning the same key could answer for each other, so the configuration refuses it ("tpm.publicKey is also pinned for server ..."): list the services of one machine on one server entry.

### Manufacturer CAs

List the TPM manufacturers' CA certificates (PEM, several per file allowed) in the verifier configuration:

```yaml
references:
  tpmRoots:
    - tpm-cas/infineon.pem
    - tpm-cas/nuvoton.pem
```

Every certificate in these files is trusted as an anchor, so include the CA that issued your TPMs' EK certificates, which is often an intermediate. Without any, enrolling a TPM that has an EK certificate fails with "No TPM manufacturer CAs are configured (references.tpmRoots) to check the EK certificate". `auditstatus doctor --role verifier` checks that each file exists.

### Virtual TPMs

Virtual TPMs (cloud vTPMs, swtpm) often have no EK certificate. Enrollment then fails with "The TPM has no EK certificate; pass --allow-uncertified to enroll it anyway (virtual TPMs)". With `--allow-uncertified`, the AK is still bound to the EK by the credential check, but nothing shows the TPM is genuine, and the command prints a warning. A virtual TPM is only as trustworthy as the hypervisor that runs it.

On the server itself, `auditstatus tpm-enroll` prints the same enrollment as JSON, for inspection. It does not check anything; pin the key that `tpm-verify` prints.

For a project in the [public registry](registry.md#tpm-keys), `auditstatus registry tpm-verify` enrolls the registry file's servers the same way and pins each key in the file.

### Pin the boot state

A quote with a pinned key proves freshness and which machine answered. To also prove the machine booted the expected firmware and boot chain, pin PCR values:

```yaml
servers:
  - name: web1
    host: web1.example.com
    tpm:
      publicKey: |
        -----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----
      expectedPcrs:
        sha256:
          '0': <64 hex characters>
          '7': <64 hex characters>
```

Read the values on the server in a known-good state (`tpm2_pcrread sha256:0,1,2,3,4,5,6,7`), or take them from the `tpm.quote` of `auditstatus collect`. The pinned indexes must be among the quoted ones (`tpm.pcrs`). PCR values change with firmware, boot loader and kernel updates; update them when you update those. `auditstatus doctor --role verifier` warns about a pinned key without expected PCR values: "quotes prove freshness, not boot state".


## IMA

The Linux Integrity Measurement Architecture (IMA) makes the kernel hash files as they are executed, mapped executable or read (as its policy says), append each measurement to a log, and extend it into TPM PCR 10. Entries cannot be removed from the PCR, so a log that replays to the quoted PCR 10 is the kernel's own record, even against root.

IMA is what keeps root on the server from answering with forged evidence: the attester's report is root's word, the kernel's measurements are not (see [A forged answer](how-it-works.md#a-forged-answer)). It covers only what the policy measures.

### Enable IMA

Boot with an IMA policy that measures executed and memory-mapped files, SHA-256 hashes, and the `ima-ng` template, for example with these kernel parameters:

```text
ima_policy=tcb ima_hash=sha256 ima_template=ima-ng
```

The `tcb` policy measures programs executed, files mapped executable, and files read by root. That covers a compiled service, but not the code of a Node.js, Python, Ruby or PHP service whose processes run as another user: its scripts are read, not executed, and are never measured. The verifier then reports that the kernel measured no file under the service's root, and fails when `servers[].tpm.ima` is set.

For such a service, load a custom policy (`/etc/ima/ima-policy`, read at boot by systemd) that also measures every file the service's user reads. With the service running as the user with id 1001:

```text
dont_measure fsmagic=0x9fa0
dont_measure fsmagic=0x62656572
dont_measure fsmagic=0x64626720
dont_measure fsmagic=0x1cd1
dont_measure fsmagic=0x42494e4d
dont_measure fsmagic=0x73636673
dont_measure fsmagic=0xf97cff8c
dont_measure fsmagic=0x6e736673
dont_measure fsmagic=0x27e0eb
dont_measure fsmagic=0x63677270
dont_measure fsmagic=0xde5e81e4
measure func=BPRM_CHECK
measure func=FILE_MMAP mask=MAY_EXEC
measure func=FILE_CHECK mask=^MAY_READ uid=1001
measure func=FILE_CHECK mask=^MAY_READ euid=0
```

The first lines leave out pseudo filesystems (proc, sysfs, debugfs, devpts, binfmt, securityfs, selinuxfs, nsfs, cgroup, cgroup2, efivarfs). Measure by the reading user (`uid=`), not by the file's owner (`fowner=`): root can give a modified file another owner, but the service's processes still read it as their user. Leave temporary filesystems measured: code put in `/tmp` or `/dev/shm` must be measured too. Each distinct file is measured once until it changes, so the log grows with the files read, not with each read; data files the service rewrites and reads again are measured again each time. Keep such files outside the service's root, or accept the "no reference explains" warning for them. With `mask=MAY_READ` in place of `mask=^MAY_READ`, the kernel measures only files opened read-only, as Node.js, Python and other interpreters open their code: databases, caches and browser profiles that the service opens read-write stay out of the log.

The verifier cannot see which policy the kernel uses; it sees only what was measured. Two consequences:

* **A process of another user is not measured by a `uid=` rule.** Root could run modified code as another user and leave it out of the evidence. Add a rule for every user that runs code on the server, or measure all reads (`measure func=FILE_CHECK mask=^MAY_READ`, with `dont_measure` rules for data directories), at the cost of a larger log.
* **Root can reboot with a weaker policy.** Nothing measured under the service's root is reported, as above, but a policy that still measures the service's files and leaves out something else is not. Bind the policy to the boot measurements: load it from the initramfs (for example with dracut's `integrity` module) and quote and pin PCR 9, where GRUB measures the initramfs, and PCR 8, where it measures the kernel command line (`ima_policy=`, `ima_hash=`). Set `tpm.pcrs` in the attester configuration to include 8, 9 and 10, and pin 8 and 9 in `servers[].tpm.expectedPcrs`.

Then, in the attester configuration:

```yaml
ima:
  enabled: true
```

`tpm.pcrs` then includes 10 by default; if you set `tpm.pcrs` yourself, include 10, and keep `tpm.bank: sha256`. The attester reads `/sys/kernel/security/ima/binary_runtime_measurements`, which needs root or `CAP_DAC_READ_SEARCH`. `auditstatus doctor` checks that it is readable.

### How the log is verified

The attester reads the log after the quote, so the log holds every entry the quote covers. The verifier replays the log in the SHA-256 bank from the start and looks for the prefix whose replay equals the quoted PCR 10; entries added after the quote are ignored. IMA counts only when:

* a pinned TPM key verified the quote, and
* the quote selected PCR 10 in the SHA-256 bank ("IMA log provided but PCR 10 was not quoted in the SHA-256 bank" otherwise).

A log that does not replay fails: "IMA log does not replay to the quoted PCR 10 (edited or truncated log)".

With a verified log, the level becomes `TPM + IMA`. Every tracked project file the kernel measured is compared with the commit (or the attested release); every other file it measured under the service's root must be a file of a verified package or build output, with the contents of the reference (not the hash the attester reports); and the hash the attester reports for each executable and library of the inspected processes must be one the kernel measured at that path since boot, and should be the last one it measured there (paths the IMA policy does not measure are not compared):

| Finding                                                                                                                                                                                                       | Severity                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| The kernel measured project files whose contents differ from the public commit                                                                                                                                | fail                                                                   |
| Since boot, the kernel measured contents of these project files that no commit of the branch has: code loaded, then restored                                                                                  | fail                                                                   |
| Since boot, the kernel measured contents of these project files that no commit of the branch has, while they were open for writing (a deploy writing a file as it was read, or code loaded and then restored) | warn                                                                   |
| Since boot, the kernel also measured these project files as other commits of the branch have them (earlier deploys)                                                                                           | info                                                                   |
| Since boot, the kernel also measured other contents for these project files (a previous deploy, or code loaded and then restored)                                                                             | warn: an attested release, or a repository the verifier could not read |
| The kernel measured other contents than the evidence reports for executables or libraries the processes run                                                                                                   | fail                                                                   |
| The kernel last measured other contents than the evidence reports at these paths (a file replaced after the reported one ran)                                                                                 | warn                                                                   |
| The kernel measured other contents at the attester's path than the attester reports for itself                                                                                                                | fail                                                                   |
| The kernel measured files under the service's root whose contents differ from the package or build output the evidence reports                                                                                | fail                                                                   |
| Since boot, the kernel also measured other contents for these package or build files (an earlier install, or code loaded and then restored)                                                                   | warn                                                                   |
| The kernel measured files under the service's root that no reference explains (not tracked, not a verified package, not build output)                                                                         | `policy.unexplainedCode` (warn)                                        |
| The kernel measured no file under the service's root: the IMA policy does not measure the files its processes read, so IMA does not cover the service's code                                                  | warn, or fail with `servers[].tpm.ima`                                 |

Other contents the kernel measured for a project file since boot are compared with every version of that file in the first-parent history of the branch and of the deployed commit, later commits included (a deploy rolled back): contents another commit has are an earlier deploy, and contents no commit has are code that ran and was then restored, which fails however the file looks now. A file the kernel read while a process had it open for writing (it logs that) may have been hashed half written, as when a deploy writes a file just as an old process loads it, so there contents no commit has are a warning. An attested release has no such history, so there all of these are a warning. Each clears at the next boot, when the log starts again. The warning about the last contents measured at a path means root may have swapped a modified file in after the genuine one ran and reported the genuine hash, or a process still maps a file replaced since it started (restart it). Earlier contents are reported for project files only: every upgrade leaves earlier contents at the paths of system executables and libraries, so a modified one that ran and was then replaced by the genuine file at the same path, with the process restarted, is not reported there.

Two settings in the verifier configuration keep root on the server from sidestepping this:

* `services[].root` pins where the service is deployed. The measurements are compared under the root the evidence names; without a pinned root, root on the server could name another directory, so the verifier warns ("Project files the kernel measured are compared under the root the server reports …").
* `servers[].tpm.ima: true` makes IMA mandatory. Otherwise root can switch IMA off in the attester's configuration and the evidence is `TPM` only, which still passes.


## Confidential VMs

In an AMD SEV-SNP or Intel TDX guest, the CPU measures the VM's initial memory at launch and signs a report binding 64 bytes the guest chooses. The host operator cannot read or change the guest's memory or forge the report. The attester binds `SHA-512(nonce || evidenceDigest)` into it.

### Prepare the guest

* A kernel with `CONFIG_TSM_REPORTS` (Linux 6.7 or later) and configfs mounted at `/sys/kernel/config`, so `/sys/kernel/config/tsm/report` exists.
* `confidential.enabled: auto` (the default) adds a report when configfs-tsm is available; `true` reports its absence as a failure.
* By default the attester creates a report entry for each request, which needs root. With capabilities instead of root, create an entry at boot as root (`mkdir /sys/kernel/config/tsm/report/auditstatus`), let the attester's account write its `inblob`, and set `confidential.entry` to that directory.

`auditstatus doctor` reports "This is a confidential VM (configfs-tsm is available)" when it finds configfs-tsm. Run without root, it also checks that `confidential.entry` is set, that the entry exists, and that its `inblob` belongs to the attester's user; when not, it prints the commands to create it (`mkdir /sys/kernel/config/tsm/report/auditstatus && chown <uid> /sys/kernel/config/tsm/report/auditstatus/inblob`), a failure with `confidential.enabled: true` and a warning with `auto`. configfs entries do not survive a reboot, so create it at every boot (a systemd unit or a boot script).

### How the report is verified

* **AMD SEV-SNP**: the report's signature is checked up to AMD's root key (ARK), which ships with Audit Status. The chip's certificate (VCEK, or a VLEK) comes from the host with the report or, when the host does not provide it, from AMD's key distribution service (`references.amdKdsUrl`). Its TCB values must match the report's.
* **Intel TDX**: the quote is signed by the quoting enclave's attestation key, which the quoting enclave's report binds; that report is signed by the platform's PCK, whose certificate chain in the quote leads to Intel's SGX root CA, which ships with Audit Status. The platform's TCB level is reported, not evaluated.

The report must bind this nonce and evidence, and debugging must be off.

### Pin the launch measurement

```yaml
servers:
  - name: api1
    host: api1.example.com
    confidential:
      type: sev-snp
      measurements:
        - <96 hex characters>
```

| Setting                 | Meaning                                                                            |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `required`              | `true` by default once `confidential` is set: a server that sends no report fails. |
| `type`                  | `sev-snp` or `tdx`.                                                                |
| `measurements`          | Accepted launch measurements (SEV-SNP `MEASUREMENT`, TDX `MRTD`).                  |
| `mrConfigId`, `mrOwner` | TDX only: the expected MRCONFIGID and MROWNER.                                     |

Compute the expected measurement from the firmware, kernel, initrd and command line you boot (for example with AMD's `sev-snp-measure`, or your cloud provider's published values). Without pinned measurements, a verified report warns and shows the measurement it saw: "The report verified, but no launch measurement is pinned (this one is ...)". A report from a VM whose measurement is not in the list fails: "The confidential VM is not the expected one".

A verified report adds `AMD SEV-SNP` or `Intel TDX` to the evidence level. When the report fails to verify because of a network error or rate limit (for example fetching the VCEK), the result is inconclusive rather than failing.

A confidential VM report without a `confidential` section in the verifier configuration is noted but not used: "add them to use it".
