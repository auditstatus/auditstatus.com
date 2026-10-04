<!--
title: Runtime integrity monitoring for Linux servers
description: Detect injected libraries, debuggers, modified binaries and programs that ran between audits, with process checks, an eBPF monitor and IMA.
label: Runtime integrity monitoring
keywords: runtime integrity monitoring, process injection detection, LD_PRELOAD, eBPF monitor, IMA, file integrity, Linux servers
-->

# Runtime integrity monitoring for Linux servers

File integrity checks compare files on disk. Code runs in processes. Audit Status inspects every process of each service, explains every executable and library they map, and with its monitor also checks what ran between two audits.


## Process checks

For every process of a service, the attester reports facts and the verifier decides:

* **Executable memory.** The process's executable pages are compared byte for byte with the files they map, so code patched in memory is found.
* **Injection vectors.** Environment variables and flags that load code before the application: `LD_PRELOAD`, `NODE_OPTIONS` with `--require` or `--import`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`, `RUBYOPT` and the equivalents of each runtime.
* **Debuggers and inspectors.** An attached tracer, and open inspector or debug ports.
* **Code without a file.** `memfd` objects mapped executable.
* **The running binary.** Read through `/proc/<pid>/exe`, so a binary replaced on disk after the process started is still the one checked.

Runtimes recognized: Node.js, Python, the JVM, Ruby, .NET, BEAM, PHP, Perl, Deno and Bun.


## Every running file is explained

Every executable and library an inspected process runs or maps is compared with a reference: the service's commit, a verified package, the official Node.js release, a container image, the owning Debian or Ubuntu package in the signed archive, or a pinned hash or signed checksum list. A file that differs from its reference fails; a file no reference explains is reported. See [How it works](/docs/how-it-works/#what-is-compared-with-what).


## Between audits: the monitor

An audit sees one moment. Code that ran and was removed before the audit leaves no file to find. `auditstatus monitor` records, with eBPF through `bpftrace`, every program started and every file mapped executable, and each audit checks the window before it:

| Finding                                                                        | Default |
| ------------------------------------------------------------------------------ | ------- |
| Programs or libraries loaded since the last audit differ from their references | fail    |
| Programs or libraries loaded since the last audit are no longer on disk        | fail    |
| Programs or libraries loaded since the last audit that no reference explains   | fail    |

The monitor's log is written by root on the server, so it is software evidence. See [Monitor](/docs/monitor/).


## Hardware-backed records: IMA

With IMA, the kernel hashes files as they are loaded and extends TPM PCR 10 before they run. The verifier replays the log to the quoted PCR, so the record holds even against root: files the kernel measured cannot be removed from it. See [Hardware evidence](/docs/hardware/#ima).


## Limits

* Code outside files (evaluated strings, output of just-in-time compilers, data interpreted as code) is not verified.
* Kernel and firmware are trusted at every level.
* An attacker who blocks the verifier makes the result inconclusive, never passing.


## Next

* [Threat model](/docs/threat-model/): what each evidence level holds against.
* [Reports](/docs/reports/): every process and code finding, and what to do about it.
