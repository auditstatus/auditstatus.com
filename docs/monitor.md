# Monitor

An audit sees the server at one moment. Code that ran and was removed before the audit leaves no file to find. The monitor records, with eBPF through `bpftrace`, every program started and every file mapped executable, so each audit also checks what ran in the window before it. This page covers what the monitor records, the service that runs it, and how the verifier explains each entry.


## What it records

`auditstatus monitor` runs a `bpftrace` program with two probes:

| Event  | Probe                                        | Recorded                                                                        |
| ------ | -------------------------------------------- | ------------------------------------------------------------------------------- |
| `exec` | `tracepoint:sched:sched_process_exec`        | Every program started: pid, uid, and the program's path.                        |
| `mmap` | `fentry:security_mmap_file` with `PROT_EXEC` | Every file mapped executable (shared libraries, and code loaded any other way). |

The `mmap` probe needs a kernel with BTF and function tracing. When `bpftrace` refuses it, the monitor restarts with `exec` events only.

Each event is one line in the log: the time in milliseconds, the event, pid, uid and path. A path may hold any byte but NUL: in the log a line break is written `\n` and a backslash `\\`. `bpftrace` prints each event with a random token before and after the path; the token is new for each run and kept in a file only root can read, so a program named to look like more events cannot add any or end its own early. `bpftrace` keeps at most 199 bytes of a path (`BPFTRACE_MAX_STRLEN` is set to 200): for a longer program path the monitor reads the path of the running program instead, and a path it still has only the start of is marked, reported with an error, and not hashed, since it may name another file. The log is `monitor.log` in `/var/log/auditstatus/` by default; at 64 MiB it is renamed to `monitor.log.1` and a new one is started.


## The service

`packaging/systemd/auditstatus-monitor.service` runs the monitor as root (`bpftrace` needs `CAP_BPF`, `CAP_PERFMON`, or `CAP_SYS_ADMIN` on older kernels), restarts it when it stops, and confines it: `ProtectSystem=strict` with only `/var/log/auditstatus` writable, `ProtectHome=read-only`, `PrivateTmp`, `NoNewPrivileges`. The log directory is created with mode `0750` and the log with mode `0640`, readable by the attester through root or `CAP_DAC_READ_SEARCH`.

Install it:

```sh
sudo apt install bpftrace
sudo install -m 0644 packaging/systemd/auditstatus-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now auditstatus-monitor
```

The Ansible role does the same with `auditstatus_monitor: true`. Then enable it in the attester configuration:

```yaml
monitor:
  enabled: true
  log: /var/log/auditstatus/monitor.log
  windowSeconds: 86400
```

`auditstatus doctor` checks that the log exists ("Enable the auditstatus-monitor service" otherwise), that it was written in the last hour, and that `bpftrace` is installed. With capabilities, `monitor.log` must be under `/var/log/`.


## What the attester reports

When it collects evidence, the attester reads the log (and `monitor.log.1`) for the last `monitor.windowSeconds` seconds, and keeps each distinct path once per event type, with its count, the uids that ran it, and when it was first and last seen, up to 2,000 paths per type. It then hashes each file as it is now, and records the Debian or Ubuntu package that owns it. Any user chose these paths, so only symbolic links owned by root are followed and only regular files are read. A path that is a link (`/bin/sh`, `/usr/bin/python3`, `node_modules/.bin/<name>`) is recorded with the file it resolves to (`realPath`), which is the file hashed and whose package is recorded. A maintainer script dpkg keeps (`/var/lib/dpkg/info/<package>.postinst`, run when a package is upgraded or removed) is recorded as its package's. A file that is gone, or cannot be read that way, is reported with the error.

Windows overlap: with an hourly verification and the default window of a day, a program is reported by every verification in the day after it ran. A finding about it stays until it leaves the window.


## How the verifier explains entries

Each entry is explained like the running code of the inspected processes (see [How it works](how-it-works.md#what-is-compared-with-what)): a service file that matched its commit, build or release; a file of a verified package; an official Node.js binary (the same file as a running Node.js process whose release matched); a pinned hash or signed checksum list in `executables`; or the file of its package in the distribution's signed archive (for a maintainer script, the script in the package's control archive). An entry recorded with `realPath` is explained as that file. Programs in containers are recorded with paths inside the container; an entry whose path is a file of a compared container image is not reported.

| Finding                                                                                       | Severity         | What to do                                                                                                                                                                                                                                                    |
| --------------------------------------------------------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The monitor recorded N programs and M libraries from ... to ...                               | info             | Nothing.                                                                                                                                                                                                                                                      |
| Programs or libraries loaded since the last audit differ from their references                | fail             | A file differs from the package or release it claims to be. Investigate.                                                                                                                                                                                      |
| Programs or libraries loaded since the last audit are no longer on disk                       | `policy.monitor` | Something ran and was deleted: a temporary build tool, an installer, or code that removed itself. Find out what it was.                                                                                                                                       |
| Programs or libraries loaded since the last audit could not be hashed on the server           | `policy.monitor` | The file is there, but the attester would not or could not read it: a symbolic link on its path that another user owns (and so may have pointed elsewhere when it ran), or a file it may not read. Make the link root's, or run the program by its real path. |
| Programs or libraries loaded since the last audit that no reference explains                  | `policy.monitor` | Add the program to `executables` (pinned hash or checksum list), install it from the distribution, or remove it.                                                                                                                                              |
| Programs or libraries loaded since the last audit whose path is longer than the monitor keeps | warn             | Only the first 199 bytes of the path are known, so the file was not found or checked. Look at the log; use shorter paths for programs.                                                                                                                        |
| Programs or libraries loaded since the last audit could not be checked                        | error            | A reference could not be fetched; the next run usually succeeds.                                                                                                                                                                                              |
| The monitor saw more distinct files than it keeps; the list is incomplete                     | `policy.monitor` | Something ran many distinct files. Look at the log.                                                                                                                                                                                                           |
| The monitor log has N line(s) that are not monitor events                                     | warn             | The monitor writes only whole events: something else wrote to the log, or a line was cut short (a crash, a full disk). Look at the log.                                                                                                                       |
| The monitor recorded nothing in its window (is it running?)                                   | warn             | Check the service: `systemctl status auditstatus-monitor`.                                                                                                                                                                                                    |
| The monitor log could not be read: ...                                                        | `policy.monitor` | Check `monitor.log` and the attester's permissions.                                                                                                                                                                                                           |

`policy.monitor` is `fail` by default.


## Limits

The log is written by root on the audited server, so it is software evidence: it shows what happened unless root edited it. Files are hashed when the evidence is collected, not when they ran, so a file replaced after it ran is checked as it is now. For a record that root cannot edit, use IMA with a TPM (see [Hardware evidence](hardware.md#ima)).
