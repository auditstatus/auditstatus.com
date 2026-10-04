# Getting started

The simplest way to verify your servers is the [public registry](registry.md): install the attester, allow Audit Status's key, and add one YAML file to the Audit Status repository. Its workflow verifies your servers every hour and publishes your report and badge.

This page sets up your own verifier instead, in your repository. It takes you from a repository to a first published report: generate the configuration with `auditstatus init`, install the attester on one server, check both sides with `auditstatus doctor`, and let the GitHub workflow verify the server and publish the result. It assumes a server that deploys a git checkout of a public GitHub repository and that you can reach over SSH.


## 1. Install the command line tool

On your own machine, install the CLI from npm (the verifier and `init` run anywhere Node.js 18 or later runs):

```sh
npm install -g auditstatus
```

Audited servers run the release binary instead (step 3), because the verifier matches the attester's own executable against the release checksums.


## 2. Generate the configuration

In your repository:

```sh
auditstatus init --host app1.example.com --root /srv/app --user app
```

`init` looks for lockfiles, a `Dockerfile` or compose file, and the `origin` remote, then writes three files it does not find already:

| File                                | What it is                                                                                                             |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `auditstatus.config.yml`            | The verifier configuration: which repository and branch each service is verified against, and which servers to verify. |
| `auditstatus/attester.config.yml`   | The attester configuration, to install on each server as `/etc/auditstatus/config.yml`.                                |
| `.github/workflows/auditstatus.yml` | A workflow that verifies every hour and publishes the report.                                                          |

| Option    | Default            | Meaning                                                                  |
| --------- | ------------------ | ------------------------------------------------------------------------ |
| `--dir`   | `.`                | The repository to look at and write into.                                |
| `--host`  | `app1.example.com` | The first server's host name. Its first label becomes the server's name. |
| `--root`  | `/srv/<name>`      | The deployed checkout on the server. `<name>` is the directory's name.   |
| `--user`  | `<name>`           | The account the application runs as.                                     |
| `--force` | off                | Replace files that exist.                                                |

The output lists what it detected and wrote, for example:

```text
Detected: Node.js (package-lock.json)
  wrote auditstatus.config.yml
  wrote auditstatus/attester.config.yml
  wrote .github/workflows/auditstatus.yml
```

Open the two configuration files and read the comments. Check `root` and `user` in the attester configuration, and `host` in the verifier configuration. If the deploy generates files the repository ignores (a bundle, compiled assets), uncomment the `build` section. See [Configuration](configuration.md) for every setting.


## 3. Install the attester on the server

On the server, install the release binary. The installer checks it against the release's `SHA256SUMS`:

```sh
curl -fsSLO https://github.com/auditstatus/auditstatus.com/releases/latest/download/install.sh
AUDITSTATUS_VERSION=<version> bash install.sh
```

Create the account the verifier connects as, let only root and that account run the attester, let the attester read other users' processes and files, and install the configuration:

```sh
sudo useradd --system --create-home --shell /bin/sh auditstatus
sudo chgrp auditstatus /usr/local/bin/auditstatus
sudo chmod 0750 /usr/local/bin/auditstatus
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep /usr/local/bin/auditstatus
sudo install -d -o root -g root -m 0755 /etc/auditstatus
sudo install -o root -g root -m 0644 attester.config.yml /etc/auditstatus/config.yml
```

The configuration must be owned by root and must not be writable by group or others. See [Attester](attester.md) for the details, the Ansible role, and running as root instead of with capabilities.


## 4. Check the server

```sh
sudo -u auditstatus auditstatus doctor
```

`doctor` checks the configuration, permissions, the processes of each service, installed packages, the TPM, and more. Each problem comes with a `fix:` line. It exits with `1` while any check fails. A warning such as "The TPM is disabled; evidence is software-only" does not stop you; see [Hardware evidence](hardware.md) to add a TPM later.

You can also print what the attester sees:

```sh
sudo -u auditstatus auditstatus check
```


## 5. Give the verifier an SSH key

Create a key for the verifier:

```sh
ssh-keygen -t ed25519 -N "" -f auditstatus_key
```

On the server, allow the public key to run the attester and nothing else:

```sh
sudo install -d -o root -g auditstatus -m 0755 ~auditstatus/.ssh
echo "command=\"/usr/local/bin/auditstatus ssh\",restrict $(cat auditstatus_key.pub)" | sudo tee ~auditstatus/.ssh/authorized_keys
```

Pin the server's host key next to `auditstatus.config.yml`, then compare its fingerprint with the one the server shows (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server):

```sh
ssh-keyscan -t ed25519 app1.example.com >> known_hosts
ssh-keygen -lf known_hosts
```

Do not hash the entries (`ssh-keyscan -H`): `doctor` looks for the plain host name.

Store the private key as a repository secret named `AUDITSTATUS_SSH_KEY`, and commit `known_hosts`.


## 6. Check the verifier

```sh
AUDITSTATUS_SSH_KEY="$(cat auditstatus_key)" auditstatus doctor --role verifier
```

It checks the configuration, the pinned host key of each server, the SSH key, and that every repository is reachable.


## 7. Verify

Run a verification from your machine:

```sh
AUDITSTATUS_SSH_KEY="$(cat auditstatus_key)" auditstatus verify
```

It prints one line per server and each finding that is not informational, then writes `report.json`, `report.md` and `badge.json` to `audit-status/`. Then commit and push `auditstatus.config.yml`, `known_hosts` and the workflow. The workflow runs every hour, on a push to `main` or `master`, and on demand; it commits the report to the `audit-status` branch and opens an issue when the result is not passing. See [Verifier](verifier.md).


## 8. Read the first report

Open `report.md` on the `audit-status` branch. The table has one row per server with its status and evidence level; below it, each server's services and findings. [Reports](reports.md) explains each finding and what to do about it. To show a badge, see [Verifier](verifier.md#badge).


## Next steps

* Add every server to `servers`, and every application or container to `services`.
* Add hardware evidence: [TPM, IMA and confidential VMs](hardware.md).
* Record what runs between audits with the [monitor](monitor.md).
* Publish the result on your status page: [Adopters](adopters.md).
