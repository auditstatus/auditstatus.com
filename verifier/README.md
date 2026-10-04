# Audit Status verifier keys

The [public registry](../docs/registry.md) connects to each registered server over SSH with one of these keys. On the server the key can run the attester and nothing else.

<!-- keys:start -->

No key has been generated yet. The [Verifier key workflow](../.github/workflows/verifier-key.yml) writes this table.

<!-- keys:end -->

[auditstatus.pub](auditstatus.pub) lists every current key, one per line: one key, or two while servers move from one to the next.


## Allow the keys on a server

Allow every line of `auditstatus.pub` for the account the registry connects as, with the forced command:

```sh
curl -fsSLo auditstatus.pub https://raw.githubusercontent.com/auditstatus/auditstatus.com/main/verifier/auditstatus.pub
ssh-keygen -lf auditstatus.pub
sudo install -d -o root -g auditstatus -m 0755 ~auditstatus/.ssh
sed 's|^|command="/usr/local/bin/auditstatus ssh",restrict |' auditstatus.pub | sudo tee ~auditstatus/.ssh/authorized_keys
```

Compare the fingerprints `ssh-keygen` prints with the table above before you install them. `command=` runs the attester whatever the client asks for, and `restrict` turns off port, agent and X11 forwarding and the terminal.


## What the key can do

The attester's forced command accepts three requests: `check <nonce>` (evidence for a fresh nonce), `enroll` (the TPM's attestation key) and `activate <credential>` (TPM credential activation). It answers with evidence and nothing else: no shell, no files, no changes to the server. Someone holding a copy of the key could ask your servers for evidence, which the registry publishes anyway, and nothing more.


## How the keys were generated

The [Verifier key workflow](../.github/workflows/verifier-key.yml) generates a key on a GitHub-hosted runner:

1. `ssh-keygen -t ed25519 -N '' -C auditstatus-verifier-key-<n>` writes the key pair in a private temporary directory.
2. `gh secret set AUDITSTATUS_SSH_KEY_<n> --env verifier` stores the private key as a secret of the `verifier` environment, with a fine-grained token that can write the environment's secrets and never read them. The workflow removes its copy; the runner is discarded after the job.
3. The workflow writes the public key to `auditstatus-<n>.pub` and `auditstatus.pub`, and signs `auditstatus-<n>.pub` with a GitHub artifact attestation (Sigstore build provenance naming the workflow, its commit and its run), kept as `auditstatus-<n>.pub.sigstore.json`.
4. It pushes them to the branch `verifier-key/<run>`; a pull request publishes them.

Nobody sees the private key: GitHub never shows a secret's value, and nothing in the workflow prints it. The `verifier` environment admits the `main` branch only, so only the registry's workflows on `main` receive the key, and every change to them is a public commit.

Check that the workflow generated a key:

```sh
gh attestation verify verifier/auditstatus-1.pub --repo auditstatus/auditstatus.com \
  --signer-workflow auditstatus/auditstatus.com/.github/workflows/verifier-key.yml
```

Add `--bundle verifier/auditstatus-1.pub.sigstore.json` to check it without GitHub's attestation API.


## Replace a key

Two places, 1 and 2, let servers move from one key to the next without a gap:

1. Run the Verifier key workflow for the free place, and merge its pull request. The registry offers both keys from then on.
2. Announce the new key; each project adds its line to `authorized_keys`.
3. Once the projects allow it, delete the old key's secret (Settings, Environments, `verifier`), its two files, and its line in `auditstatus.pub` and in the table above.

For a key that leaked, run the workflow for that key's place: the new key replaces it at once, and servers stay inconclusive until they allow the new one.


## Set up (maintainers)

1. Create two environments (Settings, Environments): `verifier` and `verifier-key`. For each, allow deployments from `main` only (Deployment branches and tags, Selected branches, `main`). Turn off "Allow administrators to bypass configured protection rules" for both.
2. Create a fine-grained personal access token: resource owner `auditstatus`, only the `auditstatus/auditstatus.com` repository, the repository permission "Environments: Read and write", an expiration of one day. Store it as the `KEY_ADMIN_TOKEN` secret of the `verifier-key` environment.
3. Run the Verifier key workflow (Actions, Verifier key, Run workflow) with key `1` and confirm `replace key`.
4. Merge the pull request from `verifier-key/<run>`.
5. Delete the `KEY_ADMIN_TOKEN` secret and the token.
