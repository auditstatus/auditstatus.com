# Registry

Each file here registers one project with the public registry. The [Registry workflow](../.github/workflows/registry.yml) verifies every project's servers each hour with Audit Status's key ([verifier/](../verifier/README.md)) and publishes the results to the [`status` branch](https://github.com/auditstatus/auditstatus.com/tree/status). The [README](../README.md#projects) lists every project with its live badge.

To add yours, follow [Public registry](../docs/registry.md): install the attester, allow the key on your servers, add `<project>.yml` here, and open a pull request. A minimal file:

```yaml
# yaml-language-server: $schema=https://auditstatus.com/schema/registry.schema.json
project:
  name: Example
  url: https://example.com
  contact: security@example.com
repository:
  url: https://github.com/example/app.git
  branch: main
services:
  - name: app
    root: /srv/app
servers:
  - name: web1
    host: web1.example.com
    hostKeys:
      - ssh-ed25519 AAAA...
```

More in [examples/registry](../examples/registry/). Before the pull request:

```sh
pnpm install
node scripts/cli.js registry validate
node scripts/cli.js registry readme
```
