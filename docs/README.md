# Documentation

The Audit Status documentation: how to add your project to the public registry or run your own verifier, how to set up the attester on your servers, every configuration setting, and how to read the published report.


## Guides

* [Public registry](registry.md): let Audit Status verify your servers every hour from its own GitHub Actions, with one YAML file and nothing in your CI.
* [Getting started](getting-started.md): your own verifier, from `auditstatus init` to a first published report in about ten minutes.
* [How it works](how-it-works.md): the attester, the verifier and the report, what is compared with what, and what each evidence level proves.
* [Attester](attester.md): install the attester on a server, the SSH forced command, Ansible, PM2 and git-based deploys.
* [Verifier](verifier.md): the GitHub action, running `auditstatus verify` yourself, output files, badge, issues and exit codes.
* [Configuration](configuration.md): every setting of the attester and verifier configuration files, with types and defaults.
* [Containers](containers.md): Docker, containerd, CRI-O and Podman containers compared with their images.
* [Kubernetes](kubernetes.md): the Helm chart, `auditstatus serve`, and the port-forward transport.
* [Hardware evidence](hardware.md): TPM enrollment, IMA, and confidential VMs (AMD SEV-SNP, Intel TDX).
* [Monitor](monitor.md): record every program and library loaded between audits.
* [Reports](reports.md): statuses, table columns, and what each finding means and what to do about it.
* [Threat model](threat-model.md): what an attacker can and cannot hide at each evidence level, and who you trust.
* [Adopters](adopters.md): how a service adopts Audit Status and publishes the result on its status page.


## Languages

One page per language or package ecosystem, with the lockfiles and install layouts the verifier understands:

* [Node.js](languages/node.md)
* [Python](languages/python.md)
* [Ruby](languages/ruby.md)
* [Elixir](languages/elixir.md)
* [PHP](languages/php.md)
* [Java](languages/java.md)
* [.NET](languages/dotnet.md)
* [Go](languages/go.md)
* [Rust](languages/rust.md)
* [Binaries](languages/binaries.md)
