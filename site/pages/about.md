<!--
title: About Audit Status: who runs it and how to reach us
description: Audit Status is an MIT-licensed project run by the Forward Email team. How to contribute, report a bug or a vulnerability, and what this site collects.
label: About
kind: about
keywords: about audit status, forward email, audit status license, contact audit status, security report, privacy
-->

<!--lint disable no-heading-punctuation-->

# About Audit Status

Audit Status is an open-source project by the team behind [Forward Email](https://forwardemail.net), the open-source, privacy-focused email service. It verifies that production servers run exactly the code in a public repository, and publishes the result as a report and a badge anyone can read.


## Why does Audit Status exist?

A public repository lets anyone read a service's code, with no way to check that its servers run that code. Forward Email's code is public in [forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net), and Audit Status lets anyone check that its production servers run that code: the [public registry](/projects/) verifies them every hour, and the [Forward Email status page](https://status.forwardemail.net) shows the result.

The project is built for other teams too. The evidence format comes from Attestium, an open specification that any language can implement ([how the two fit together](/attestium/)), and adding a project to the registry takes one YAML file and an SSH key on your servers.


## Who maintains it?

The Forward Email team writes and maintains Audit Status and Attestium, in two separate repositories with their own purposes. The tests are end to end: they run a real `sshd` with a forced command, a software TPM and real processes, and cover every line and branch of the code.


## Price and license

Audit Status is free and open source under the [MIT license](https://github.com/auditstatus/auditstatus.com/blob/main/LICENSE). It runs on your servers and in your CI, or in Audit Status's GitHub Actions through the public registry. There is no paid plan and no Audit Status account to create.


## How do you reach the team?

| For                         | Where                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Bugs, questions and ideas   | [GitHub issues](https://github.com/auditstatus/auditstatus.com/issues)                                              |
| Changes to the code or docs | [Pull requests](https://github.com/auditstatus/auditstatus.com/pulls); every docs page has an "Edit this page" link |
| Adding your project         | A pull request with `registry/<project>.yml`; see [Add your project](/docs/registry/#add-your-project)              |
| Security vulnerabilities    | [forwardemail.net/security](https://forwardemail.net/security), not a public issue                                  |

The site also publishes [`/.well-known/security.txt`](/.well-known/security.txt) with the security contact.


## What does this website collect?

Nothing about you. auditstatus.com sets no cookies and runs no analytics, trackers or third-party scripts. Its pages, fonts and images are served from auditstatus.com, except the live status badges on the [projects page](/projects/), which come from Shields.io. The theme button stores your choice of light or dark in your browser's local storage, and nothing leaves your browser.

The site is static HTML hosted on GitHub Pages, built from the repository by a public workflow. GitHub's [privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement) covers the logs its servers keep.


## Brand and press

The logo, the mark, the colors and the type are on the [brand page](/brand/), with SVG downloads.
