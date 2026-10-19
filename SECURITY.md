# Security policy

AE-OS produces evidence that auditors rely on, so security reports are taken seriously and handled privately.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. This opens a private advisory that only the maintainer can see.

Please do not open a public issue, pull request or discussion for a suspected vulnerability.

A useful report includes the affected version or commit, the steps to reproduce, and what an attacker could achieve (for example, making a verifier accept an altered record).

## What to expect

- Acknowledgement within 7 days.
- An assessment and, where needed, a fix plan within 30 days.
- Credit in the release notes when the fix is published, unless you prefer to stay anonymous.

This is a volunteer-maintained project, so these are targets rather than guarantees.

## Supported versions

Only the latest release receives security fixes while the project is at version 0.x.

## Scope

In scope: the specification in `spec/`, the code in this repository, and the verification procedures they describe. Out of scope: third-party MCP servers or agents used alongside AE-OS, and deployments that keep the signing key where the agent can reach it (the documentation advises against this).
