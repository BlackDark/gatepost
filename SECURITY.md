# Security Policy

This repository is a **hardened fork** of
[sevensolutions/traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth).
It ships its own hardening work (see [`docs/adr/`](docs/adr/)) and its own release
tags, so vulnerabilities in this fork are **not** handled by the upstream project.
Report fork-specific issues to **this** project, not to upstream.

## Supported Versions

Only the current minor series receives security updates. Older series are not
patched; upgrade to a supported series before reporting an issue against one.

| Version | Supported |
|---------|-----------|
| `v0.22.x` | ✅ |
| `v0.21.x` | ✅ |
| `v0.20.x` | ✅ |
| `< v0.20.0` | ❌ |

Please update regularly and watch for new releases.

## Reporting a Vulnerability

Thank you for taking the time to report a vulnerability.

> [!IMPORTANT]
> **Please do not open a public GitHub issue, pull request, or discussion for a
> vulnerability.** A public issue may be exploited before a fix is available. Use
> one of the private channels below.

### Primary channel (fork-specific issues)

Report via **GitHub Security Advisory** on this repository:

<https://github.com/BlackDark/gatepost/security/advisories/new>

This is the only channel that reaches this fork's maintainers, and it keeps the
report and the eventual fix private until a release is published. Prefer it.

### Secondary channel (upstream issues)

Security issues that also reproduce on unmodified upstream
[sevensolutions/traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth)
may additionally be reported to upstream's maintainers
(<contact@danielpeinhopf.com>, <cdanis@gmail.com>). This is a courtesy CC channel
for defects that are not fork-specific — it does **not** replace the advisory
above, and a fork-only defect reported solely to upstream will not be tracked
here.

### What to include

- Affected component (`src/` Traefik middleware, or `cmd/gatepost-extauthz/`)
- Affected version or git tag
- Reproduction steps or a proof of concept
- Impact (e.g. auth bypass, token disclosure, session fixation)
- Any known workaround

## Response Expectations

These are targets, not guarantees; the maintainers of this fork are volunteers
and respond as capacity allows.

| Stage | Target |
|-------|--------|
| Acknowledgement that the report was received | 3 business days |
| Initial assessment (valid / needs more info / not a vulnerability) | 10 business days |
| Fix and released version, for confirmed Critical/High | 30 days |

Fixes are recorded in [`CHANGELOG.md`](CHANGELOG.md) under **Security**, and the
design rationale behind each hardening change is recorded in [`docs/adr/`](docs/adr/).

## Scope

In scope: the Go code in this repository (`src/`, `cmd/gatepost-extauthz/`), its
CI/CD workflows, and the shipped container images.

Out of scope: vulnerabilities in the Go standard library, third-party
dependencies, or in Traefik, the identity provider, or the gateway in front of
this middleware. Report those to their respective maintainers.