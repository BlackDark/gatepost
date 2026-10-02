# Changelog

All notable changes to this project are documented in this file.

This is a **hardened fork** of
[sevensolutions/traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth).
**Fork tags are independent of upstream tags**: a `v0.22.0` here is a fork
release and does not correspond to any upstream release. Entries below are
seeded from this repository's git history; upstream-origin commits carried in
during the fork are not enumerated.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [v0.22.0] - 2026-08-02

Standalone ext_authz service release, plus workflow hardening.

### Added

- Standalone `ext_authz` service (`cmd/extauth-server/`) exposing the shared OIDC
  session and authorization core over HTTP and gRPC, for use behind Envoy Gateway
  (`SecurityPolicy`), Traefik `forwardAuth`, and any other `ext_authz`-compatible
  gateway. Recorded in [ADR-0005](docs/adr/0005-standalone-ext-authz-service/).
- `docs/extauth-server.md` — usage, gateway compatibility, and a full security
  review of the new service.
- Release-image workflow publishing `cmd/extauth-server` as a multi-architecture
  container image from any `v*` tag.
- `zizmor` workflow linting GitHub Actions for security issues, and a Dependabot
  cooldown so the scan stays green.
- `cmd/extauth-server` is covered as its own Go module in CI.

### Changed

- CI cross-compiles `extauth-server` natively instead of under QEMU emulation, and
  builds both architectures in a single native build stage.
- README reframed around the two deliverables: the Traefik middleware (primary,
  mature) and the standalone `ext_authz` service (experimental).
- Pre-existing workflows hardened and GitHub Actions pinned to commit SHAs.

## [v0.21.1] - 2026-07-27

### Security

- Redirect URI wildcard matching is now opt-in and, when enabled, strictly
  validated. Exact entries always match; wildcard templates are additionally
  checked for host/path spoofing and path traversal. Previously wildcard
  patterns were accepted without the opt-in gate.
- Existing callback re-validation reuses the same matcher, so a redirect URI
  accepted at authorize time is also accepted on the way back.

### Changed

- Documented the wildcard opt-in gate (`TOA_ENABLE_REDIRECT_URI_WILDCARDS`) and
  the matching rules it enables.

## [v0.21.0] - 2026-07-22

### Security

- `gosec` and `govulncheck` enabled in CI.
- E2E coverage for the "Challenge" flow, verifying it does not redirect-loop
  against a mock OIDC provider.

### Changed

- Config examples in documentation migrated to camelCase.
- README: dropped the goreport badge and corrected the Pocket ID URL.

## [v0.20.0] - 2026-07-20

### Changed

- **BREAKING CHANGE:** `UnauthorizedBehavior` was split into
  `UnauthenticatedBehavior` and `UnauthorizedBehavior`. Requests that carry no
  credentials are now governed by `UnauthenticatedBehavior`; requests that carry
  credentials which fail authorization are governed by `UnauthorizedBehavior`.
  Existing configurations must migrate both keys explicitly — the previous
  single `UnauthorizedBehavior` value is no longer inherited by either case, and
  the middleware fails closed when a required key is absent.
- `src/` is now published as `github.com/BlackDark/test-oidc-traefik-plugin`;
  e2e configuration points Traefik's local plugin at this module path.
- E2E suite swaps Keycloak for `mock-oauth2-server`, and exercises non-default
  plugin `Secret` values including on bypass-rule middleware.

### Fixed

- Playwright `afterEach` fixture shape restored.

## [v0.19.0-hardening.1] - 2026-07-19

Fork hardening baseline. All work below landed in this fork, not upstream; see
[`docs/adr/`](docs/adr/) for the rationale behind each decision.

### Security

- OIDC `state` is sealed end-to-end (AES-GCM) with the plugin secret, so nothing
  in it can be read or forged by the browser — [ADR-0002](docs/adr/0002-sealed-oidc-state/).
- PKCE `code_verifier` is stored encrypted inside the sealed OIDC `state` rather
  than in a separate shared cookie, fixing verifier clobbering under parallel
  login attempts — [ADR-0001](docs/adr/0001-pkce-verifier-in-oidc-state/).
- Login flow is bound with a CSRF cookie, so an attacker cannot force a victim's
  browser onto an attacker-chosen authorization flow —
  [ADR-0003](docs/adr/0003-login-csrf-binding/).
- `nonce` is validated on ID tokens — [ADR-0004](docs/adr/0004-oidc-nonce/).
- Front-channel logout handling hardened.
- Secrets may be loaded from a file via `${file:/path}`, keeping them out of the
  rendered Traefik configuration.
- `secret` must be exactly 32 characters; a wrong-length secret is rejected at
  startup rather than silently weakening the sealed state.

### Added

- `AuthorizationParams` to pass extra query parameters to the IdP.

### Changed

- Repository published as `github.com/BlackDark/test-oidc-traefik-plugin`.

## Fork baseline

Everything preceding `v0.19.0-hardening.1` is inherited verbatim from upstream
[sevensolutions/traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth)
and is documented in that project's own release notes.

<!-- OIDC Back-Channel Logout is deliberately not implemented: see ADR-0006. -->