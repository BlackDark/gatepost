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

### Security

- Updated the Go toolchain floor to 1.26.8 in both modules. Go 1.26.5 carried
  five published standard library vulnerabilities (including `encoding/asn1`
  recursion depth and `net/http` Punycode label handling) reachable from this
  code; `govulncheck` was failing on `main` before this branch.
- Updated `google.golang.org/grpc` to v1.83.2 in `cmd/extauth-server`, fixing a
  server panic on requests with a missing authority/Host header
  (GO-2026-6443) and heap exhaustion via HTTP/2 DATA frame fragmentation
  (GO-2026-6348). Both were reachable from the gRPC ext_authz listener.
- Introspection responses now honour the `active` flag; an inactive token no
  longer validates just because it is well-formed and unexpired.
- Front-channel logout now requires `sid` **or** `id_token_hint` in addition to
  a matching `iss`. `iss` alone is identical for every user of the provider, so
  accepting it made forced-logout CSRF trivial: any unauthenticated `GET` — an
  `<img>` tag on a hostile page — could log an arbitrary visitor out. A rejected
  notification returns `400` and no longer clears the session.
- Client-supplied identity headers (`X-Forwarded-User`, `X-Forwarded-Email`,
  `Remote-User`, `X-Auth-Request-*`, ...) are stripped unconditionally and
  re-set from the session, so a request taking the bypass, `Forward`, or
  public path can no longer claim to be any user.
- Well-known identity headers set by a sibling proxy are re-applied from the
  verified session, closing the reverse of the stripping above.
- The auth-rule expression evaluator no longer scales quadratically with nesting
  depth. `evaluateSelector` in `src/predicate/parse.go` recursed once per nesting
  level and re-walked its children at every level, so a selector nested 60k deep
  — which a `bypass` or `unauthorized` rule will happily attempt to parse,
  since the expression comes from the operator's own configuration rather than
  from the request — burned roughly 16s of CPU in a single request. The
  evaluator is now an iterative single walk: the same input parses in ~10ms.

### Upgrading

Three rounds of security fixes have landed together in this release. The
behaviour changes a user will actually observe, and the config key that
preserves the old behaviour, are:

- **`sessionIdleTimeoutSeconds` assumes one replica.** The "last used" timestamp
  is written back at most once per refresh interval *per process*, tracked in an
  in-memory map that is not shared between replicas. With `N` replicas behind a
  load balancer the effective refresh rate is roughly `N` times the documented
  one, so the "exceeds the bound by at most one interval" claim holds for a
  single replica only. The error is in the safe direction: more frequent
  refreshes make the idle bound *tighter*, never looser, so an idle session is
  still terminated no later than the configured bound plus the load balancer's
  own skew.

- **Forwarded headers are only honoured from a proxy you declare.** The
  `redirect_uri` sent to the IDP, and every other absolute URL built from the
  request (post-login and post-logout redirect targets, the `loginUri` /
  `logoutUri` links on the error pages, and the scheme/host check that decides
  whether an inbound request is the OAuth callback), are now derived from the
  request itself unless the peer is in `trustedProxies`. Previously
  `X-Forwarded-Proto` and `X-Forwarded-Host` were trusted unconditionally.
  Set `trustedProxies` to the CIDR of the ingress / load balancer in front of
  Traefik. **There is no key that restores unconditional trust** — an empty
  `trustedProxies` is the fail-closed default, which is correct when Traefik
  is reachable directly.
- **BREAKING CHANGE: sessions are purpose-bound, with a legacy fallback.**
  Session cookies are now sealed with the `session` purpose bound into the
  AEAD, so a ciphertext minted for another purpose can no longer be read as a
  session. Session cookies sealed before this version are still accepted
  through a narrow fallback — and only there — logged at `INFO`, and are
  re-sealed with the session purpose on the next renewal, so a rolling upgrade
  does not log everyone out at once. Because the fallback re-seals rather than
  rejecting, each pre-upgrade session clears the window on its first renewal
  and is then indistinguishable from a newly established one. The fallback
  itself lives in the code, not in instance state, so it survives a restart;
  it will be removed in a later release, after which every session must be
  re-established through a fresh login. No config key controls this.
- **BREAKING CHANGE: the OIDC `state` parameter expires after 10 minutes.** The
  sealed state carries a signed issue/expiry pair, so a captured callback URL
  cannot be replayed indefinitely. A login that is left idle on the IDP's
  consent screen for more than 10 minutes must be restarted by the user. States
  sealed before this version carry no expiry and are accepted through the same
  legacy fallback, logged at `WARN`; that fallback refuses any ciphertext that
  *does* carry an expiry or type tag, so it cannot be used to skip the check.
  No config key controls this.
- **BREAKING CHANGE: front-channel logout requires `sid` or `id_token_hint`.**
  A notification carrying only `iss` is now rejected with `400` and leaves the
  session intact. IdPs that send only `iss` will not be able to log users out
  through this endpoint.
- **BREAKING CHANGE: invalid enum values fail at startup.**
  `provider.verification_token` (anything other than `AccessToken`, `IdToken`,
  `Introspection`) and `sessionStorageType` (anything other than `Cookie`) now
  abort the middleware's `New()` instead of failing every login at request
  time. A config copied from a fork that supports other values will refuse to
  start; remove the key. Set `sessionStorageType: "Cookie"` explicitly if the
  key must be present.
- **BREAKING CHANGE: an unparseable `trustedProxies` entry fails at startup.**
  Entries are parsed as CIDR ranges, and one that does not parse now aborts the
  middleware's `New()` instead of being silently skipped. A config that used to
  start with a typo'd or non-CIDR entry (an IP with a prefix but no mask, a
  hostname, an empty string) now refuses to start. Fix or remove the entry.
- **BREAKING CHANGE: a reserved key in `authorizationParams` fails at startup.**
  Reserved protocol parameters (`response_type`, `client_id`, `redirect_uri`,
  `state`, `scope`, `resource`, `code_challenge`, `code_challenge_method`,
  `nonce`) previously produced a warning and the key was ignored. The plugin now
  aborts `New()` when any of them is present. Remove the reserved keys you do
  not actually need; the plugin sets them itself.
- **BREAKING CHANGE (packaging): release images can no longer be published from
  prerelease tags.** The release workflow refuses any tag carrying a `-` suffix
  or a `+build` suffix, so `v1.2.3-rc1` — and anything like it — is rejected
  rather than published. Publish a prerelease only after removing the suffix, or
  by other means; do not assume `rc` publishing still works.
- **Config key casing is not interchangeable between the two config surfaces.**
  Traefik decodes the plugin config with `mapstructure` and **no** tag name, so
  it matches the Go struct field name case-insensitively and **ignores** the
  `json` tags entirely: Traefik YAML keys must be camelCase (`logLevel`,
  `sessionCookie`, `cookieNamePrefix`, `trustedProxies`,
  `maxSessionLifetimeSeconds`, `sessionIdleTimeoutSeconds`,
  `sessionStorageType`, `authorizationParamsOverridable`,
  `provider.clientId`, `provider.oidcTimeoutSeconds`,
  `provider.revokeTokensOnLogout`, `provider.maxAuthAgeSeconds`). A snake_case
  key silently decodes to its zero value — the option appears configured and
  does nothing. `cmd/extauth-server`'s `CONFIG_FILE` is a different surface: it
  is decoded with `encoding/json`, so it uses the snake_case `json` tags
  (`log_level`, `session_cookie`, `cookie_name_prefix`,
  `max_session_lifetime_seconds`, `provider.client_id`,
  `provider.client_secret`). Same option, two casings, two files. Two options
  are **not** even the same option:
  - **`trustedProxies` / `trusted_proxies` are different mechanisms.** The
    Traefik plugin gates its `X-Forwarded-*` handling on the `trustedProxies`
    **config key**. `extauth-server` gates the same handling on the
    **`TRUSTED_PROXIES` environment variable** (`parseTrustedProxies(os.Getenv(...))`
    in `cmd/extauth-server/main.go`, matched against the TCP peer in
    `forwardedRequest`); the `trusted_proxies` key in `CONFIG_FILE` decodes into
    `config.TrustedProxies` and is never read on that path. Setting one does not
    set the other.
  - **Boolean options are `*_bool` on the JSON surface.** Every `bool` provider
    option is declared in Go as a `string` field plus a separate `bool` field
    carrying the `*_bool` json tag. The string field serves Traefik's weakly-typed
    `mapstructure` decoder and `${VAR}` expansion. `encoding/json` is strictly
    typed, so in `CONFIG_FILE` only the `*_bool` key accepts a JSON boolean;
    `"revoke_tokens_on_logout": true` aborts startup with `json: cannot unmarshal
    bool into Go struct field ...` and the process exits `1`.

### Added

- `maxSessionLifetimeSeconds` — hard upper bound on total session lifetime.
  `0` (default) disables it and logs a `WARN` at startup. A session ticket sealed
  before the creation timestamp existed carries none, so its bound is backfilled
  from first use and only becomes enforceable against its true age once the ticket
  has been re-sealed.
- `sessionIdleTimeoutSeconds` — bound on the gap between accepted requests on
  one session. `0` (default) disables it. The durable timestamp is refreshed at
  most once per quarter of the bound (capped at 60s) rather than on every
  request, so a session can exceed it by at most one refresh interval. That
  "one interval" bound assumes a single replica; see [Upgrading](#upgrading).
- `trustedProxies` — CIDR ranges of proxies whose `X-Forwarded-Proto` /
  `X-Forwarded-Host` may be trusted. Empty by default (trust nothing). An
  unparseable entry fails the middleware at startup.
- `authorizationParamsOverridable` — allowlist of `authorizationParams` keys an
  incoming request may override via query parameter. Empty by default, which
  pins every configured value, including `prompt`.
- `provider.maxAuthAgeSeconds` — enforces the step-up freshness requirement on a
  **challenge** (`unauthorizedBehavior: Challenge`): sends `max_age` and requires
  a recent `auth_time` claim. A missing `auth_time` is treated as a failure. A
  plain login (`unauthenticatedBehavior: Challenge` / `Auto`) and session renewals
  are unaffected. **Not usable with `provider.tokenValidation: Introspection`**:
  RFC 7662 introspection responses carry no `auth_time`, so a challenge would
  never be satisfiable and the user would be denied.
- `provider.oidcTimeoutSeconds` — client-side timeout bounding every outbound
  IDP call. Default `30`; `0` and negative values resolve to the default.
- `provider.revokeTokensOnLogout` (default `true`) — revokes the session's
  refresh token at the IDP's `revocation_endpoint` on user-initiated logout and
  on front-channel logout. Silently skipped when no endpoint is advertised.
- Route matching is anchored: a configured route matches exactly or below itself
  with a trailing slash, never as a bare path prefix.

### Fixed

### Fixed

- **Security:** `X-Forwarded-Host` / `X-Forwarded-Proto` are now read from the
  **rightmost** entry, not the leftmost. In an appending proxy chain the entry a
  trusted hop added is the rightmost one, so the leftmost was client-controlled
  and could steer the `redirect_uri` sent to the IDP and the absolute URLs this
  plugin emits. The standalone `extauth-server` had the same defect plus no
  scheme allowlist; both are fixed.
- **Security:** an `includeWhen: Always` header on the bypass-rule and
  `Forward` paths rendered the literal `<no value>`, because templating ran
  against a nil claims map. A backend that treats the *presence* of an identity
  header as authenticated could therefore be bypassed. Those paths no longer
  render headers at all; the spoofable-identity-header stripping is unchanged.
- `maxAuthAgeSeconds` is enforced only on a step-up **challenge**. It was
  applied to every login, which contradicted the documentation and - combined
  with `tokenValidation: Introspection`, whose responses carry no `auth_time`
  claim - locked every user out.
- A failed `StoreSession` (including `ErrSessionTooLarge`) no longer writes a
  500 and then continues to forward the request upstream or redirect. The
  response is written exactly once and the request stops.
- The absolute session-lifetime bound is now real for session tickets sealed
  before this release: their creation timestamp is persisted on first sight
  instead of restarting from zero on every request.
- Config-key correctness: Traefik decodes plugin config with `mapstructure` and
  **no** `TagName`, so it matches the Go field name case-insensitively and
  ignores the `json` tags. Every option this release adds was documented in
  `snake_case` and would have been silently ignored by every Traefik
  deployment. Documentation now uses the camelCase Go field names, and a test
  guards the divergence (see Added).
- The `extauth-server` `CONFIG_FILE` example in the docs could not be loaded:
  `revoke_tokens_on_logout` is a string field, so a JSON boolean aborted
  startup with exit code 1. `trusted_proxies` was also documented for
  `CONFIG_FILE`, where it is inert - HTTP mode is gated by the `TRUSTED_PROXIES`
  environment variable.

- The multi-arch image check in CI failed on every run because the
  multi-platform build used the default docker exporter, which cannot write a
  manifest list. It now uses `type=cacheonly`, so the cross-compile is still
  verified for both published platforms without exporting anything.

### Fixed

- Header templates are compiled once in `New` instead of lazily on first use per
  request, which was a data race on the shared config: two concurrent requests
  both entered the uninitialised cache and both wrote it. A malformed template
  now also aborts `New` with a descriptive error instead of failing every
  request after a successful startup.
- A session that does not fit the cookie budget is now rejected with
  `ErrSessionTooLarge` and an actionable `ERROR` log naming the size and the
  limit. Previously the ticket was silently truncated to 32 chunks, producing a
  cookie that could never be decrypted again — visible to the user only as a
  permanent re-login loop, with nothing in the log to explain it. The usual
  cause is an oversized claim set from the IDP; reduce `assert_claims`, the
  requested scopes, or the claims the IDP returns.
- The legacy purpose-less `state` fallback no longer accepts a session cookie as
  a login state. A ciphertext sealed without an AEAD purpose has to be opened
  some other way during a rolling upgrade, but the shape it must have is now
  checked positively (a non-empty `action`) rather than only by the absence of
  the fields a real state would carry. A purpose-less ciphertext shaped like a
  session — `{"id": ..., "access_token": ..., "is_authorized": true}` — was
  previously unsealed into an empty state object and passed on to the callback.

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