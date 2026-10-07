# Gatepost

OIDC authentication as a **Traefik plugin** and a **standalone ext_authz service**.

[![E2E Tests](https://img.shields.io/github/actions/workflow/status/BlackDark/gatepost/.github%2Fworkflows%2Fe2e-tests.yml?logo=github&label=E2E%20Tests&color=green)](https://github.com/BlackDark/gatepost/actions/workflows/e2e-tests.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/BlackDark/gatepost/blob/main/LICENSE)

Gatepost is an OpenID Connect relying party. Two entry points share one core (`src/oidc`, `src/session`, `src/rules`, `src/predicate`, `src/utils`):

1. **Traefik middleware** (`src/`) — the primary component. Traefik loads it as plugin `gatepost`.
2. **Standalone ext_authz service** (`cmd/gatepost-extauthz`) — **experimental.** Same OIDC, session, and authorization logic behind Envoy's `ext_authz` contract (HTTP and gRPC), so a gateway that speaks that protocol can use it. See [`docs/gatepost-extauthz.md`](docs/gatepost-extauthz.md).

Why both stay in one repo: [ADR-0005](docs/adr/0005-standalone-ext-authz-service/).

> [!NOTE]
> This document always represents the latest version, which may not have been released yet.
> Therefore, some features may not be available currently but will be available soon.
> You can use the GIT-Tags to check individual versions.

> [!WARNING]
> The Traefik middleware is under active development and breaking changes may occur. It is only tested against Traefik v3+.
>
> The standalone ext_authz service (`cmd/gatepost-extauthz`) is **experimental** — functionally verified end-to-end against real infrastructure (Traefik `forwardAuth` and Envoy Gateway `SecurityPolicy`, both HTTP and gRPC modes, with real IdP logins), but newer and less battle-tested than the Traefik middleware itself. See its docs for known gaps before running it in production.

## Traefik middleware

Enable the plugin in Traefik's static configuration. `moduleName` is the Go module, not the `src` package:

```yml
experimental:
  plugins:
    gatepost:
      moduleName: github.com/BlackDark/gatepost
      version: v0.1.0
```

Dynamic configuration uses that same name as the plugin key (`plugin.gatepost`). The Go type is `src.Gatepost`. The catalog import path is `github.com/BlackDark/gatepost/src`.

Config reference and usage live in [`website/docs/`](website/docs/). Start with [getting started](website/docs/getting-started/index.md) and the [middleware configuration](website/docs/getting-started/middleware-configuration.md). Design notes are in [`docs/adr/`](docs/adr/).

### Tested providers

| Provider | Status | Notes |
|---|---|---|
| [ZITADEL](website/docs/identity-providers/zitadel.md) | ✅ | |
| [Kanidm](website/docs/identity-providers/kanidm.md) | ✅ | |
| [Keycloak](website/docs/identity-providers/keycloak.md) | ✅ | |
| [Microsoft Entra ID](website/docs/identity-providers/entra-id.md) | ✅ | |
| [HashiCorp Vault](https://www.vaultproject.io/) | ❌ | Not supported. |
| [Authentik](website/docs/identity-providers/authentik.md) | ✅ | |
| [Pocket ID](website/docs/identity-providers/pocket-id.md) | ✅ | |
| [GitHub](https://github.com) | ❌ | GitHub doesn't seem to support OIDC, only plain OAuth. |
| [Logto](website/docs/identity-providers/logto.md) | ✅ | |

### Behaviour

| Behaviour | What it does | Where |
|---|---|---|
| **Sealed OIDC `state`** | The whole `state` parameter is AES-GCM-sealed with the plugin secret, so its contents can be neither read nor forged by the browser. | [ADR-0002](docs/adr/0002-sealed-oidc-state/) |
| **PKCE `code_verifier` in `state`** | The verifier rides encrypted inside the sealed `state` instead of a shared cookie, so parallel logins do not clobber each other. | [ADR-0001](docs/adr/0001-pkce-verifier-in-oidc-state/) |
| **Login CSRF cookie binding** | The login flow is bound to a CSRF cookie, so an attacker cannot force a victim's browser into an attacker-chosen authorization flow. | [ADR-0003](docs/adr/0003-login-csrf-binding/) |
| **`nonce` validation** | ID tokens must carry and match the `nonce` sent on the authorize request. | [ADR-0004](docs/adr/0004-oidc-nonce/) |
| **Redirect URI wildcards are opt-in** | Wildcard `redirectUri` templates are ignored unless `TOA_ENABLE_REDIRECT_URI_WILDCARDS=true` on the Traefik process. Once enabled, exact entries always match and wildcard templates get strict host/path matching plus spoofing and traversal guards. Callback re-validation uses the same matcher. | — |
| **`${file:/path}` secrets** | Any secret value may be loaded from a file at render time. | — |
| **`secret` must be exactly 32 bytes** | A wrong-length `secret` is rejected at startup. | [ADR-0002](docs/adr/0002-sealed-oidc-state/) |
| **Purpose-bound sealing** | Session tickets and OIDC `state` are sealed with their purpose bound into the AEAD, so a ciphertext minted for one purpose cannot be read as the other. A narrow legacy fallback keeps pre-upgrade cookies working through a rolling upgrade. | [ADR-0002](docs/adr/0002-sealed-oidc-state/) |
| **Expiring OIDC `state`** | The sealed `state` carries a signed 10-minute expiry. A login left idle at the IdP for longer must be restarted. | [ADR-0002](docs/adr/0002-sealed-oidc-state/) |
| **Bounded sessions** | `maxSessionLifetimeSeconds` and `sessionIdleTimeoutSeconds` bound a stateless session. Both default to `0` (disabled). An unbounded `maxSessionLifetimeSeconds` warns at startup. | — |
| **Forwarded-header trust is opt-in** | `X-Forwarded-Proto` / `X-Forwarded-Host` are used when building absolute URLs — including the `redirect_uri` sent to the IdP — only from a peer listed in `trustedProxies`. Empty by default. **Behind an ingress you must set it or callbacks break.** | — |
| **Request-supplied authorization params are pinned** | `authorizationParamsOverridable` (empty by default) decides which `authorizationParams` keys an incoming request may override via query parameter. Everything not listed keeps the configured value, including `prompt`. | — |
| **Step-up authentication** | `provider.maxAuthAgeSeconds` applies to a **step-up challenge** (`unauthorizedBehavior: Challenge`): it sends `max_age` and requires a recent `auth_time` claim. A plain login is unaffected. A missing `auth_time` fails closed. Do not combine it with `provider.tokenValidation: Introspection`; RFC 7662 responses carry no `auth_time`. | — |
| **Refresh-token revocation on logout** | `provider.revokeTokensOnLogout` (default `true`) revokes the session's refresh token at the IdP on logout. Skipped when the IdP advertises no `revocation_endpoint`. | — |
| **Bounded IdP calls** | `provider.oidcTimeoutSeconds` (default `30`) puts a client-side timeout on every outbound IdP call. | — |
| **Front-channel logout requires `sid` or `id_token_hint`** | A notification carrying only `iss` is rejected. `iss` is the same for every user of that provider. | — |

`UnauthenticatedBehavior` (no credentials) and `UnauthorizedBehavior` (credentials presented but rejected) are separate settings. See [`CHANGELOG.md`](CHANGELOG.md).

## Project status

- Breaking changes are recorded in [`CHANGELOG.md`](CHANGELOG.md). Read it before upgrading.
- Security reports go through [`SECURITY.md`](SECURITY.md). Do not open a public issue for a vulnerability.
- Default `cookieNamePrefix` is `Gatepost`.
- `cmd/gatepost-extauthz` stays **experimental** even when a release image is published from a `v*` tag. A published image does not imply API stability.

## Standalone ext_authz service (experimental)

`cmd/gatepost-extauthz` runs the same OIDC logic as a standalone binary speaking Envoy's `ext_authz` protocol (HTTP or gRPC), for use behind Envoy Gateway, Istio, Contour, or any other `ext_authz`-compatible gateway. Wire it through the gateway's own mechanism (Envoy Gateway: `SecurityPolicy`). The Gateway API `ExternalAuth` filter (GEP-1494) is not implemented by the gateways checked so far; see [ADR-0005](docs/adr/0005-standalone-ext-authz-service/).

See [`docs/gatepost-extauthz.md`](docs/gatepost-extauthz.md) for:

- Running it, and the env var reference
- Which mode to use for which gateway (including a known Envoy Gateway HTTP-mode bug to avoid)
- A security review (findings fixed, findings accepted, and known gaps)

## Local development

This project uses a [Taskfile](https://taskfile.dev/). Install the Task CLI from the [official documentation](https://taskfile.dev/installation/). Docker is required for the compose workspaces.

```
task --list
```

### Traefik middleware

Keycloak is the preconfigured local IdP:

1. Run `task run:keycloak` and wait until the stack is up.
2. Open `http://localhost:9080`.
3. Log in at Keycloak as `admin` / `admin`.

For another identity provider, create `workspaces/external-idp/.env`:

```
PROVIDER_URL=...
CLIENT_ID=...
CLIENT_SECRET=...
VALIDATE_AUDIENCE=true
```

Then:

1. Run `task run:external`.
2. Open `http://localhost:9080`.

Plugin config for these stacks is `workspaces/configs/http.yml`. File changes reload automatically.

Other bundled IdPs: `task run:zitadel`, `task run:pocketid`, `task run:logto`.

### Standalone ext_authz service

```sh
CONFIG_FILE=./config.yaml LISTEN_ADDR=:9002 GRPC_LISTEN_ADDR=:9003 go run ./cmd/gatepost-extauthz
```

`GRPC_LISTEN_ADDR` is optional; unset, the gRPC listener does not start. See [`docs/gatepost-extauthz.md`](docs/gatepost-extauthz.md) for the config format, `TRUSTED_PROXIES`, and gateway wiring.

```
task test:extauthz
```

## Background

Gatepost continues work that started as a hardened fork of [sevensolutions/traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth). Releases here are independent of that project. A tag in this repository does not describe an upstream release of the same number.

Names before the rename:

| Before | After |
|---|---|
| `github.com/BlackDark/test-oidc-traefik-plugin` | `github.com/BlackDark/gatepost` |
| dynamic-config key `traefik-oidc-auth:` | `gatepost:` |
| `cmd/extauth-server` | `cmd/gatepost-extauthz` |
| default cookie prefix `TraefikOidcAuth` | `Gatepost` |

The wildcard opt-in env var is still `TOA_ENABLE_REDIRECT_URI_WILDCARDS`.

The original plugin's docs site, [traefik-oidc-auth.sevensolutions.cc](https://traefik-oidc-auth.sevensolutions.cc/), describes that project. Use [`website/docs/`](website/docs/) for Gatepost.

Provider notes that still live on the original tracker:

- Kanidm: [sevensolutions/traefik-oidc-auth#12](https://github.com/sevensolutions/traefik-oidc-auth/issues/12)
- HashiCorp Vault: [sevensolutions/traefik-oidc-auth#13](https://github.com/sevensolutions/traefik-oidc-auth/issues/13)

If this is useful, consider supporting the original author:

[![](https://img.shields.io/static/v1?label=Sponsor&color=blue&message=%E2%9D%A4&logo=GitHub)](https://github.com/sponsors/sevensolutions)
