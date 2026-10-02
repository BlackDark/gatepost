# OIDC Auth: Traefik Middleware + Standalone ext_authz Service

[![E2E Tests](https://img.shields.io/github/actions/workflow/status/BlackDark/test-oidc-traefik-plugin/.github%2Fworkflows%2Fe2e-tests.yml?logo=github&label=E2E%20Tests&color=green)](https://github.com/BlackDark/test-oidc-traefik-plugin/actions/workflows/e2e-tests.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/BlackDark/test-oidc-traefik-plugin/blob/main/LICENSE)

<p align="left" style="text-align:left;">
  <a href="https://github.com/BlackDark/test-oidc-traefik-plugin">
    <img alt="Logo" src=".assets/icon.png" width="150" />
  </a>
</p>

This repo secures upstream services with OpenID Connect (acting as an OIDC relying party), in two forms sharing one core implementation:

1. **Traefik middleware plugin** (`src/`) — the primary, mature component. A hardened fork of [sevensolutions/traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth) (sealed OIDC state, PKCE-in-state, login CSRF, nonce, safer defaults — see `docs/adr/` and the delta list under [📚 Documentation](#-documentation)). This is what Traefik's plugin catalog loads.
2. **Standalone ext_authz service** (`cmd/extauth-server/`) — **experimental.** Exposes the same OIDC/session/authorization logic behind Envoy's `ext_authz` contract (HTTP and gRPC modes), so it can run behind any gateway that speaks that protocol — Envoy Gateway's `SecurityPolicy`, and in the future the standardized [Gateway API `ExternalAuth` filter (GEP-1494)](https://gateway-api.sigs.k8s.io/geps/gep-1494/) once an implementation actually supports it — not just Traefik. See [`docs/extauth-server.md`](docs/extauth-server.md) for usage, gateway compatibility, and a security review.

Both share the same core packages (`src/oidc`, `src/session`, `src/rules`, `src/predicate`, `src/utils`) — one codebase, two transports, kept as one repo deliberately (see [ADR-0005](docs/adr/0005-standalone-ext-authz-service/) for why).

> [!NOTE]
> This document always represents the latest version, which may not have been released yet.
> Therefore, some features may not be available currently but will be available soon.
> You can use the GIT-Tags to check individual versions.

> [!WARNING]
> The Traefik middleware is under active development and breaking changes may occur. It is only tested against Traefik v3+.
>
> The standalone ext_authz service (`cmd/extauth-server`) is **experimental** — functionally verified end-to-end against real infrastructure (Traefik `forwardAuth` and Envoy Gateway `SecurityPolicy`, both HTTP and gRPC modes, with real IdP logins), but newer and less battle-tested than the Traefik middleware itself. See its docs for known gaps before running it in production.

## Traefik middleware

Used as a Traefik plugin (`import: github.com/BlackDark/test-oidc-traefik-plugin/src` in Traefik's static/plugin config). All hardening decisions are recorded in [`docs/adr/`](docs/adr/).

### Tested Providers

| Provider | Status | Notes |
|---|---|---|
| [ZITADEL](https://zitadel.com/) | ✅ | |
| [Kanidm](https://github.com/kanidm/kanidm) | ✅ | See upstream [GH-12](https://github.com/sevensolutions/traefik-oidc-auth/issues/12) |
| [Keycloak](https://github.com/keycloak/keycloak) | ✅ | |
| [Microsoft EntraID](https://learn.microsoft.com/de-de/entra/identity/) | ✅ | |
| [HashiCorp Vault](https://www.vaultproject.io/) | ❌ | See upstream [GH-13](https://github.com/sevensolutions/traefik-oidc-auth/issues/13) |
| [Authentik](https://goauthentik.io/) | ✅ | |
| [Pocket ID](https://github.com/pocket-id/pocket-id) | ✅ | |
| [GitHub](https://github.com) | ❌ | GitHub doesn't seem to support OIDC, only plain OAuth. |
| [Logto](https://logto.io/) | ✅ | |

### 📚 Documentation

The Traefik middleware's config reference and usage docs are built from the upstream project this fork is based on: [traefik-oidc-auth.sevensolutions.cc](https://traefik-oidc-auth.sevensolutions.cc/). **That site describes upstream, not this fork** — treat it as the baseline and assume no fork-local behaviour unless it is listed below. Fields and behaviors added by this fork's hardening work are documented in [`docs/adr/`](docs/adr/), since they diverge from upstream.

### Fork hardening delta (not in upstream)

These behaviours exist only in this fork. The upstream docs site will not mention them.

| Behaviour | What it does | ADR |
|---|---|---|
| **Sealed OIDC `state`** | The whole `state` parameter is AES-GCM-sealed with the plugin secret, so its contents can be neither read nor forged by the browser. | [0002](docs/adr/0002-sealed-oidc-state/) |
| **PKCE `code_verifier` in `state`** | The verifier rides encrypted inside the sealed `state` instead of a shared cookie, fixing verifier clobbering when parallel requests start parallel logins. | [0001](docs/adr/0001-pkce-verifier-in-oidc-state/) |
| **Login CSRF cookie binding** | The login flow is bound to a CSRF cookie, so an attacker cannot force a victim's browser into an attacker-chosen authorization flow. | [0003](docs/adr/0003-login-csrf-binding/) |
| **`nonce` validation** | ID tokens are required to carry and match the `nonce` sent on the authorize request. | [0004](docs/adr/0004-oidc-nonce/) |
| **Redirect URI wildcards are opt-in** | Wildcard `redirectUri` templates are ignored entirely unless `TOA_ENABLE_REDIRECT_URI_WILDCARDS=true`. Once enabled, exact entries always match and wildcard templates get strict host/path matching plus spoofing and traversal guards. Callback re-validation uses the same matcher. | — (opt-in, defaults off) |
| **`${file:/path}` secrets** | Any secret value may be loaded from a file at render time, keeping it out of the rendered Traefik configuration. | — |
| **`secret` must be exactly 32 bytes** | A wrong-length `secret` is rejected at startup instead of silently weakening the sealed state. | [0002](docs/adr/0002-sealed-oidc-state/) |

Also fork-local and **breaking** since `v0.20.0`: `UnauthorizedBehavior` is split into `UnauthenticatedBehavior` (no credentials presented) and `UnauthorizedBehavior` (credentials presented but rejected). See [`CHANGELOG.md`](CHANGELOG.md).

## Project status / versioning

- This is a **fork** of [sevensolutions/traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth), not a drop-in mirror of it. The two projects release independently and do not coordinate.
- **Fork tags are independent of upstream tags.** A `v0.22.0` in this repository is a fork release with no upstream counterpart; an upstream tag of the same number may describe entirely different code. Never assume the two line up.
- **Breaking changes are recorded in [`CHANGELOG.md`](CHANGELOG.md)** and marked explicitly with a **BREAKING CHANGE** note. Read it before upgrading across minor versions.
- Security reports go through the private channels in [`SECURITY.md`](SECURITY.md) — not upstream's, and not a public issue.
- `github.com/BlackDark/test-oidc-traefik-plugin` is a **placeholder** repo/module name pending a final organisation rename. If you depend on it, expect the import path to change; pin a specific version and re-check this section when you upgrade.
- The standalone `ext_authz` service (`cmd/extauth-server`) remains **experimental** even though a release image is published from `v*` tags. A published image does not imply API stability.

## Standalone ext_authz service (experimental)

`cmd/extauth-server` runs the same OIDC logic as a standalone binary speaking Envoy's `ext_authz` protocol (HTTP or gRPC), for use behind Envoy Gateway, Istio, Contour, or any other `ext_authz`-compatible gateway — anything that isn't Traefik. Intended primarily as a path toward Gateway API's standardized external-auth filter once a real implementation of it exists (currently unimplemented everywhere checked — see [ADR-0005](docs/adr/0005-standalone-ext-authz-service/)); today, wire it via each gateway's own vendor-specific mechanism (e.g. Envoy Gateway's `SecurityPolicy`).

See [`docs/extauth-server.md`](docs/extauth-server.md) for:
- Running it, and env var reference
- Which mode to use for which gateway (with a known, currently-unfixed Envoy Gateway HTTP-mode bug to avoid)
- A full security review (findings fixed, findings accepted as-is, and known gaps)

## 🧪 Local Development and Testing

This project uses a [Taskfile](https://taskfile.dev/) for easy access to commonly used tasks. You need to install the Taskfile CLI by following the [official documentation](https://taskfile.dev/installation/). You also need Docker installed on your machine.

You can then run the following command to list all available tasks:

```
task --list
```

### Traefik middleware

The easiest way to get started is to run the plugin with Keycloak because this repo comes with a pre-configured instance.
Just do:

1. Run `task run:keycloak` and wait a moment for everything to be settled
2. Open a web browser and navigate to `http://localhost:9080`
3. You will be redirected to Keycloak's login page. Log in with user `admin` and password `admin`.


If you want to start the plugin with your own identity provider, create the following `.env` file in `workspaces/external-idp`:

```
PROVIDER_URL=...
CLIENT_ID=...
CLIENT_SECRET=...
VALIDATE_AUDIENCE=true
```

And then do:
1. Run `task run:external`
2. Open a web browser and navigate to `http://localhost:9080`
3. You will be redirected to your own identity provider

If you want to play around with the plugin config, modify the file `workspaces/configs/http.yml`.
Changes will be reloaded automatically and you should see some debug output in the container logs.

### Standalone ext_authz service

```sh
CONFIG_FILE=./config.json LISTEN_ADDR=:9002 GRPC_LISTEN_ADDR=:9003 go run ./cmd/extauth-server
```

See [`docs/extauth-server.md`](docs/extauth-server.md) for config format, `TRUSTED_PROXIES`, and gateway-specific wiring examples (Traefik `forwardAuth`, Envoy Gateway `SecurityPolicy`).

Run its test suite from `cmd/extauth-server`:

```
task test:extauth
```

## Attribution

The Traefik middleware in `src/` is a fork of [sevensolutions/traefik-oidc-auth](https://github.com/sevensolutions/traefik-oidc-auth). Credit to the original author for the base implementation; this fork's changes (security hardening in `docs/adr/`, and the standalone `cmd/extauth-server` service) are independent additions on top of it, not upstream contributions — if you're looking for the original project, go there.

## ☕ Support

If you find this useful, consider supporting the original upstream project, whose work this fork builds on:

[![](https://img.shields.io/static/v1?label=Sponsor&color=blue&message=%E2%9D%A4&logo=GitHub)](https://github.com/sponsors/sevensolutions)

