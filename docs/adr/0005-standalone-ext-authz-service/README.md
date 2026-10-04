# 0005. Standalone ext_authz service (`cmd/gatepost-extauthz`)

**Status:** Accepted
**Date:** 2026-07-31

## Context

The core OIDC logic in `src/` (session handling, PKCE, token validation, claims-based authorization, redirect flows) is coupled to Traefik only through `New(ctx, next, cfg, name) (http.Handler, error)` and the yaegi-interpretable `main.go`/`config.go` glue. `src/oidc`, `src/session`, `src/rules`, `src/predicate`, `src/utils`, `src/errorPages` have no Traefik-specific dependencies.

Gateway API's `ExternalAuth` HTTPRoute filter (GEP-1494, Experimental since v1.4) and Envoy's `ext_authz` filter (which most gateways — Envoy Gateway, Istio, Contour, oauth2-proxy consumers — implement in some form) standardize on a generic "call an external service, get an allow/deny decision" contract. If this plugin's logic were exposed behind that contract instead of only Traefik's plugin API, it would work behind any ext_authz-compatible gateway, not just Traefik.

Two ext_authz transports exist, verified against real infrastructure ([Envoy Gateway](https://gateway.envoyproxy.io/latest/tasks/security/ext-auth/) + Traefik `forwardAuth`, tested live on a k3s cluster):

- **HTTP mode** — the auth server receives a plain HTTP request describing the client's request (either via the real request line, or via `X-Forwarded-*` headers depending on the gateway) and responds with a normal HTTP response.
- **gRPC mode** — the auth server implements `envoy.service.auth.v3.Authorization/Check`, receiving a structured `CheckRequest` and returning a structured `CheckResponse` (`OkResponse` or `DeniedResponse`).

## Decision

1. Add `cmd/gatepost-extauthz`, a separate `main` package that calls `src.New(...)` unchanged and exposes it over both transports:
   - **HTTP mode** (`LISTEN_ADDR`, default `:9002`) — wraps the handler in `forwardedRequest()`, which rewrites `req.Method`/`req.URL`/`req.RequestURI` from `X-Forwarded-Method/Proto/Host/Uri` headers before calling `ServeHTTP`. This is required for gateways (confirmed: Traefik `forwardAuth`) that always call the auth backend at a fixed address and describe the real request only via headers.
   - **gRPC mode** (`GRPC_LISTEN_ADDR`, opt-in — only starts if the env var is set) — implements `authv3.AuthorizationServer.Check`, reconstructing an `*http.Request` directly from `CheckRequest.Attributes.Request.Http` (structured fields, no header parsing needed), running it through the same handler via `httptest.NewRecorder()`, and translating the captured response into `OkResponse`/`DeniedResponse`.
2. Both modes share one `Gatepost` instance (one `src.New(...)` call in `main()`), so JWKS caching, OIDC discovery caching, and config are identical regardless of which transport a given gateway uses.
3. `next` (what `ServeHTTP` calls on "allow") is a single stub that copies the request's headers (mutated in place by `attachHeaders`) onto the response — this is what tells the gateway which headers to inject into the real upstream call. Deny/redirect responses are already fully-formed by `ServeHTTP` (status, headers incl. `Location`/`Set-Cookie`, body) and pass through as-is.

### Why gRPC mode exists (not just HTTP mode)

HTTP mode was implemented first and works correctly against Traefik's `forwardAuth`. Testing against Envoy Gateway's `SecurityPolicy` (HTTP mode) surfaced a real, currently-open upstream bug: Envoy's `ext_authz` HTTP filter only forwards response headers on **denial** if `allowed_client_headers` is configured, and Envoy Gateway's `SecurityPolicy` CRD has no field mapping to it ([envoyproxy/gateway#8202](https://github.com/envoyproxy/gateway/issues/8202), open, no fix version). Effect: `Location` and `Set-Cookie` are silently dropped on the 302-to-IdP redirect, breaking the entire login flow for any redirect-based ext_authz provider (this plugin, oauth2-proxy, Authentik, Authelia) run behind Envoy Gateway's HTTP-mode `SecurityPolicy`.

gRPC mode's `DeniedHttpResponse.Headers` is the full, explicit response the auth server hands back — there is no separate allowlist step, so this class of bug does not exist in gRPC mode. Verified live: gRPC mode through Envoy Gateway `SecurityPolicy` correctly preserves `Location` + multiple `Set-Cookie` headers on the redirect-to-IdP response, and a full login round-trip (redirect → Pocket ID login → callback → session → `X-Auth-Sub`/`X-Auth-Email` injected into the request reaching the protected backend) completed successfully.

### GEP-1494 `ExternalAuth` filter — not used

The standard Gateway API filter (as opposed to Envoy Gateway's vendor-specific `SecurityPolicy`) is not implemented by Envoy Gateway as of v1.8.3 ([envoyproxy/gateway#8422](https://github.com/envoyproxy/gateway/issues/8422), open, "Backlog" milestone, no committed timeline) or by any other gateway checked. `SecurityPolicy` was used instead since it is the only implementation that actually exists today.

## Consequences

**Good:**
- Same core OIDC/session/authz logic now usable behind Traefik (native middleware or `forwardAuth`), Envoy Gateway (`SecurityPolicy`, gRPC mode), and any other ext_authz-HTTP-compatible gateway, without duplicating logic.
- Sessions are fully stateless (encrypted into the cookie via `config.Secret`, see `src/session/cookieSessionStorage.go`), so `gatepost-extauthz` scales horizontally with no shared state — any replica can serve any request as long as they share the same `secret`.
- Panic in a single request (`recoveryInterceptor` in gRPC mode) does not take down the process — grpc-go's default behavior otherwise crashes the whole server on a handler panic, unlike `net/http`.

**Bad / follow-ups:**
- New dependency: `github.com/envoyproxy/go-control-plane/envoy` + `google.golang.org/grpc` (pinned ≥v1.82.1 — v1.78.0 had [GO-2026-4762](https://pkg.go.dev/vuln/GO-2026-4762), an authz bypass via missing leading slash in `:path`, directly relevant to an authz service). Pulls `vendor/` from 424K to ~19M. HTTP mode alone would not need this; accepted because gRPC mode is the only working fix for the Envoy Gateway redirect bug above.
- Neither listener terminates TLS. Envoy's own docs call TLS "optional but recommended" for ext_authz backends; not implemented here. Acceptable only when the network path between gateway and `gatepost-extauthz` is already trusted (e.g. same-cluster ClusterIP, no cross-boundary hop). Flagged as a gap, not a decision — add `BackendTLSPolicy` support if this crosses a trust boundary in a real deployment.
- HTTP mode's `forwardedRequest()` only honors `X-Forwarded-*` headers from peers matching `TRUSTED_PROXIES` (CIDR/IP allowlist, unset by default = never trusted). Added after initial implementation once it was clear the unconditional-trust version was the same vulnerability class as oauth2-proxy's [CVE-2026-40575](https://nvd.nist.gov/vuln/detail/CVE-2026-40575). See `docs/gatepost-extauthz.md` for details.
- HTTP mode still exists and still has value (Traefik `forwardAuth`, any future ext_authz-HTTP-compatible gateway that doesn't hit the header-stripping bug) — kept, not replaced by gRPC mode.
