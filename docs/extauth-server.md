# extauth-server

Standalone ext_authz service exposing this plugin's OIDC logic to any gateway that supports Envoy's `ext_authz` contract (HTTP or gRPC), not just Traefik. See [ADR-0005](adr/0005-standalone-ext-authz-service/) for why this exists and why both transports are kept.

Source: `cmd/extauth-server/`.

## Running

```sh
CONFIG_FILE=./config.yaml LISTEN_ADDR=:9002 GRPC_LISTEN_ADDR=:9003 go run ./cmd/extauth-server
```

- `CONFIG_FILE` — path to a **YAML** multi-client config (default `config.yaml`), see [Multi-client config](#multi-client-config) below. **Breaking:** the single-client JSON config is no longer supported; the process now always serves a `clients[]` map. Each entry carries the **same fields** as `.traefik.yml`'s `testData` / Traefik's dynamic plugin config (see `src/config/config.go` for all of them) under **camelCase YAML keys** — the same spelling Traefik itself uses, because both surfaces match the **Go field name** (see the casing note below). Values support `${VAR}` and `${file:/path}` expansion (same as Traefik). The two CA-bundle keys are `provider.cABundle` and `provider.cABundleFile` (note the initialism's capitals).
- `LISTEN_ADDR` — HTTP mode listener. Default `:9002`.
- `GRPC_LISTEN_ADDR` — gRPC mode listener. Unset by default (gRPC server does not start unless set).
- `SECRET_WATCH_DIRS` — optional comma-separated directories to watch (in addition to the config file's directory). Use for mounted Secret volumes so `${file:…}` rotations trigger reload.
- `SIGHUP` — triggers the same reload path as file watch.

Both modes can run simultaneously against the same Host→client map — pick whichever your gateway supports; see the compatibility table below.

## Multi-client config

One process serves many OIDC clients keyed by **Host** (exact, case-insensitive; port and one trailing FQDN dot stripped; `*.suffix` wildcards with a two-label-or-more suffix, exact wins). Unknown Host → **403**.

```yaml
clients:
  - id: grafana
    hosts:
      - grafana.example.com
    secret: ${file:/secrets/grafana/cookie-secret}   # exactly 32 chars after expand
    provider:
      url: https://idp.example.com
      clientId: grafana
      clientSecret: ${file:/secrets/grafana/client-secret}
    cookieNamePrefix: grafana
    callbackUri: /oidc/callback
    # …all other fields from src/config/config.go (Traefik camelCase YAML keys)
  - id: argo
    hosts:
      - argo.example.com
    secret: ${file:/secrets/argo/cookie-secret}
    provider:
      url: https://idp.example.com
      clientId: argo
      clientSecret: ${file:/secrets/argo/client-secret}
    cookieNamePrefix: argo
```

Rules:

- `clients` required, ≥1 entry
- Unique `id`, unique normalized hosts across clients, unique `cookieNamePrefix`, unique cookie `secret` — the uniqueness checks are **unconditional**, so two clients sharing `secret: ""` or the built-in default are rejected too, not just two clients sharing a real value.
- Hosts are normalized (lowercased, port stripped, one trailing FQDN dot stripped) and must be exact names or a whole-leftmost-label `*.suffix` wildcard whose suffix has at least two labels. A bare `*`, a `*.com`-style suffix, and a wildcard anywhere but the leftmost label are **rejected by name** at load: they match nothing (bare `*`) or silently widen to a whole public suffix (`*.com`, which this process has no public-suffix list for).
- A sub-struct explicitly set to YAML `null` (`sessionCookie:`, `authorization:`, `errorPages:`, `errorPages.unauthenticated:`, `errorPages.unauthorized:`, `authorizationHeader:`, `authorizationCookie:`, `provider:`) is **rejected with an error naming the field**, not re-defaulted. `src.New` dereferences these unconditionally, so a `null` used to panic the process; and quietly re-defaulting would contradict what the operator wrote (e.g. `authorization: null` becoming "no claim assertions"). Omit the key to get its defaults.
- No top-level shared provider/secret — everything per client
- Values support `${VAR}` and `${file:/path}` expansion (same as Traefik plugin)

**Reload:** file watch (debounced) on the config directory + `SECRET_WATCH_DIRS`, and `SIGHUP`. Bad reload keeps the previous map; bad boot exits 1. "Bad" includes **panicking**: the reload body runs under a `recover()` that logs the panic with a stack trace and keeps the previous map, so a config that triggers a bug in `src.New` can never take every tenant of the process down.

**K8s tip:** ConfigMap for the YAML; Secret volume for files under `/secrets/<id>/…`. Prefer `${file:…}` over env for secrets.

**Trust:** same-org clients in one process share blast radius. Split Deployments for cross-tenant / high-value isolation.

### Casing: why `CONFIG_FILE` keys are camelCase

`CONFIG_FILE` is decoded with `gopkg.in/yaml.v3` against the `yaml` struct tags in `src/config/config.go`, which the multi-client config sets to the **Go field name**. That is deliberately the same spelling **Traefik** uses: Traefik decodes the plugin config with `mapstructure` and **no `TagName`**, so it matches the Go field name case-insensitively and ignores the `json` tags entirely. One spelling therefore serves both surfaces — `clientId`, `callbackUri`, `maxSessionLifetimeSeconds`, `trustedProxies`, `authorizationParams`, `authorizationParamsOverridable`, `provider.maxAuthAgeSeconds`, `provider.oidcTimeoutSeconds`, `provider.cABundle`, `provider.cABundleFile`.

The yaml tags are **required** to be the lowerCamel form of the Go field name, and `TestTraefikConfigKeys/YamlTagsAreTheLowerCamelGoFieldName` in `src/config_dockeys_test.go` enforces that over every field of every config struct. This matters because yaml.v3 matches struct fields case-insensitively, so a wrong tag (e.g. `caBundle` for `CABundle`) binds here and looks fine, while Traefik's tagless mapstructure drops it with no error — and the documented remedy for a CA bundle that did not load is `insecureSkipVerify`, i.e. a wrong tag silently pushes operators onto the weaker control. Note the Go field names `CABundle`/`CABundleFile` take the initialism's capitals: the camelCase key is **`cABundle`**, not `caBundle`.

The snake_case `json` tags (eg. `log_level`, `callback_uri`, `provider.client_id`) are **not** valid `CONFIG_FILE` keys. They are decoded only on the historical single-client JSON path, which this release removed. See the casing note in [`website/docs/getting-started/middleware-configuration.md`](../website/docs/getting-started/middleware-configuration.md#plugin-config-block).

:::note Boolean provider options work under either name in YAML
The `bool`-typed provider options (`usePkce`, `validateAudience`, `validateIssuer`, `validateNonce`, `useClaimsFromUserInfo`, `insecureSkipVerify`, and `revokeTokensOnLogout`) are declared in Go as a **string** field plus a separate `bool` field carrying the `Bool` suffix — see `RevokeTokensOnLogout string` / `RevokeTokensOnLogoutBool bool` in `src/config/config.go`. The **string** field exists only to serve Traefik's weakly-typed `mapstructure` decoder and `${VAR}` expansion; `src.New` then expands it into the `bool` field with `ExpandEnvironmentVariableBoolean`, which accepts `true`/`false`/`1`/`0`.

In YAML both spellings therefore work and mean the same thing: `revokeTokensOnLogout: true` (a native YAML boolean) is accepted by the string field, and `revokeTokensOnLogoutBool: true` sets the boolean directly. The string form additionally supports `"${FLAG}"` env expansion. (The removed single-client JSON path was strictly typed and required the `_bool` key; there is no such requirement on the YAML surface.)
:::

:::note There is no `trustedProxies` in this example on purpose
`trustedProxies` is a real config key, but in **HTTP mode it does nothing**: `cmd/extauth-server` gates the `X-Forwarded-*` rewrite on the **`TRUSTED_PROXIES` environment variable** (parsed in `main.go`, checked against the TCP peer address in `forwardedRequest`), not on the config key. This is a **different mechanism**, not a second spelling of one — see [`TRUSTED_PROXIES`](#trusted-proxies-http-mode-only) below. The Traefik plugin, by contrast, reads the `trustedProxies` config key.
:::

## Network exposure

`extauth-server` is called only by the gateway (Traefik/Envoy Gateway) — never directly by browsers or API clients. The gateway calls it internally on every request, then relays the allow/deny decision back to the actual client as if it came from the protected backend. Expose it via `ClusterIP` only; it needs no public listener, ingress, or externally-resolvable name. Restrict ingress to the gateway's namespace/pods with a `NetworkPolicy` — this is defense-in-depth alongside `TRUSTED_PROXIES` below, not a substitute for it (see Security review).

## `TRUSTED_PROXIES` (HTTP mode only)

:::caution This is not the `trustedProxies` config key
`extauth-server` reads the trusted-proxy allowlist **only** from the `TRUSTED_PROXIES` **environment variable** — `parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))` in `cmd/extauth-server/main.go`. The `trustedProxies` key in `CONFIG_FILE` has no effect on this path: it is decoded into `config.TrustedProxies`, which HTTP mode's `forwardedRequest()` never consults. The Traefik plugin, by contrast, is gated by the `trustedProxies` **config key** and has no environment variable. Two surfaces, two mechanisms — setting one does not set the other.
:::

HTTP mode's `X-Forwarded-Method`/`X-Forwarded-Proto`/`X-Forwarded-Host`/`X-Forwarded-Uri` headers are only honored when the request's TCP peer address matches an entry in `TRUSTED_PROXIES` — a comma-separated list of IPs and/or CIDR ranges (e.g. `TRUSTED_PROXIES=10.42.0.0/16` for a typical pod CIDR, or the specific IP(s) of your gateway's pods/Service). **Unset by default — meaning `X-Forwarded-*` headers are never honored from anyone**, and the server logs a startup warning. This is deliberately fail-closed: get the gateway's source CIDR right, or HTTP mode will treat every request as its own literal request (no path/method rewriting), which is safe but breaks routing for gateways that rely on those headers (Traefik `forwardAuth`).

Without this, any caller that can reach the listener directly could set `X-Forwarded-Uri: /oidc/callback?...` and reach callback-only code paths regardless of what was actually requested — the same vulnerability class as [CVE-2026-40575](https://nvd.nist.gov/vuln/detail/CVE-2026-40575) in oauth2-proxy (unconditionally trusting `X-Forwarded-Uri` when reverse-proxy mode is enabled, with no source-address check). gRPC mode is unaffected — `CheckRequest`'s structured attributes carry the real method/path directly, there is no header to spoof.

Example: if your gateway's pods run with the cluster's pod CIDR (typical for Cilium/Calico), set `TRUSTED_PROXIES` to that CIDR. If you'd rather pin to the gateway's exact Service/pod IPs, use those instead (tighter, but breaks if the gateway is rescheduled onto a new IP without a corresponding config update — a CIDR covering the expected range is usually more operable).

## Which mode to use

| Gateway | Mode | Status |
|---|---|---|
| Traefik `forwardAuth` middleware | HTTP | Works. Verified end-to-end (real login) on live infra. |
| Envoy Gateway `SecurityPolicy.extAuth.http` | HTTP | **Broken for redirect-based login** — Envoy strips `Location`/`Set-Cookie` on denied responses ([envoyproxy/gateway#8202](https://github.com/envoyproxy/gateway/issues/8202), open, no fix). Non-redirect flows (pure Bearer-token APIs that only need 200/401/403) are unaffected. |
| Envoy Gateway `SecurityPolicy.extAuth.grpc` | gRPC | Works, including redirect-based login. Verified end-to-end (real login) on live infra. **Recommended for Envoy Gateway.** |
| Gateway API `ExternalAuth` HTTPRoute filter (GEP-1494) | — | Not usable — not implemented by Envoy Gateway or any other checked implementation as of writing ([envoyproxy/gateway#8422](https://github.com/envoyproxy/gateway/issues/8422), open, Backlog). |

If your gateway calls the auth backend with a fixed address and describes the real request via `X-Forwarded-Method`/`X-Forwarded-Proto`/`X-Forwarded-Host`/`X-Forwarded-Uri` headers (Traefik's convention), HTTP mode's `forwardedRequest()` adapter handles that automatically. If your gateway sends the real request line/structured attributes directly (Envoy's own HTTP or gRPC ext_authz), HTTP mode also works without the adapter doing anything (it falls back to using the request as received), and gRPC mode works natively since `CheckRequest` is already structured.

## Example: Traefik `forwardAuth`

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: extauth-forward
spec:
  forwardAuth:
    address: http://extauth-server.<namespace>.svc.cluster.local:9002/
    authResponseHeaders:
    - X-Auth-Sub
    - X-Auth-Email
```

## Example: Envoy Gateway `SecurityPolicy` (gRPC)

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: extauth
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: <your-route>
  extAuth:
    grpc:
      backendRefs:
      - name: extauth-server
        port: 9003
```

`headersToBackend` is not needed in gRPC mode — the equivalent (which headers reach the protected backend on allow) is controlled entirely by this plugin's own `config.headers` (see `src/config/config.go`'s `HeaderConfig`), since `OkHttpResponse.Headers` always carries whatever `attachHeaders()` set.

## Security review

Reviewed 2026-07-31 alongside the gRPC mode addition. Findings and fixes below; anything not listed was checked and found acceptable.

### Fixed during this review

- **grpc-go authz bypass (GO-2026-4762)** — `google.golang.org/grpc@v1.78.0` had a known vulnerability ("Authorization bypass in gRPC-Go via missing leading slash in `:path`"), directly relevant to an authorization service. Bumped to `v1.82.1`. Also picked up a fix for GO-2026-6061 (xDS RBAC / HTTP2 transport). Verified via `govulncheck ./cmd/...` — 0 vulnerabilities in code actually called.
- **Process-wide crash on panic** — grpc-go's default behavior is to crash the entire server on a handler panic (unlike `net/http`, which only aborts the one connection — [grpc-go#441](https://github.com/grpc/grpc-go/issues/441), by design, not going to change). Since `TraefikOidcAuth.ServeHTTP` has many code paths (JWT parsing, template rendering with user-controlled claims, JSON decoding), a single malformed or unexpected request could otherwise take the whole auth service offline. Added `recoveryInterceptor` (`grpc.UnaryInterceptor`) that recovers and returns a generic internal error instead. Covered by `TestRecoveryInterceptor_ConvertsPanicToError`.
- **No socket-level timeouts** — both the HTTP listener and (implicitly, via `grpc.ConnectionTimeout`) the gRPC listener previously had no read/write/idle timeouts, leaving them exposed to slow-client resource exhaustion (slowloris-style). Added `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout` to the HTTP server and `grpc.ConnectionTimeout` to the gRPC server.
- **Integer overflow risk (gosec G115)** — `typev3.StatusCode(result.StatusCode)` cast an `int` to an `int32`-backed enum without bounds checking. Not exploitable today (status codes are always small), but a malformed/unexpected upstream value could wrap. Added an explicit bounds check (100–599) before the cast, falling back to 500.
- **Path traversal flag (gosec G703)** on `os.ReadFile(path)` in `loadConfig` — `path` comes from `CONFIG_FILE`, operator-supplied deployment config, not attacker-controlled network input. Confirmed as a false positive for this threat model and suppressed with a documented `//nolint` (scoped to the one line, not the whole linter/package), matching the project's existing convention in `.golangci.yml` for `src/`'s own documented gosec exclusions.
- **`gosec` noctx** — `net.Listen` replaced with `net.ListenConfig.Listen` for consistency with lint expectations (no behavioral difference for a long-lived listener).
- **Unconditional trust of `X-Forwarded-*` headers (HTTP mode)** — any caller reaching the listener directly could spoof `X-Forwarded-Uri` to redirect routing to an arbitrary path (same vulnerability class as oauth2-proxy's [CVE-2026-40575](https://nvd.nist.gov/vuln/detail/CVE-2026-40575)). Added `TRUSTED_PROXIES` (CIDR/IP allowlist checked against the request's peer address) gating whether these headers are honored at all; unset by default = never trusted, fail-closed. See the `TRUSTED_PROXIES` section above. Covered by `TestForwardedRequest_IgnoresHeadersFromUntrustedPeer` and `TestForwardedRequest_NoTrustedProxiesConfigured_NeverHonorsHeaders`.

### Reviewed and accepted as-is

- **Sessions are stateless** (`src/session/cookieSessionStorage.go` — encrypted into the session cookie via each client's `secret`, no server-side store). Horizontally scalable as long as all replicas mount the same multi-client config and secrets.
- **Host-keyed multi-client:** Unknown Host → 403 (no default client). Tenant selection security depends on gateway-only reachability (`NetworkPolicy`) and a narrow `TRUSTED_PROXIES` for HTTP mode — Host / `X-Forwarded-Host` chooses which OIDC client config applies. Split Deployments for untrusted / cross-tenant clients.
- **JWKS/OIDC-discovery caching** is per client handler (`src.New` once per client). HTTP and gRPC share the same Host→handler map, so a given client uses one discovery/JWKS cache.
- **`httptest.NewRecorder()` per gRPC request** — in-memory buffer, no I/O, negligible overhead; this is the standard way to capture an `http.ResponseWriter`'s output without a real network hop, and is the correct choice here since `TraefikOidcAuth.ServeHTTP` writes directly to a `ResponseWriter` and cannot be restructured to return a response value without touching the core `src` package (out of scope, and would diverge Traefik-mode behavior from ext_authz-mode behavior).
- **Cookie header reconstruction in gRPC mode** (`buildHTTPRequest`, splitting merged header values on `,`) — correct for the common case. Envoy's `AttributeContext.HttpRequest.headers` map merges same-key headers with a comma per the HTTP spec; cookie-pairs cannot legally contain a literal comma (RFC 6265 `cookie-octet` grammar excludes it), so splitting a merged `Cookie` value back apart on `,` cannot corrupt a well-formed single `Cookie:` header (the overwhelmingly common case: one `Cookie` header, `;`-separated pairs, no comma splitting applied since there's nothing to split). Only a theoretical concern for non-conformant clients that send multiple raw `Cookie:` lines, which is a client bug, not a gap in this code.
- **gRPC message size limits** — not set explicitly; grpc-go's default max receive size (4 MiB) already bounds request size at the transport layer before it reaches `buildHTTPRequest`.

### Known gaps (not fixed — flagged, needs a decision before production use)

- **`extauth-server` is never reached directly by browsers/clients — only by the gateway.** The gateway (Traefik/Envoy Gateway) is always the intermediary: it calls `extauth-server` internally and relays the decision back to the client as if it came from the protected backend. This changes the risk calculus for the next two points — they're acceptable specifically because the network path is gateway-to-auth-server, not internet-to-auth-server. Expose only via `ClusterIP` (not `NodePort`/`LoadBalancer`); the `NodePort` used during live testing was solely to make the *gateway's* data plane reachable externally for the test, not `extauth-server` itself, which stayed `ClusterIP` throughout.
- **No TLS on either listener.** Acceptable because the only real client is the gateway over cluster-internal networking (see above), not because TLS never matters. Still not fine if the ext_authz call crosses a genuine trust boundary (e.g. a shared/multi-tenant cluster where other namespaces might route traffic through your gateway's network path, or the gateway and auth server sit in different clusters). Envoy Gateway supports `BackendTLSPolicy` for ext_authz backends (both HTTP and gRPC); not implemented here. Add if deploying across such a boundary.
- **Recommendation not yet enforced by manifests in this repo: restrict ingress to `extauth-server` with a `NetworkPolicy`** allowing only the gateway's namespace/pods, mirroring the pattern this cluster already uses for protected backends (`allow-ingress-from-traefik`-style policies). `TRUSTED_PROXIES` (see above) covers the HTTP-mode header-spoofing angle specifically; a `NetworkPolicy` is still worth adding as defense-in-depth against anything else reaching the service (gRPC mode, or an HTTP-mode caller inside the trusted CIDR that isn't actually the gateway).
- **No rate limiting / request body size cap** at the HTTP-mode listener (gRPC mode inherits grpc-go's 4 MiB default; HTTP mode has none). Lower risk under the gateway-only assumption (the gateway is a single, mostly-trusted caller, not the open internet), but worth tracking if that assumption ever changes.

### Verified but out of scope to fix (pre-existing in `src/`)

Confirmed no unbounded request-body reads or missing size limits were introduced by `cmd/extauth-server` beyond what `src/main.go`'s `ServeHTTP` already does for the Traefik plugin path. Any fix there belongs to the core package, not this wrapper.
