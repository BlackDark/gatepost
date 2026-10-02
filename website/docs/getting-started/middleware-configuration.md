---
sidebar_position: 3
---

# Middleware Configuration

## Plugin Config Block

:::warning Config key casing — camelCase, on every surface
Traefik decodes the plugin config with `mapstructure` and **no `TagName`**, so it matches the **Go struct field name case-insensitively and ignores the `json` and `yaml` struct tags entirely**. Traefik YAML must therefore use **camelCase**. Legacy PascalCase (`Secret`, `ClientId`) works for the same reason. A snake_case key is not a synonym — it decodes to the field's zero value, so the option looks configured and silently does nothing.

`cmd/extauth-server`'s `CONFIG_FILE` is a **YAML multi-client** file (the single-client JSON form was removed), decoded with `gopkg.in/yaml.v3` against the `yaml` struct tags in `src/config/config.go`. Those tags are set to the **same lowerCamel Go field name** Traefik matches, so **one spelling serves both surfaces** — you can copy a key straight out of this reference into `CONFIG_FILE`. `src/config_dockeys_test.go` enforces that invariant over every field of every config struct, so the two surfaces cannot drift apart again.

There is deliberately **no second column any more**: the snake_case `json` tags (`log_level`, `callback_uri`, `provider.client_id`, …) are not valid keys on either surface. Do not use them.

Every `bool` provider option is declared in Go as a `string` field plus a separate `bool` field with a `Bool` suffix (`src/config/config.go`). The string field exists to serve Traefik's weakly-typed `mapstructure` decoder and `${VAR}` expansion; `src.New` expands it into the `bool` field with `ExpandEnvironmentVariableBoolean`, which accepts `true`/`false`/`1`/`0`. That covers `revokeTokensOnLogout`, `usePkce`, `insecureSkipVerify`, `validateAudience`, `validateIssuer`, `validateNonce` and `useClaimsFromUserInfo`.

Write the plain camelCase name with a **string** value on the Traefik path (`revokeTokensOnLogout: "true"`), as every example in this reference does. In `CONFIG_FILE` you may additionally use a native YAML boolean. The `Bool`-suffixed keys are deliberately **not** listed as options here — they exist for the `CONFIG_FILE` YAML surface, not for Traefik; see [`docs/extauth-server.md`](https://github.com/BlackDark/test-oidc-traefik-plugin/blob/main/docs/extauth-server.md#multi-client-config).

Three guardrails **do** fail loudly with the correct camelCase spelling, and are your safety net that a misspelled key was caught rather than silently dropped: `provider.tokenValidation` and `sessionStorageType` are rejected at startup when invalid, and `provider.maxAuthAgeSeconds` / `maxSessionLifetimeSeconds` / `sessionIdleTimeoutSeconds` are rejected when negative. A wrong **spelling**, by contrast, is never rejected — see the note below on snake_case.

- **`trustedProxies` is a different mechanism on `extauth-server`, not a spelling.** `cmd/extauth-server` gates the `X-Forwarded-*` rewrite on the `TRUSTED_PROXIES` environment variable (`parseTrustedProxies(os.Getenv(...))`, checked against the TCP peer in `forwardedRequest`). The `trustedProxies` key in `CONFIG_FILE` decodes into `config.TrustedProxies` and is **never read on that path**. Put the allowlist in the environment, not the file. See [`docs/extauth-server.md`](https://github.com/BlackDark/test-oidc-traefik-plugin/blob/main/docs/extauth-server.md#trusted_proxies-http-mode-only).

A YAML `null` on a sub-struct (`sessionCookie:`, `authorization:`, `errorPages:`, `errorPages.unauthenticated:`/`errorPages.unauthorized:`, `authorizationHeader:`, `authorizationCookie:`, `provider:`) is **rejected** with an error naming the field rather than defaulted, so a hot reload fails closed and keeps the previous config. Omit the key to get its defaults.

Everything in this reference is **camelCase**, because both surfaces now accept only that.
:::

:::warning Upgrading from a single `unauthorizedBehavior`
Starting with this fork's `v0.20.0`, the single `unauthorizedBehavior` option that previously controlled the response for both unauthenticated requests (no/invalid session, HTTP 401) and unauthorized requests (valid session, but failing the `authorization` rules, HTTP 403) has been split into two separate options:

- `unauthenticatedBehavior` now controls the 401 case.
- `unauthorizedBehavior` now controls only the 403 case.

If you're upgrading from a pre-split config (legacy single `unauthorizedBehavior`), move your existing value as-is to `unauthenticatedBehavior` to keep the same unauthenticated behavior. No change is needed for the 403 case unless you want to opt into `Challenge` there (e.g. step-up authentication; see [`authorizationParams`](#plugin-config-block) and [Authorization](./authorization.md)). Legacy configs that only set `unauthorizedBehavior` are also migrated automatically at startup.
:::

:::warning Redirect URI wildcard migration
Redirect URI wildcards (including a bare `*`) now require explicitly setting `TOA_ENABLE_REDIRECT_URI_WILDCARDS=true` on the Traefik process. Without it, all allowlist entries are matched exactly, as required by OIDC/OAuth2. See [Redirect URI Wildcards](#redirect-uri-wildcards).
:::

:::danger Upgrading behind an ingress — set `trustedProxies`
Absolute URLs built from the request — the `redirect_uri` sent to the IDP above all — now ignore `X-Forwarded-Proto` and `X-Forwarded-Host` unless the request arrived from a proxy in [`trustedProxies`](#trusted-proxies). The default list is **empty**, i.e. trust nothing.

If Traefik is behind an ingress, load balancer or CDN, you **must** add that hop's CIDR or your callbacks break with a `redirect_uri` mismatch. See [Trusted Proxies](#trusted-proxies).
:::

:::warning Other behaviour changes on upgrade
- Session cookies sealed before this version are still accepted through a narrow legacy fallback and re-sealed with the new purpose on the next renewal. The fallback will be removed in a later release, after which every session must be re-established through a fresh login.
- The OIDC `state` parameter now expires after **10 minutes**. A login left idle at the IDP for longer must be restarted.
- Front-channel logout now requires `sid` **or** `id_token_hint`; `iss` alone is rejected. See [Front-Channel Logout](#front-channel-logout).
- `provider.tokenValidation` and `sessionStorageType` are rejected at startup when invalid instead of failing at request time.
:::

:::caution
It is highly recommended to change the default encryption-secret by providing your own 32-character secret using the `secret`-option.
You can generate a random one here: https://it-tools.tech/token-generator?length=32
:::

:::tip
Every property marked with a * also supports environment variables when enclosed with `${}`. Eg.:  
```yml
provider:
  url: "${MY_PROVIDER_URL}"
  clientSecret: "${MY_CLIENT_SECRET}"
```
If a variable is not defined, the provided value is used as-is.  
Please note that you can only use a single environment variable using this syntax and it **does not allow templating**.
So something like this wouldn't work: `https://auth.${MY_DOMAIN}/auth/${CLIENT_ID}`.  
But: If you're using YAML-files for configuration you can use [traefik's templating](https://doc.traefik.io/traefik/providers/file/#go-templating).

Alternatively, you can read the value from a file using `${file:/path/to/file}`. This is useful for secrets
(eg. `clientSecret` or `secret`) when using Docker/Kubernetes secrets mounted as files, since environment
variables set on a container can be read by anyone with access to `docker inspect`, while a mounted secret
file cannot. The file content is trimmed of surrounding whitespace/newlines. Eg.:
```yml
secret: "${file:/run/secrets/oidc_secret}"
provider:
  clientSecret: "${file:/run/secrets/oidc_client_secret}"
```
:::

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `logLevel`* | no | `string` | `WARN` | Defines the logging level of the plugin. Can be one of `DEBUG`, `INFO`, `WARN`, `ERROR`. |
| `secret`* | no | `string` | `MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ`| A secret used for encryption. Must be a 32 character string. It is strongly suggested to change this. |
| `provider` | yes | [`provider`](#provider) | *none* | Identity Provider Configuration. See *Provider* block. |
| `scopes` | no | `string[]` | `["openid", "profile", "email"]` | A list of scopes to request from the IDP. |
| `callbackUri`* | no | `string` | `/oidc/callback` | Defines the callback url used by the IDP. This needs to be registered in your IDP. This may be either a relative URL or an absolute URL -- see also [Callback URLs](./callback-uri.md) |
| `loginUri`* | no | `string` | *none* | An optional url, which should trigger the login-flow. The response of every other url is defined by the `unauthenticatedBehavior`-configuration.  |
| `postLoginRedirectUri`* | no | `string` | *none* | An optional static redirect url where the user should be redirected after login. By default the user will be redirected to the url which triggered the login-flow. |
| `validPostLoginRedirectUris` | no | `string[]` | *none* | Allowed redirect URIs for the login endpoint's *redirect_uri* query parameter. Entries match exactly unless wildcard support is explicitly enabled. See [Redirect URI Wildcards](#redirect-uri-wildcards). |
| `logoutUri`* | no | `string` | `/logout` | The url which should trigger the logout-flow. See [here](./how-it-works.md#logout) for more details. |
| `frontChannelLogoutUri`* | no | `string` | `/frontchannel-logout` | Endpoint for [OIDC Front-Channel Logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html). Requires a matching `iss` query parameter **and** either a matching `sid` or a matching `id_token_hint` before clearing the session. See [Front-Channel Logout](#front-channel-logout). |
| `postLogoutRedirectUri`* | no | `string` | `/` | The url where the user should be redirected after logout. |
| `validPostLogoutRedirectUris` | no | `string[]` | *none* | Allowed redirect URIs for the logout endpoint's *redirect_uri* query parameter. Entries match exactly unless wildcard support is explicitly enabled. See [Redirect URI Wildcards](#redirect-uri-wildcards). |
| `cookieNamePrefix`* | no | `string` | `TraefikOidcAuth` | Specifies the prefix for all cookies used internally by the plugin. The final names are concatenated using dot-notation. Eg. `TraefikOidcAuth.Session`, `TraefikOidcAuth.CodeVerifier` etc. Please note that this prefix does not apply to *AuthorizationCookie* where the name can be set individually. |
| `sessionCookie` | no | [`sessionCookie`](#session-cookie) | *none* | SessionCookie Configuration. See *SessionCookieConfig* block. |
| `authorizationHeader` | no | [`authorizationHeader`](#authorization-header) | *none* | AuthorizationHeader Configuration. See *AuthorizationHeader* block. |
| `authorizationCookie` | no | [`authorizationCookie`](#authorization-cookie) | *none* | AuthorizationCookie Configuration. See *AuthorizationCookie* block. |
| `unauthenticatedBehavior`* | no | `string` | `Auto` | Behavior for requests with no valid session. `Challenge` redirects to the IdP, `Unauthorized` returns 401, `Forward` sends the request unauthenticated to upstream, `Auto` chooses by Accept (HTML → Challenge, else 401). Legacy configs that only set `unauthorizedBehavior` are migrated into this field. |
| `unauthorizedBehavior`* | no | `string` | `Unauthorized` | Behavior for a valid session that fails Authorization rules. `Challenge` starts one IdP re-login (HTML only; second failure → 403), `Unauthorized` returns 403, `Forward` continues to upstream (never on the OAuth callback URL). |
| `authorization` | no | [`authorization`](#authorization) | *none* | Authorization Configuration. See *Authorization* block. |
| `headers` | no | [`Header`](#header) | *none* | Supplies a list of headers which will be attached to the upstream request. See *Header* block. |
| `bypassAuthenticationRule`* | no | `string` | *none* | Specifies an optional rule to bypass authentication. See [Bypass Authentication Rule](./bypass-authentication-rule.md) for more details. |
| `errorPages` | no | [`errorPages`](#error-pages) | *none* | Allows you to customize some error pages. See *ErrorPages* block. |
| `requestedResources` | no | `string[]`| *none* | An array of resource URIs according to [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) for which the token should be requested. | 
| `authorizationParams` | no | `map[string]string`| *none* | Additional query parameters to send to the IDP's authorization endpoint, eg. `acr_values` to request a specific authentication context (step-up authentication) or a default `prompt`. Reserved protocol parameters (`response_type`, `client_id`, `redirect_uri`, `state`, `scope`, `resource`, `code_challenge`, `code_challenge_method`, `nonce`) are always set by the plugin and are **rejected at startup** if you list them here. A `prompt` query parameter on the incoming `/login` request only takes precedence over the configured value if `prompt` is listed in [`authorizationParamsOverridable`](#overridable-authorization-params). |
| `authorizationParamsOverridable` | no | `string[]` | *none* (nothing overridable) | Which `authorizationParams` keys an incoming request may override via query parameter. **Anything not listed here is pinned to your value.** See [Overridable Authorization Params](#overridable-authorization-params). |
| `trustedProxies` | no | `string[]` (CIDR) | *none* (trust none) | CIDR ranges of reverse proxies in front of Traefik whose `X-Forwarded-Proto` / `X-Forwarded-Host` may be trusted. See [Trusted Proxies](#trusted-proxies). |
| `maxSessionLifetimeSeconds` | no | `int` | `0` (unbounded, warns at startup) | Hard upper bound on the total lifetime of a session. See [Session Lifetime Bounds](#session-lifetime-bounds). |
| `sessionIdleTimeoutSeconds` | no | `int` | `0` (disabled) | Maximum gap between two accepted requests on the same session. See [Session Lifetime Bounds](#session-lifetime-bounds). |
| `sessionStorageType` | no | `string` | `""` (cookie) | Only `Cookie` is supported. Any other value is rejected at startup rather than silently ignored, so a config copied from another fork cannot give you an intermittent 401 loop across replicas. |


### Session Lifetime Bounds {#session-lifetime-bounds}

Sessions in this plugin are **stateless**. The whole session — tokens, claims, expiry — is encrypted and stored in the user's own cookie. Traefik keeps nothing server-side, which is what lets you run many replicas behind any load balancer without a shared session store, but it also means **there is no server-side record of a session to delete**.

| Option | YAML key | Type | Default |
|---|---|---|---|
| Maximum total session lifetime | `maxSessionLifetimeSeconds` | `int` | `0` = unbounded (logs a warning at startup) |
| Maximum idle time per session | `sessionIdleTimeoutSeconds` | `int` | `0` = disabled |

Because sessions are stateless and therefore **cannot be revoked** without changing the `secret`, `maxSessionLifetimeSeconds` is the only hard bound you have. A captured session cookie stays usable — and keeps refreshing — until the bound elapses. When it does, the next request is treated as unauthenticated: the cookie is cleared and the usual `unauthenticatedBehavior` applies (a re-challenge for HTML requests, a `401` otherwise). Negative values are rejected at startup.

The idle bound is durable but not exact. The stored `last used` timestamp only survives when the session ticket is rewritten, and the ticket is rewritten at most once per quarter of the idle bound (capped at 60s) rather than on literally every request, to avoid a `Set-Cookie` per request. A session can therefore outlive `sessionIdleTimeoutSeconds` by at most that one refresh interval, never indefinitely.

:::info That "one refresh interval" bound assumes a single replica
The refresh cadence is tracked in a **per-process** in-memory map, not in the session itself, so replicas do not share it. With `N` replicas behind a load balancer each has its own counter and each writes the ticket back on its own schedule, which makes the effective refresh rate roughly `N` times the documented one. The overshoot is therefore *smaller* than the single-replica figure, and the idle bound is *tighter*, never looser — an idle session still dies no later than the bound plus the load balancer's own request-routing skew. Nothing about the bound is weakened by running more than one replica.

For completeness: the per-process map is capped (20 000 tracked sessions) and is cleared wholesale when it overflows. A cleared map only means "write the ticket back sooner again", which is the safe direction.
:::

:::info
A session cookie sealed before these bounds existed carries no creation timestamp. The plugin backfills one from the session's last-used time rather than rejecting the cookie, so upgrading does not log every user out at once. Such a session is then bounded from that backfilled point, not from its true login time.
:::

:::caution
Both bounds only apply to sessions in the session cookie. A request authenticated by an external `authorizationHeader` / `authorizationCookie` is a per-request pseudo-session and is never bounded or renewed.
:::

```yml
traefik-oidc-auth:
  secret: "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"
  # highlight-start
  maxSessionLifetimeSeconds: 3600   # re-authenticate at least once an hour
  sessionIdleTimeoutSeconds: 900    # and drop sessions idle for 15 minutes
  # highlight-end
```

:::warning
Leaving `maxSessionLifetimeSeconds` at `0` is a conscious decision to have sessions that never expire on their own. Pick a value that matches how fast you need to be able to offboard a user — see [Security Considerations](./security-considerations.md).
:::


### Trusted Proxies {#trusted-proxies}

| Name | Required | Type | Default |
|---|---|---|---|
| `trustedProxies` | no | `string[]` of CIDR ranges | *none* — **trust nothing** |

The plugin builds absolute URLs — most importantly the `redirect_uri` it sends to the IDP — from the incoming request. `X-Forwarded-Proto` and `X-Forwarded-Host` are attacker-controlled headers, so they are only honoured when the request actually arrived from a proxy you declared. With an empty list they are **ignored**, which is the fail-closed default and is correct when Traefik is reachable directly.

If Traefik sits behind an ingress, load balancer or CDN, you **MUST** list that hop's CIDR. Otherwise the `redirect_uri` is built from the wrong host or scheme, and the IDP rejects the callback.

```yml
traefik-oidc-auth:
  provider:
    url: "https://idp.example.com"
    clientId: "<YourClientId>"
  # highlight-start
  trustedProxies:
    - "10.42.0.0/16"   # Kubernetes pod network (ingress-nginx)
    - "172.18.0.0/16"   # Docker bridge network
    - "192.168.1.5/32"  # a single external load balancer
  # highlight-end
```

:::warning
List ranges, never `0.0.0.0/0`. Anyone who can reach Traefik directly can then choose the host and scheme of the callback URL.
:::

Entries are parsed as CIDR ranges and an unparseable entry fails the whole middleware at startup. Like most string options in this plugin, each entry supports `${}` environment variables.

:::caution
This gate applies to **every** absolute URL the plugin builds from the request, not only the `redirect_uri`: the post-login and post-logout redirect targets, the `loginUri` / `logoutUri` links on the error pages, and the scheme/host comparison used to decide whether an inbound request is the OAuth callback. A relative `postLoginRedirectUri` behind an untrusted ingress is therefore redirected to the wrong host too.
:::

An `X-Forwarded-Proto` value that is not one of `http`, `https`, `ws`, `wss` is ignored with a `WARN` and the scheme falls back to `https` (TLS) or `http`. Only the first entry of a comma-separated forwarded header is used — the hop closest to the client.


### Overridable Authorization Params {#overridable-authorization-params}

| Name | Required | Type | Default |
|---|---|---|---|
| `authorizationParamsOverridable` | no | `string[]` | *none* — nothing is overridable |

`authorizationParams` are pinned to your configured values. Listing a key in `authorizationParamsOverridable` additionally lets an incoming request replace it with a query parameter of the same name.

```yml
traefik-oidc-auth:
  # highlight-start
  authorizationParams:
    acr_values: "aal2"
  authorizationParamsOverridable: ["prompt"]
  # highlight-end
```

Here `acr_values` stays `aal2` for everyone, while `prompt` can be set per request, e.g. `/login?prompt=login`.

The reserved protocol parameters (`response_type`, `client_id`, `redirect_uri`, `state`, `scope`, `resource`, `code_challenge`, `code_challenge_method`, `nonce`) are always set by the plugin, cannot be overridden from a request, and are rejected at startup if you try to configure them in `authorizationParams`.

:::warning
Adding `acr_values` or `prompt` to this list is a downgrade risk: `?acr_values=loa1` would weaken an authentication context you configured as `aal2`, and `?prompt=none` lets an existing IDP session satisfy a login without any user interaction. Only make a key overridable if you are willing to accept whatever the weakest client sends.
:::


### Front-Channel Logout {#front-channel-logout}

`frontChannelLogoutUri` implements [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html): the IDP loads a URL in the user's browser (usually in a hidden iframe) and that request clears the session cookie in **that browser**. It reaches one browser, not all of them, and it only works while the user still has the IDP session.

The notification is only honoured when it carries **both** of:

- `iss` — matching the session's `iss` claim, and additionally matching the expected issuer when `validateIssuer` is on.
- **either** `sid` matching the session's `sid` claim, **or** `id_token_hint` matching the session's ID token.

`iss` on its own is rejected. It is identical for every user of the provider, so accepting it would let any unauthenticated `GET` — an `<img>` tag, an iframe on a hostile page — log an arbitrary visitor out. This matches the spec, which requires one of `sid` / `id_token_hint`. A rejected notification returns `400` and **leaves the session cookie in place**.

If the session is present and the notification is valid, the session's refresh token is also revoked (see [`revokeTokensOnLogout`](#provider)) before the cookie is cleared; a revocation failure is logged at `WARN` and the logout still completes. A request to the endpoint with **no** session at all is answered as a successful no-op, so an IDP retrying the notification does not produce errors.

:::note
Back-channel (IDP-initiated, server-to-server `POST`) logout is **not** supported and cannot be: the session lives in a browser cookie that an inbound `POST` cannot reach. See [Security Considerations](./security-considerations.md#idp-initiated-back-channel-logout-is-not-supported).
:::


### Per-route audience {#per-route-audience}

There is **no per-route audience key**. `clientId`, `validAudience` and `validateAudience` belong to the middleware instance, not to the router.

To protect one route with a different audience than the rest, declare a **second middleware** with its own client registration and attach it to that route:

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          provider:
            url: "https://idp.example.com"
            clientId: "<DefaultClientId>"
    oidc-auth-sensitive: # highlight-start
      plugin:
        traefik-oidc-auth:
          cookieNamePrefix: "TraefikOidcAuthSensitive"
          provider:
            url: "https://idp.example.com"
            clientId: "<SensitiveClientId>"
          validAudience: "<SensitiveClientId>"
    # highlight-end

  routers:
    app:
      rule: "Host(`app.example.com`)"
      service: app
      middlewares: ["oidc-auth@file"]
    admin:
      rule: "Host(`admin.example.com`)"
      service: admin
      middlewares: ["oidc-auth-sensitive@file"]
```

Give the second middleware a distinct `cookieNamePrefix` so the two session cookies do not overwrite each other when both middlewares are active on one domain.

:::tip
The same applies to any other per-middleware setting you want to vary per route — `authorization.assertClaims`, `maxSessionLifetimeSeconds`, `trustedProxies` and so on. A second middleware is the only way to vary them.
:::


### Redirect URI Wildcards {#redirect-uri-wildcards}

OIDC/OAuth2 requires exact redirect URI matching. Wildcard entries are **off unless you opt in process-wide**: set the environment variable `TOA_ENABLE_REDIRECT_URI_WILDCARDS=true` (or `1`) on the **Traefik process**. This is an instance-wide security decision, not a middleware option — one Traefik instance either allows wildcard redirect URIs or it does not, and there is no per-middleware or per-route switch.

**If the variable is not set, a `*` in an allowlist entry means nothing.** The entry is compared as a literal string, so `validPostLoginRedirectUris: ["https://app.example.com/*"]` only matches the exact URL `https://app.example.com/*` and rejects every real callback underneath it. Each wildcard entry in that state logs a warning at startup.

With wildcards enabled:

- A host `*` matches exactly one label: `https://*.example.com/*` matches `https://app.example.com/home`, not `https://app.eu.example.com/home`.
- A path `*` works only as the final character and spans any number of path segments: `/app/*` matches `/app`, `/app/index.html`, and `/app/a/b`.
- Query strings and fragments are ignored for wildcard path matching but remain unchanged in the accepted redirect URI.
- A bare `*` accepts any **safe** redirect URI and effectively disables allowlist protection. Avoid it.
- Ambiguous host suffixes such as `https://example.com*`, protocol-relative URLs, user-info host spoofing, and encoded/double-encoded path traversal are rejected.
- Path-only entries only match path-only redirects; full URLs only match full URLs.

## Provider Block {#provider}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `url`* | yes | `string` | *none* | The full URL of the Identity Provider. |
| `insecureSkipVerify`* | no | `bool` | `false` | Disables SSL certificate verification of your provider. It's highly recommended to provide the real CA bundle via `cABundleFile` instead. So this option should only be used for quick testing. |
| `cABundle`* | no | `string` | *none* | An optional CA certificate bundle provided as a raw string in case you're using self-signed certificates for the provider. Please note that the string needs to represent a valid certificate, including new-lines. In case you cannot provide a multi-line argument you can base64-encode the bundle and provide it with the `base64:` prefix. Eg.: `base64:<your-base64-encoded-bundle>`. |
| `cABundleFile`* | no | `string` | *none* | Specifies the path to an optional CA certificate bundle in case you're using self-signed certificates for the provider. If you're using Docker, make sure the file is mounted into the traefik container. |
| `clientId`* | yes | `string` | *none* | The client id of the application. |
| `clientSecret`* | no | `string` | *none* | The client secret of the application. May not be needed for some providers when using PKCE. |
| `clientJwtPrivateKeyId`* | no | `string` | *none* | Specifies the key id (`keyId` field in the downloaded file) of a [JWT Profile](https://zitadel.com/docs/guides/integrate/token-introspection/private-key-jwt). Only works with ZITADEL. Note: This is a little bit experimental and not well tested yet. |
| `clientJwtPrivateKey`* | no | `string` | *none* | Specifies the private key (`key` field in the downloaded file) of a [JWT Profile](https://zitadel.com/docs/guides/integrate/token-introspection/private-key-jwt). Only works with ZITADEL. Note: This is a little bit experimental and not well tested yet. |
| `usePkce`* | no | `bool` | `true`| Enable PKCE. In this case, a client secret may not be needed for some providers. The following algorithms are supported: *RS*, *EC*, *ES*. |
| `validateIssuer`* | no | `bool` | `true` | Specifies whether the `iss` claim in the JWT-token should be validated. |
| `validIssuer`* | no | `string` | *discovery document* | The issuer which must be present in the JWT-token. By default this will be read from the OIDC discovery document. |
| `validateAudience`* | no | `bool` | `true` | Specifies whether the `aud` claim in the JWT-token should be validated. |
| `validAudience`* | no | `string` | *ClientId* | The audience which must be present in the JWT-token. Defaults to the configured client id. This is a **per-middleware** setting: there is no per-route key for it. To give one route a different audience, declare a second middleware with its own `clientId` / `validAudience` and attach that to the route. See [Per-route audience](#per-route-audience). |
| `tokenValidation`* | no | `string` | `IdToken` | Specifies which token or method should be used to validate the authentication cookie. Can be either `AccessToken`, `IdToken` or `Introspection`. Any other value is rejected at startup rather than failing every login. `Introspection` may not work when using PKCE. |
| `useClaimsFromUserInfo`* | no | `bool` | `false` | When enabled, an additional request to the provider's `userinfo_endpoint` is made to validate the token and to retrieve additional claims. The userinfo claims are merged directly into the token claims, with userinfo values overriding token values for non-security-critical claims. |
| `tokenRenewalThreshold` | no | `float` | `0.75` | The percentage of the token's lifetime after which it should be renewed before expiration. The value must be between 0.5 and 1.0. |
| `revokeTokensOnLogout`* | no | `bool` | `true` | On user-initiated logout — and on a front-channel logout notification for the same session — POST the refresh token to the IDP's `revocation_endpoint` so neither the cookie nor the refresh token can be replayed afterwards. **Silently skipped when the IDP's discovery document advertises no `revocation_endpoint`, or when the session holds no refresh token** — check your provider before relying on it. A failing revocation endpoint is logged at `WARN` and the logout completes anyway. It only revokes *that* session's refresh token; other browsers holding a copy of the same cookie keep working. See [Security Considerations](./security-considerations.md). In `CONFIG_FILE` the same option also has a native-boolean spelling; see [`docs/extauth-server.md`](https://github.com/BlackDark/test-oidc-traefik-plugin/blob/main/docs/extauth-server.md#multi-client-config). |
| `maxAuthAgeSeconds` | no | `int` | `0` (disabled) | Enforces the step-up freshness requirement **only on a challenge** (`unauthorizedBehavior: Challenge` with an already-valid session): sends `max_age` on the authorization request and requires the resulting ID token to carry an `auth_time` claim that recent. A **plain login is unaffected**, as are session renewals. Not usable with `tokenValidation: Introspection`. See [Step-Up Authentication](#step-up-authentication). |
| `oidcTimeoutSeconds` | no | `int` | `30` | Bounds **every** outbound call to the IDP — discovery, token, JWKS, introspection and userinfo. Without a client-side timeout a hung IDP pins the request goroutine indefinitely, and because discovery and JWKS loads happen under a lock one slow dependency stalls every router behind that Traefik instance. A value below `0` is reset to the default of `30`; `0` is also treated as the default. |
| `validateNonce` | no | `bool` | `true` | Require the ID token's `nonce` claim to match the value sealed into the login state (OIDC Core). Set to `false` **only** if your IDP cannot return a nonce; doing so removes the replay protection that binds the ID token to the authorization request that started it. |
| `tokenClockSkewSeconds` | no | `int` | `60` | Leeway applied to JWT `nbf`/`exp` validation, for IDPs whose clocks drift from yours. Raise it only for a measured skew; it widens the window in which an expired token is still accepted. A negative value is reset to the default of `60`. |


### Step-Up Authentication {#step-up-authentication}

Setting [`unauthorizedBehavior`](#plugin-config-block) to `Challenge` only makes the browser go back through the IDP. It does **not** by itself make the IDP ask for a password again: if the user still has a live SSO session at the IDP, the redirect returns immediately with the old authentication.

`maxAuthAgeSeconds` fixes that, but **only for the challenge**. When the request reached the middleware with a valid session and failed the `authorization` rules (`unauthorizedBehavior: Challenge`), the freshness requirement is enforced: `max_age` is sent on the authorization request and the resulting ID token must carry an `auth_time` claim within that many seconds. `0` (the default) disables the check. A **plain login** — an unauthenticated request answered by `unauthenticatedBehavior: Challenge` or `Auto` — is **unaffected**, as is every renewal of an existing session: neither sends `max_age` nor is checked for freshness.

```yml
traefik-oidc-auth:
  provider:
    url: "https://idp.example.com"
    clientId: "<YourClientId>"
    # highlight-start
    maxAuthAgeSeconds: 300
  # highlight-end
  unauthorizedBehavior: "Challenge"
```

:::warning
Without `maxAuthAgeSeconds`, a route that advertises "re-authenticate to continue" can be satisfied by an IDP session from hours earlier. If your step-up is a real security control — a high-accuracy `acr`, a sensitive action — set this value. Note that the IDP must honour `max_age`; if it ignores the parameter, the plugin cannot distinguish a fresh authentication from a cached SSO one.
:::

:::danger Do not combine `maxAuthAgeSeconds` with `provider.tokenValidation: Introspection`
RFC 7662 introspection responses carry **no `auth_time` claim** — the response is `{active, sub, scope, client_id, ...}`, with no authentication-time information at all. The plugin treats a missing `auth_time` as **not fresh** (fail-closed), so with this combination a step-up challenge would *never* be satisfiable: the user is sent to the IDP, comes back with a perfectly valid token, and is denied anyway. This looks like a broken login rather than a misconfiguration.

**Recommended IdP setup:** use `provider.tokenValidation: IdToken` (the default) and configure the client so the **ID token** carries `auth_time` — in practice that means the client must be an OAuth2 **confidential client using the authorization code flow with a real user login**, and the provider must emit `auth_time` in its ID tokens. Several providers require the `openid` profile scope or the `auth_time` response claim to be requested explicitly. Verify with a real challenge before enabling this in production: complete one step-up flow and inspect the ID token for a non-zero `auth_time`.
:::

:::warning
When using `useClaimsFromUserInfo`, an additional request to the provider's `userinfo_endpoint` is made to validate the token and to retrieve additional claims.
When `checkOnEveryRequest` is enabled, this will greatly increase the hit rate on the IDP and may introduce latency.
:::

:::info
`max_age` is only sent on the **challenge** authorization request. A plain login triggered by `unauthenticatedBehavior: Challenge` or `Auto` is unaffected, and so is every renewal of an existing session. If your IDP returns an ID token without an `auth_time` claim, the step-up login is **rejected** (fail-closed) rather than accepted.
:::

:::info
**Claims Merging Behavior**: When `useClaimsFromUserInfo` is enabled, claims from the userinfo endpoint are merged directly into the token claims. Security-critical JWT claims (`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `azp`) are protected and cannot be overwritten by userinfo data. All other claims from userinfo will override corresponding token claims, allowing you to access updated profile information directly via `{{ .claims.* }}` templates.
:::

## SessionCookie Block {#session-cookie}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `path` | no | `string` | `/` | The path to which the cookie should be assigned to. |
| `domain` | no | `string` | *none* | An optional domain to which the cookie should be assigned to. See [Callback URLs](./callback-uri.md) for examples. |
| `secure` | no | `bool` | `true` | Whether the cookie should be marked secure. |
| `httpOnly` | no | `bool` | `true` | Whether the cookie should be marked http-only. |
| `sameSite` | no | `string` | `lax` | Can be one of `default` (let Go decide), `none`, `lax`, `strict`. Any other value is rejected at startup. |
| `maxAge` | no | `int` | `0` | Cookie time-to-live in seconds.  0 (default) is a ephemeral session cookie. |

## AuthorizationHeader Block {#authorization-header}

By specifying this configuration, a request can send an externally generated access token via this header to authenticate the request.
In this case no session will be created by the middleware. You may also want to set `unauthenticatedBehavior` to `Unauthorized`.

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `name` | no | `string` | *none* | The name of the header. |

## AuthorizationCookie Block {#authorization-cookie}

This works exactly the same as [AuthorizationHeader](#authorization-header), but using a cookie instead of a header. You can also use both.

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `name` | no | `string` | *none* | The name of the cookie. |

## Authorization Block {#authorization}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `assertClaims` | no | [`ClaimAssertion[]`](#claim-assertion) | *none* | ClaimAssertion Configuration. See *ClaimAssertion* block. |
| `checkOnEveryRequest` | no | `bool` | `false` |  When set to true, authorization is checked on every single request. When set to false, authorization is only checked when the user logs in and the session is being created. When using external authentication using ˋAuthorizationHeaderˋ or ˋAuthorizationCookieˋ this is always treated as true.


## ClaimAssertion Block {#claim-assertion}

If only the `name` property is set and no additional assertions are defined it is only checked whether there exist any matches for the name of this claim without any verification on their values.
Additionaly, the `name` field can be any [json path](https://jsonpath.com/). The `name` gets prefixed with `$.` to match from the root element. The usage of json paths allows for assertions on deeply nested json structures.

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `name` | yes | `string` | *none* | The name of the claim in the access token. |
| `anyOf` | no | `string[]` | *none* | An array of allowed strings. The user is authorized if any value matching the name of the claim contains (or is) a value of this array. |
| `allOf` | no | `string[]` | *none* | An array of required strings. The user is only authorized if any value matching the name of the claim contains (or is) a value of this array and all values of this array are covered in the end. |

It is possible to combine `anyOf` and `allOf` quantifiers for one assertion.

:::tip
Also see the [Authorization](./authorization.md) section for more details about how to use this feature.
:::

:::important
Because the name is being interpreted as jsonpath, you may need to escape some names, if they contain special characters like a colon or minus.
So instead of `name: "my:zitadel:grants"`, use `name: "['my:zitadel:grants']"`.
:::

## Header Block {#header}

| Name          | Required           | Type     | Default    | Description                                                                                                                                                      |
|---------------|--------------------|----------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `name`        | yes                | `string` | *none*     | The name of the header which should be added to the upstream request.                                                                                            |
| `value`       | if `values` absent | `string` | *none*     | The value of the header, which can use [Go-Templates](https://pkg.go.dev/text/template). Please see the info below.                                              |
| `values`      | if `value` absent  | `string` | *none*     | The values of the header, which can use [Go-Templates](https://pkg.go.dev/text/template). Should evaluate to valid json array of strings.                        |
| `includeWhen` | no                 | `string` | Authorized | Whether the header is sent to public routes or if `unauthorizedBehavior` is set to `Forward`. Available options are `Always`, `Authorized`, `Public`, `Forward`. |

By using Go-Templates you have access to the following attributes:

| Template | Description |
|---|---|
| `{{ .accessToken }}` | The OAuth Access Token. The access token gets renewed automatically after `tokenRenewalThreshold` percent of it's lifetime has passed. This means that when sending this token upstream, it is still valid for at least `1 - TokenRenewalThreshold` percent of it's lifetime. |
| `{{ .idToken }}` | The OAuth Id Token |
| `{{ .refreshToken }}` | The OAuth Refresh Token |
| `{{ .claims.* }}` | Replace `*` with the name or path to your desired claim. If `useClaimsFromUserInfo` is enabled, the claims from the `userinfo_endpoint` are merged directly into the token claims and accessible via `{{ .claims.* }}`. |

:::info
Because [traefik configuration files already support Go-templating](https://doc.traefik.io/traefik/providers/file/#go-templating), you need to *escape* your templates in a weird way. Here are some examples:

```yml
headers:
  - name: "Authorization"
    value: "{{`Bearer {{ .accessToken }}`}}"
  - name: "X-Oidc-Username"
    value: "{{`{{ .claims.preferred_username }}`}}"
```

The outer curly braces and backticks are used to escape the inner curly braces.

Note that this *only* applies for configuring Traefik from a YAML file, where it performs it's own template expansion.  If you are using the Kubernetes CRDs, you should *not* escape, just template as usual:

```yml
headers:
  - name: X-Oidc-Groups-Json-Array
    value: '[{{with .claims.groups}}{{ range $i, $g := . }}{{if $i}},{{end}}"{{js $g}}"{{end}}{{end}}]'
```

Some additional helper functions are available in the templates:

| Name             | Description                                                                              |
|------------------|------------------------------------------------------------------------------------------|
| `withPrefix`     | Prefixes each value in the slice with a given string.                                    |
| `withSuffix`     | Suffixes each value in the slice with a given string.                                    |
| `mapToJsonArray` | Maps each value to a JSON array element, escaping any special characters in the process. |

If using `values` templating, value should be a valid string of JSON array with only strings as values. Each value is mapped to an individual header.
It can be used to pass multiple headers with the same name, for example, for a Kubernetes impersonation request:

```yml
headers:
  - name: "Authorization"
    value: "Bearer {{ .accessToken }}"
  - name: "Impersonate-User"
    value: "prefix:{{ .claims.preferred_username }}"
  - name: "Impersonate-Group"
    values: '{{ .claims.groups | withPrefix "prefix:" | mapToJsonArray }}'
```
:::

## ErrorPages Block {#error-pages}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `unauthenticated` | no | [`ErrorPage`](#error-page) | *none* | Configures the page or behavior when the user is not authenticated. |
| `unauthorized` | no | [`ErrorPage`](#error-page) | *none* | Configures the page or behavior when the user is not authorized. |

## ErrorPage Block {#error-page}

| Name | Required | Type | Default | Description |
|---|---|---|---|---|
| `filePath`* | no | `string` | *none* | Specifies the path to a local html file which should be served. If this is not set, the default page is shown. This html file needs to be self-contained which means all CSS and JS must be inlined. |
| `redirectTo`* | no | `string` | *none* | If this is set to a URL, the user is redirected to this page in case of an error, instead of showing an error page. |
