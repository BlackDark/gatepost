---
sidebar_position: 3
---

# Middleware Configuration

## Plugin Config Block

:::tip Config key casing
Examples use **camelCase** keys (`secret`, `clientId`, `unauthorizedBehavior`) to match Kubernetes CRD conventions. Traefik's plugin decoder matches field names **case-insensitively**, so legacy PascalCase keys (`Secret`, `ClientId`) still work.

The newer options in this reference are written in **snake_case**, matching their JSON field names exactly. `max_session_lifetime_seconds` and `maxSessionLifetimeSeconds` are the same option.
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
| `frontChannelLogoutUri`* | no | `string` | `/frontchannel-logout` | Endpoint for [OIDC Front-Channel Logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html). Requires a matching `iss` query parameter (and optional `sid`) before clearing the session. |
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
| `authorizationParams` | no | `map[string]string`| *none* | Additional query parameters to send to the IDP's authorization endpoint, eg. `acr_values` to request a specific authentication context (step-up authentication) or a default `prompt`. Reserved protocol parameters (`response_type`, `client_id`, `redirect_uri`, `state`, `scope`, `resource`) cannot be overridden this way and are ignored with a warning. A `prompt` query parameter on the incoming `/login` request still takes precedence over the configured value. |
| `authorization_params_overridable` | no | `string[]` | *none* (nothing overridable) | Which `authorizationParams` keys an incoming request may override via query parameter. **Anything not listed here is pinned to your value.** See [Overridable Authorization Params](#overridable-authorization-params). |
| `trusted_proxies` | no | `string[]` (CIDR) | *none* (trust none) | CIDR ranges of reverse proxies in front of Traefik whose `X-Forwarded-Proto` / `X-Forwarded-Host` may be trusted. See [Trusted Proxies](#trusted-proxies). |
| `max_session_lifetime_seconds` | no | `int` | `0` (unbounded, warns at startup) | Hard upper bound on the total lifetime of a session. See [Session Lifetime Bounds](#session-lifetime-bounds). |
| `session_idle_timeout_seconds` | no | `int` | `0` (disabled) | Maximum gap between two accepted requests on the same session. See [Session Lifetime Bounds](#session-lifetime-bounds). |
| `session_storage_type` | no | `string` | `""` (cookie) | Only `Cookie` is supported. Any other value is rejected at startup rather than silently ignored, so a config copied from another fork cannot give you an intermittent 401 loop across replicas. |


### Session Lifetime Bounds {#session-lifetime-bounds}

Sessions in this plugin are **stateless**. The whole session — tokens, claims, expiry — is encrypted and stored in the user's own cookie. Traefik keeps nothing server-side, which is what lets you run many replicas behind any load balancer without a shared session store, but it also means **there is no server-side record of a session to delete**.

| Option | YAML key | Type | Default |
|---|---|---|---|
| Maximum total session lifetime | `max_session_lifetime_seconds` | `int` | `0` = unbounded (logs a warning at startup) |
| Maximum idle time per session | `session_idle_timeout_seconds` | `int` | `0` = disabled |

Because sessions are stateless and therefore **cannot be revoked** without changing the `secret`, `max_session_lifetime_seconds` is the only hard bound you have. A captured session cookie stays usable — and keeps refreshing — until the bound elapses. When it does, the next request forces the user through a fresh authentication at the IDP. Negative values are rejected at startup.

```yml
traefik-oidc-auth:
  secret: "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"
  # highlight-start
  max_session_lifetime_seconds: 3600   # re-authenticate at least once an hour
  session_idle_timeout_seconds: 900    # and drop sessions idle for 15 minutes
  # highlight-end
```

:::warning
Leaving `max_session_lifetime_seconds` at `0` is a conscious decision to have sessions that never expire on their own. Pick a value that matches how fast you need to be able to offboard a user — see [Security Considerations](./security-considerations.md).
:::


### Trusted Proxies {#trusted-proxies}

| Name | Required | Type | Default |
|---|---|---|---|
| `trusted_proxies` | no | `string[]` of CIDR ranges | *none* — **trust nothing** |

The plugin builds absolute URLs — most importantly the `redirect_uri` it sends to the IDP — from the incoming request. `X-Forwarded-Proto` and `X-Forwarded-Host` are attacker-controlled headers, so they are only honoured when the request actually arrived from a proxy you declared. With an empty list they are **ignored**, which is the fail-closed default and is correct when Traefik is reachable directly.

If Traefik sits behind an ingress, load balancer or CDN, you **MUST** list that hop's CIDR. Otherwise the `redirect_uri` is built from the wrong host or scheme, and the IDP rejects the callback.

```yml
traefik-oidc-auth:
  provider:
    url: "https://idp.example.com"
    clientId: "<YourClientId>"
  # highlight-start
  trusted_proxies:
    - "10.42.0.0/16"   # Kubernetes pod network (ingress-nginx)
    - "172.18.0.0/16"   # Docker bridge network
    - "192.168.1.5/32"  # a single external load balancer
  # highlight-end
```

:::warning
List ranges, never `0.0.0.0/0`. Anyone who can reach Traefik directly can then choose the host and scheme of the callback URL.
:::

Entries are parsed as CIDR ranges and an unparseable entry fails the whole middleware at startup. Like most string options in this plugin, each entry supports `${}` environment variables.


### Overridable Authorization Params {#overridable-authorization-params}

| Name | Required | Type | Default |
|---|---|---|---|
| `authorization_params_overridable` | no | `string[]` | *none* — nothing is overridable |

`authorizationParams` are pinned to your configured values. Listing a key in `authorization_params_overridable` additionally lets an incoming request replace it with a query parameter of the same name.

```yml
traefik-oidc-auth:
  # highlight-start
  authorization_params:
    acr_values: "aal2"
  authorization_params_overridable: ["prompt"]
  # highlight-end
```

Here `acr_values` stays `aal2` for everyone, while `prompt` can be set per request, e.g. `/login?prompt=login`.

:::warning
Adding `acr_values` or `prompt` to this list is a downgrade risk: `?acr_values=loa1` would weaken an authentication context you configured as `aal2`, and `?prompt=none` lets an existing IDP session satisfy a login without any user interaction. Only make a key overridable if you are willing to accept whatever the weakest client sends.
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
The same applies to any other per-middleware setting you want to vary per route — `authorization.assertClaims`, `max_session_lifetime_seconds`, `trusted_proxies` and so on. A second middleware is the only way to vary them.
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
| `usePkce`* | no | `bool` | `false`| Enable PKCE. In this case, a client secret may not be needed for some providers. The following algorithms are supported: *RS*, *EC*, *ES*. |
| `validateIssuer`* | no | `bool` | `true` | Specifies whether the `iss` claim in the JWT-token should be validated. |
| `validIssuer`* | no | `string` | *discovery document* | The issuer which must be present in the JWT-token. By default this will be read from the OIDC discovery document. |
| `validateAudience`* | no | `bool` | `true` | Specifies whether the `aud` claim in the JWT-token should be validated. |
| `validAudience`* | no | `string` | *ClientId* | The audience which must be present in the JWT-token. Defaults to the configured client id. This is a **per-middleware** setting: there is no per-route key for it. To give one route a different audience, declare a second middleware with its own `clientId` / `validAudience` and attach that to the route. See [Per-route audience](#per-route-audience). |
| `tokenValidation`* | no | `string` | `IdToken` | Specifies which token or method should be used to validate the authentication cookie. Can be either `AccessToken`, `IdToken` or `Introspection`. Any other value is rejected at startup rather than failing every login. `Introspection` may not work when using PKCE. |
| `useClaimsFromUserInfo`* | no | `bool` | `false` | When enabled, an additional request to the provider's `userinfo_endpoint` is made to validate the token and to retrieve additional claims. The userinfo claims are merged directly into the token claims, with userinfo values overriding token values for non-security-critical claims. |
| `tokenRenewalThreshold` | no | `float` | `0.75` | The percentage of the token's lifetime after which it should be renewed before expiration. The value must be between 0.5 and 1.0. |
| `revoke_tokens_on_logout`* | no | `bool` | `true` | On user-initiated logout, POST the refresh token to the IDP's `revocation_endpoint` so neither the cookie nor the refresh token can be replayed afterwards. **Silently skipped when the IDP's discovery document advertises no `revocation_endpoint`** — check your provider before relying on it. Does not affect front-channel logout of other sessions. See [Security Considerations](./security-considerations.md). |
| `max_auth_age_seconds` | no | `int` | `0` (disabled) | Turns `Challenge` into a real step-up authentication: sends `max_age` on the authorization request and requires the resulting ID token to carry an `auth_time` claim that recent. See [Step-Up Authentication](#step-up-authentication). |
| `oidc_timeout_seconds` | no | `int` | `30` | Bounds **every** outbound call to the IDP — discovery, token, JWKS, introspection and userinfo. Without a client-side timeout a hung IDP pins the request goroutine indefinitely, and because discovery and JWKS loads happen under a lock one slow dependency stalls every router behind that Traefik instance. A value below `0` is reset to the default of `30`; `0` is also treated as the default. |


### Step-Up Authentication {#step-up-authentication}

Setting [`unauthorizedBehavior`](#plugin-config-block) to `Challenge` only makes the browser go back through the IDP. It does **not** by itself make the IDP ask for a password again: if the user still has a live SSO session at the IDP, the redirect returns immediately with the old authentication.

`max_auth_age_seconds` fixes that. It sends `max_age` on the authorization request and requires the returned ID token's `auth_time` claim to be within that many seconds. `0` (the default) disables the check.

```yml
traefik-oidc-auth:
  provider:
    url: "https://idp.example.com"
    clientId: "<YourClientId>"
    # highlight-start
    max_auth_age_seconds: 300
  # highlight-end
  unauthorizedBehavior: "Challenge"
```

:::warning
Without `max_auth_age_seconds`, a route that advertises "re-authenticate to continue" can be satisfied by an IDP session from hours earlier. If your step-up is a real security control — a high-assurance `acr`, a sensitive action — set this value. Note that the IDP must honour `max_age`; if it ignores the parameter, the plugin cannot distinguish a fresh authentication from a cached SSO one.
:::

:::warning
When using `useClaimsFromUserInfo`, an additional request to the provider's `userinfo_endpoint` is made to validate the token and to retrieve additional claims.
When `checkOnEveryRequest` is enabled, this will greatly increase the hit rate on the IDP and may introduce latency.
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
| `sameSite` | no | `string` | `default` | Can be one of `default`, `none`, `lax`, `strict`. |
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
