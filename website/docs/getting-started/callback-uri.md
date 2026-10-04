---
sidebar_position: 4
---

# Callback URLs

The `callbackUri` field of the top-level [plugin config block](./middleware-configuration.md#plugin-config-block) can be either an absolute or relative URL.

## Relative URL (the default)

If configured as a relative URL (by default, `/oidc/callback`), then the plugin will intercept calls to that path under any hostname it is given.

When authentication is needed, whatever host the user is accessing will be used as the callback URL for the redirect to the identity provider.

:::warning
The scheme and host come from the request, and `X-Forwarded-Proto` / `X-Forwarded-Host` are **ignored** unless that request arrived from a proxy listed in [`trustedProxies`](./middleware-configuration.md#trusted-proxies). If Traefik sits behind an ingress or load balancer, configure `trustedProxies` or the callback URL is built with the wrong scheme/host and the IDP rejects the callback.
:::

When the plugin is protecting only one hostname, this is zero-configuration.

If you protect many different hostnames using the plugin, it's likely desirable to use an identity provider with dynamic callback URL patterns, or to instead use the plugin in absolute URL mode.

## Absolute URL

If `callbackUri` is an absolute URL with a protocol scheme and a hostname, for example `https://login.example.com/oidc/callback`, then the plugin will only intercept calls to that path and hostname, and, that URL will always be used as the callback URL for the redirect to the identity provider.

This will likely greatly simplify your identity provider configuration.

:::warning An absolute `callbackUri` still needs `trustedProxies`
An absolute `callbackUri` fixes the URL **sent to the IDP** — it is never taken from the request. It does **not** remove the need for [`trustedProxies`](./middleware-configuration.md#trusted-proxies).

Deciding whether an inbound request *is* the OAuth callback still happens by comparing the request-derived scheme/host against the absolute `CallbackURL`. Behind a TLS-terminating ingress with an empty `trustedProxies`, `X-Forwarded-Proto` / `X-Forwarded-Host` are ignored, the derived URL becomes `http://internal-service/oidc/callback`, that comparison fails, and the request is handled as an ordinary unauthenticated request instead of a callback. The user is bounced back to the IDP and the login never completes.

So an absolute `callbackUri` removes *one* source of mismatch (the outgoing `redirect_uri`), not the proxy trust requirement.
:::

Of course you must pick an absolute URL where the plugin will receive the traffic.

For users familiar with [thomseddon/traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth), this is equivalent to its [Auth Host Mode](https://github.com/thomseddon/traefik-forward-auth?tab=readme-ov-file#auth-host-mode).

If you are protecting many different subdomains that share parent domain (for example `example.com`), you might wish to store the cookie at the common level:

```yml
  middlewares:
    oidc-auth:
      plugin:
        gatepost:
        # highlight-start
          callbackUri: "https://login.example.com/oidc/callback"
          sessionCookie:
            domain: ".example.com"
        # highlight-end
          provider:
            url: "https://ident.example.com/"
            clientId: "<YourClientId>"
            clientSecret: "<YourClientSecret>"
          scopes: ["openid", "profile", "email"]
```

This is not required, but is a performance optimization.

### Full working example for local development
```yml
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        gatepost:
          logLevel: DEBUG
          provider:
            url: "${PROVIDER_URL}"
            clientId: "${CLIENT_ID}"
            clientSecret: "${CLIENT_SECRET}"
            usePkce: false
          scopes: ["openid", "profile", "email"]
          callbackUri: "https://auth.127.0.0.1.sslip.io/oidc/callback"
          sessionCookie:
            domain: ".127.0.0.1.sslip.io"

  routers:
    service1:
      entryPoints: ["websecure"]
      tls: {}
      rule: "Host(`service1.127.0.0.1.sslip.io`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    service2:
      entryPoints: ["websecure"]
      tls: {}
      rule: "Host(`service2.127.0.0.1.sslip.io`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    auth:
      entryPoints: ["websecure"]
      tls: {}
      rule: "Host(`auth.127.0.0.1.sslip.io`)"
      service: noop@internal
      middlewares: ["oidc-auth@file"]
```

:::caution
If you're sharing the session cookie (by providing `SessionCookie.Domain`) as shown above, authorization may not work as expected.
Authorization is only checked when the session is being created.
This means, if you have two different middlewares with different authorization rules but you're sharing the session cookie,
you will also be logged in on the other application.
:::
