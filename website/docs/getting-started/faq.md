---
sidebar_position: 99
---

# FAQ

## How can i get more log output from the plugin

The default log level of the plugin is set to `WARN`. You can change this by specifying the `logLevel` option in the [configuration](./middleware-configuration.md).

## I get stuck in a redirect loop after signing in

Make sure you're using HTTPS. The session cookie is configured as *Secure* by default which means it will only be stored, when using HTTPS.
If you open the Browser's development console you might see a warning icon (at least in Google Chrome) telling you that you're not on a secure context.
In the traefik logs you might see the message `named cookie is not present` which is also a sign that the session cookie hasn't been stored.
If you really can't use HTTPS you can set `SessionCookie.Secure` to `false`, but please don't do this in production.

## I just see *Unauthorized* after signing in

This normally means, that your user isn't authorized to sign in. Please check the traefik logs to get more information.
You may see something like `Unauthorized. Unable to find claim roles in token claims.`. It will also output all the claims contained in the token.
Please adjust your `authorization`-config accordingly.

## My IDP rejects the callback / login loops after upgrading

If the IDP reports a `redirect_uri` mismatch and Traefik sits behind an ingress, load balancer or CDN, you are almost certainly missing [`trusted_proxies`](./middleware-configuration.md#trusted-proxies).

The plugin builds the `redirect_uri` it sends to the IDP from the incoming request, and only honours `X-Forwarded-Proto` / `X-Forwarded-Host` when the request actually arrived from a proxy you listed. With an empty `trusted_proxies` the forwarded headers are ignored, so behind an ingress the callback URL is built with the wrong host or scheme and the IDP refuses the callback.

```yml
traefik-oidc-auth:
  # highlight-start
  trusted_proxies:
    - "10.42.0.0/16"   # the CIDR of the hop in front of Traefik
  # highlight-end
```

List ranges, never `0.0.0.0/0`. See the [Trusted Proxies](./middleware-configuration.md#trusted-proxies) section for the full rules.
