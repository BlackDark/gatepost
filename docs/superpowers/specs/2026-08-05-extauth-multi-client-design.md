# extauth-server multi-client design

**Date:** 2026-08-05  
**Status:** approved for planning  
**Scope:** `cmd/extauth-server` only — Traefik middleware plugin unchanged

## Problem

Today `extauth-server` loads one JSON config and builds one OIDC client via `src.New`. Each additional OIDC client needs another Deployment. Goal: one process serves many Host→client mappings with config reload, without an operator.

## Constraints (decided)

| Decision | Choice |
|---|---|
| Surface | extauth-server only |
| Client selection | Host header (exact, case-insensitive; strip port) |
| Trust model | Same-org / shared blast radius OK in one process |
| Reload | File watch primary; SIGHUP optional (same path) |
| Config format | YAML only (breaking) |
| Secrets | ConfigMap for non-secrets; Secret files via `${file:…}` |
| Compat | Break single-client JSON — no dual schema |

## Approach

**Host router over N `src.New` instances.** Wrapper in `cmd/extauth-server` owns multi-client config, Host→handler map, and reload. Core `src/` / Traefik plugin stay single-client.

Rejected: pushing multi-client into `src/` (touches middleware), K8s Operator (overkill).

## Architecture

```
Gateway (Host: app-a.example.com)
  → extauth HTTP or gRPC
    → resolve Host → client runtime
      → existing TraefikOidcAuth.ServeHTTP
```

- Boot: load YAML → expand `${…}` / `${file:…}` → `src.New` per client → `map[host]handler`
- Unknown Host → **403** (fail closed; no default client)
- Duplicate Host across clients → reject at load/reload
- In-flight requests keep the handler they started with (atomic map swap only between requests)

## Config schema

```yaml
clients:
  - id: grafana
    hosts:
      - grafana.example.com
    secret: ${file:/secrets/grafana/cookie-secret}
    provider:
      url: https://idp.example.com
      clientId: grafana
      clientSecret: ${file:/secrets/grafana/client-secret}
    cookieNamePrefix: grafana
    callbackUri: /oidc/callback
    # …all other fields from today's per-instance Config
```

Rules:

- `clients` required, length ≥ 1
- Each entry: unique `id`, `hosts` length ≥ 1, remaining fields = today’s `config.Config`
- No top-level shared `secret` / `provider`
- Host match: exact, case-insensitive; strip `:port` if present. Optional `*.suffix` wildcards (exact wins)
- `${ENV}` and `${file:/path}` expansion unchanged

K8s: ConfigMap mounts the YAML; Secret volume mounts files under `/secrets/<id>/…`.

## Reload

**Triggers**

- fsnotify on `CONFIG_FILE` with debounce (200–500ms; handles K8s symlink atomic swaps)
- Optional `SIGHUP` → same reload function
- Optional `SECRET_WATCH_DIRS` (comma-separated) so Secret file updates trigger re-expand without requiring a config touch

**Procedure**

1. Parse YAML → validate (unique ids/hosts, ≥1 client, each client `src`-valid)
2. Expand env/file refs
3. `src.New` for every client (any failure → abort reload, keep old map)
4. Atomic swap (`atomic.Pointer` or equivalent) of Host→handler map
5. Log added/removed/updated client `id`s only — never secrets

**Error table**

| Case | Behavior |
|---|---|
| Boot: bad config | exit 1 |
| Reload: bad config / `src.New` fail | log error; keep serving previous map |
| Unknown Host | 403 |
| Duplicate Host at validate | reject config |

## Security

- Host source: HTTP mode uses `X-Forwarded-Host` only after existing `TRUSTED_PROXIES` peer check; gRPC uses Envoy request attributes. No default/fallback client.
- Per-client cookie `secret` and `cookieNamePrefix` must be distinct across clients (validation fails on collision).
- Docs/examples use `${file:…}` for secrets; `${ENV}` allowed but discouraged.
- Logs may include client `id`; must never include `clientSecret` or cookie `secret`.
- Reload fail-closed; boot fail-hard.
- Shared process ⇒ shared blast radius — document when to split Deployments (cross-tenant, high-value isolation).
- No HTTP admin reload endpoint.
- Existing guidance unchanged: ClusterIP only, NetworkPolicy to gateway, `TRUSTED_PROXIES` for HTTP mode.

## Testing

- Unit: Host match (case, port strip); unknown Host → 403; duplicate host rejected
- Unit: reload success; bad reload keeps old map; SIGHUP triggers reload
- Unit: `${file:…}` expansion per client
- Integration: two clients, different Hosts → different IdP `clientId`s (mocked IdP OK)
- Traefik plugin tests unchanged

## Out of scope

- Middleware / Traefik plugin multi-client
- K8s Operator or CRD
- Per-client TLS on extauth listeners
- Rate limiting
- Keeping JSON single-client config compatibility

## Migration

1. Convert each old single-client `config.json` into one entry under `clients:` with explicit `hosts`
2. Rename/relocate to `config.yaml`; point `CONFIG_FILE` at it
3. Move secrets into files; replace inline secrets with `${file:…}`
4. Roll Deployments; remove N−1 redundant Deployments once Hosts are consolidated

## Success criteria

- One `extauth-server` Deployment serves ≥2 OIDC clients selected by Host
- Config/Secret update reloads without process restart (file watch and/or SIGHUP)
- Invalid reload does not disrupt existing clients
- Unknown Host returns 403
- No changes required to Traefik middleware plugin behavior
