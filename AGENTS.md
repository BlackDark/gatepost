# gatepost

OIDC auth for Traefik: Yaegi plugin + ext_authz sidecar.

## Verify

- `mise run check`: build, race tests, gofmt, vet, golangci-lint, govulncheck, E2E TS lint (both Go modules).
- Docker changes: ext_authz image build + smoke tests run in CI (`.github/workflows/testing.yaml`).
- Auth behavior changes: run the Playwright E2E workflows.
- CI gate: `check` (code checks + actionlint, zizmor, strict Renovate validation).

## Stack

Follows https://github.com/BlackDark/agent-presets/blob/main/stack/core.md. Deviations:
- `vendor/` is committed; no mutating dependency commands (CI verifies integrity).
- Plugin Go directive tracks the Traefik E2E compatibility line; sidecar builder image moves independently.
- Playwright E2E is a separate workflow; `mise run check` covers only its lint.

## Map

- `src/`: Traefik plugin and OIDC behavior.
- `cmd/gatepost-extauthz/`: independent Go module and sidecar image.
- `e2e/`: Bun, Biome, Playwright, mock-provider fixtures.

## Rules

- Conventional Commits, one topic per PR; squash unless commits need separate review; `--force-with-lease` only on own branches.
- Tools from `mise.toml`; no global installs.
- No image publishing or release tags from local sessions.
