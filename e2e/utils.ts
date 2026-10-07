import * as fs from 'node:fs';
import * as path from 'node:path';

const ROUTERS_API = 'http://localhost:8080/api/http/routers';
const MIDDLEWARES_API = 'http://localhost:8080/api/http/middlewares';

// Bounded wait for Traefik to apply a rewritten file-provider config. Overridable so a
// debugging run can extend it without editing the file.
const CONFIG_WAIT_TIMEOUT_MS = Number(process.env.E2E_CONFIG_WAIT_MS ?? 90_000);

type TraefikRouter = { name?: string; provider?: string };
type TraefikMiddleware = {
  name?: string;
  provider?: string;
  plugin?: { gatepost?: { CookieNamePrefix?: string } };
};

function routerNamesFromYaml(yaml: string): string[] {
  const match = yaml.match(/(?:^|\n) {2}routers:\n([\s\S]*?)(?=\n {2}\w|\n*$)/);
  if (!match) return [];
  return [...match[1].matchAll(/^ {4}([\w-]+):/gm)].map((m) => m[1]);
}

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function fileRouterNames(): Promise<string[] | null> {
  const routers = await fetchJson<TraefikRouter[]>(ROUTERS_API);
  if (!Array.isArray(routers)) return null;
  return routers.flatMap((r) => {
    if (r.provider !== 'file' || typeof r.name !== 'string') return [];
    return [r.name.replace(/@file$/, '')];
  });
}

async function fileOidcPrefixes(): Promise<string[] | null> {
  const middlewares = await fetchJson<TraefikMiddleware[]>(MIDDLEWARES_API);
  if (!Array.isArray(middlewares)) return null;
  return middlewares
    .filter((m) => m.provider === 'file' && m.plugin?.gatepost)
    .map((m) => m.plugin?.gatepost?.CookieNamePrefix ?? '');
}

export async function configureTraefik(
  yaml: string,
  opts?: {
    /**
     * Filename written under e2e/. Defaults to ".http.yml" so the original
     * mock-oidc suite is untouched.
     *
     * A second suite (mock-oidc-tls) MUST pass its own filename. Every write
     * stamps a fresh CookieNamePrefix and both suites bind-mount their file to
     * the same in-container path, so a shared fixed name means one Playwright
     * project's beforeAll/test overwrites the other project's Traefik config
     * mid-run — which fails as a mystery "router not found" rather than as the
     * obvious file collision it is.
     */
    file?: string;
    /**
     * Set false to skip the wait-for-apply loop entirely (default true).
     *
     * The loop throws "Traefik config not ready" once the deadline passes,
     * which is correct for a config Traefik is expected to accept. It is
     * actively wrong for the negative cases: a config the plugin rejects in
     * New() is NEVER applied, so the wait can only ever time out and bury the
     * real signal (the plugin's own error log) under an unrelated failure.
     */
    wait?: boolean;
  },
) {
  const filePath = path.join(__dirname, opts?.file ?? '.http.yml');
  const marker = `e2e${Date.now()}`;
  // Anchored to a line start: `gatepost:` is short enough to appear inside an
  // image ref, URL, or comment, and a bare global replace would stamp a bogus
  // CookieNamePrefix into whatever it happened to match first.
  const stamped = yaml.replace(
    /^(\s*)gatepost:/gm,
    (_match, indent: string) => `${indent}gatepost:\n${indent}  CookieNamePrefix: "${marker}"`,
  );
  const expectedRouters = routerNamesFromYaml(stamped).sort();
  fs.writeFileSync(filePath, stamped);

  if (opts?.wait === false) {
    return;
  }

  // beforeAll writes config before Traefik is up — nothing to wait on.
  if ((await fileRouterNames()) === null) {
    return;
  }

  // Traefik picks up a rewritten file provider config on its own schedule, and on a
  // loaded CI runner that can take a while - especially when the plugin under test has to
  // re-run OIDC discovery. 20s was short enough to flake on a busy runner. The wait is
  // bounded so a genuine failure still surfaces instead of hanging.
  const deadline = Date.now() + CONFIG_WAIT_TIMEOUT_MS;
  let last = '';
  while (Date.now() < deadline) {
    const routers = ((await fileRouterNames()) ?? []).sort();
    const prefixes = (await fileOidcPrefixes()) ?? [];
    last = `routers=[${routers.join(',')}] prefixes=[${prefixes.join(',')}]`;

    const routersReady =
      expectedRouters.length > 0 &&
      routers.length === expectedRouters.length &&
      expectedRouters.every((name, i) => name === routers[i]);

    const middlewaresReady = prefixes.length > 0 && prefixes.every((prefix) => prefix === marker);

    if (routersReady && middlewaresReady) {
      await new Promise((r) => setTimeout(r, 200));
      return;
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  throw new Error(`Traefik config not ready. ${last}`);
}
