package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	src "github.com/BlackDark/gatepost/src"
	"github.com/BlackDark/gatepost/src/config"
)

// multiConfig is the gatepost-extauthz YAML root. Breaking change vs single-client JSON.
type multiConfig struct {
	Clients []clientEntry
}

type clientEntry struct {
	ID     string
	Hosts  []string
	Config *config.Config
}

// normalizeHost canonicalises a Host for both the configured hosts and the incoming
// request Host, so a client is reachable under exactly one key. It lowercases, strips the
// port and strips a single trailing FQDN dot ("grafana.example.com." is the same host as
// "grafana.example.com" - RFC 1035 5.1 - and some clients send the fully-qualified form).
// The trailing dot must be stripped on BOTH sides: stripping only the incoming Host would
// leave a configured "example.com." unreachable, and stripping only the configured side
// would 403 the dotted request spelling.
func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}

func parseMultiConfigFile(path string) (*multiConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CONFIG_FILE is operator-supplied deployment config
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return parseMultiConfig(data)
}

func parseMultiConfig(data []byte) (*multiConfig, error) {
	var raw struct {
		Clients []yaml.Node `yaml:"clients"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}
	if len(raw.Clients) == 0 {
		return nil, errors.New("clients: must contain at least one client")
	}

	out := &multiConfig{Clients: make([]clientEntry, 0, len(raw.Clients))}
	for i, node := range raw.Clients {
		var meta struct {
			ID    string   `yaml:"id"`
			Hosts []string `yaml:"hosts"`
		}
		if err := node.Decode(&meta); err != nil {
			return nil, fmt.Errorf("clients[%d]: %w", i, err)
		}
		if meta.ID == "" {
			return nil, fmt.Errorf("clients[%d]: id is required", i)
		}
		if len(meta.Hosts) == 0 {
			return nil, fmt.Errorf("clients[%d] (%s): hosts must be non-empty", i, meta.ID)
		}

		cfg := src.CreateConfig()
		if err := node.Decode(cfg); err != nil {
			return nil, fmt.Errorf("clients[%d] (%s): %w", i, meta.ID, err)
		}
		if err := rejectNilSubStructs(cfg); err != nil {
			return nil, fmt.Errorf("clients[%d] (%s): %w", i, meta.ID, err)
		}
		out.Clients = append(out.Clients, clientEntry{
			ID:     meta.ID,
			Hosts:  meta.Hosts,
			Config: cfg,
		})
	}

	if err := validateMultiConfig(out); err != nil {
		return nil, err
	}
	return out, nil
}

// rejectNilSubStructs refuses a configuration in which a pointer sub-struct that src.New
// (or the request path it installs) dereferences unconditionally was set to YAML null.
//
// Why REJECT instead of substituting a default: the sub-structs below are exactly the ones
// src.CreateConfig() pre-fills, so a null means the operator explicitly wrote `key: null` and
// is asserting "no value here". Silently re-defaulting would contradict that assertion and
// apply a security-relevant default the operator asked to remove - `sessionCookie: null`
// would quietly become Secure/HttpOnly/SameSite=lax again, and `authorization: null` would
// quietly become "no claim assertions", which is a permissive default for an access-control
// setting. Rejecting keeps the promise the docs make ("bad reload keeps the previous map"):
// parseMultiConfig returns an error, the reload is skipped, and the previous map keeps
// serving every tenant. Fail-closed and honest beats silently doing something else.
//
// Provider is handled here too even though src.New also nil-checks it, so that the error
// names the offending key and client instead of surfacing as a generic src.New error.
func rejectNilSubStructs(cfg *config.Config) error {
	if cfg.Provider == nil {
		return errors.New("provider must not be null")
	}
	if cfg.SessionCookie == nil {
		return errors.New("sessionCookie must not be null (omit the key to accept its defaults)")
	}
	if cfg.AuthorizationHeader == nil {
		return errors.New("authorizationHeader must not be null (omit the key to accept its defaults)")
	}
	if cfg.AuthorizationCookie == nil {
		return errors.New("authorizationCookie must not be null (omit the key to accept its defaults)")
	}
	if cfg.Authorization == nil {
		return errors.New("authorization must not be null (omit the key to accept its defaults)")
	}
	if cfg.ErrorPages == nil {
		return errors.New("errorPages must not be null (omit the key to accept its defaults)")
	}
	if cfg.ErrorPages.Unauthenticated == nil {
		return errors.New("errorPages.unauthenticated must not be null (omit the key to accept its defaults)")
	}
	if cfg.ErrorPages.Unauthorized == nil {
		return errors.New("errorPages.unauthorized must not be null (omit the key to accept its defaults)")
	}
	return nil
}

func validateMultiConfig(cfg *multiConfig) error {
	ids := make(map[string]string, len(cfg.Clients))
	hosts := make(map[string]string) // host -> client id
	prefixes := make(map[string]string)
	secrets := make(map[string]string)

	for _, c := range cfg.Clients {
		if prev, ok := ids[c.ID]; ok {
			return fmt.Errorf("duplicate id %q (also used by %s)", c.ID, prev)
		}
		ids[c.ID] = c.ID

		prefix := c.Config.CookieNamePrefix
		if prev, ok := prefixes[prefix]; ok {
			return fmt.Errorf("duplicate cookieNamePrefix %q for clients %q and %q", prefix, prev, c.ID)
		}
		prefixes[prefix] = c.ID

		// Unconditional on purpose, including "" and config.DefaultSecret. src.New rejects
		// both values, so today this check only changes WHICH error an operator sees - but the
		// uniqueness of the cookie sealing key is a stated invariant of the multi-client
		// surface, and a conditional check is an invariant that silently stops holding the
		// moment empty or default becomes legal. cookieNamePrefix has no such exemption
		// either; both checks must be equally strict or the weaker one is a trap for the next
		// person editing this file.
		if prev, ok := secrets[c.Config.Secret]; ok {
			return fmt.Errorf("duplicate secret for clients %q and %q", prev, c.ID)
		}
		secrets[c.Config.Secret] = c.ID

		seen := make(map[string]struct{}, len(c.Hosts))
		for _, h := range c.Hosts {
			n := normalizeHost(h)
			if n == "" {
				return fmt.Errorf("client %q: empty host", c.ID)
			}
			if err := validateHostPattern(n); err != nil {
				return fmt.Errorf("client %q: %w", c.ID, err)
			}
			if _, ok := seen[n]; ok {
				continue // same client listing aliases that normalize equal
			}
			seen[n] = struct{}{}
			if prev, ok := hosts[n]; ok {
				return fmt.Errorf("duplicate host %q for clients %q and %q", n, prev, c.ID)
			}
			hosts[n] = c.ID
		}
	}
	return nil
}
