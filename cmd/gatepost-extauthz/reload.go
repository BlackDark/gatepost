package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/BlackDark/gatepost/src/config"
)

type handlerFactory func(ctx context.Context, next http.Handler, cfg *config.Config, name string) (http.Handler, error)

func buildHostMap(ctx context.Context, cfg *multiConfig, next http.Handler, factory handlerFactory) (map[string]http.Handler, error) {
	out := make(map[string]http.Handler)
	secrets := make(map[string]string, len(cfg.Clients))
	for _, c := range cfg.Clients {
		h, err := factory(ctx, next, c.Config, "gatepost-extauthz/"+c.ID)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", c.ID, err)
		}
		// src.New expands ${file:...} in place — enforce distinct cookie secrets after expand.
		// Unconditional, including an empty expanded secret: a ${file:...} ref that expands
		// to "" (or to a file that does not exist, since expansion is best-effort) must not
		// slip past the uniqueness invariant, and the strictness must match the pre-expansion
		// check in validateMultiConfig so both surfaces enforce the same rule.
		if prev, ok := secrets[c.Config.Secret]; ok {
			return nil, fmt.Errorf("duplicate secret after expand for clients %q and %q", prev, c.ID)
		}
		secrets[c.Config.Secret] = c.ID
		for _, host := range c.Hosts {
			out[normalizeHost(host)] = h
		}
	}
	return out, nil
}

func reloadFromFile(ctx context.Context, r *hostRouter, path string, next http.Handler, factory handlerFactory) error {
	cfg, err := parseMultiConfigFile(path)
	if err != nil {
		return err
	}
	m, err := buildHostMap(ctx, cfg, next, factory)
	if err != nil {
		return err
	}
	r.swap(m)
	return nil
}
