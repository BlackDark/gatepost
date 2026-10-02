package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

type hostRouter struct {
	hosts atomic.Pointer[map[string]http.Handler]
}

func newHostRouter() *hostRouter {
	r := &hostRouter{}
	empty := map[string]http.Handler{}
	r.hosts.Store(&empty)
	return r
}

func (r *hostRouter) swap(m map[string]http.Handler) {
	r.hosts.Store(&m)
}

func (r *hostRouter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	m := *r.hosts.Load()
	h, ok := lookupHost(m, req.Host)
	if !ok {
		http.Error(rw, "unknown host", http.StatusForbidden)
		return
	}
	h.ServeHTTP(rw, req)
}

// validateHostPattern rejects host patterns that can never match a real client.
//
// lookupHost only treats a key as a wildcard when it carries the "*." prefix, and it
// requires the incoming host to be strictly longer than the ".suffix". So:
//
//   - "*" is stored under the literal key "*", matches only a request whose Host header is
//     literally "*", which no client ever sends - it silently 403s every request including
//     the operator's own.
//   - "*.ab" / "*.com" are a public-suffix-wide catch: "*.com" matches every .com host in
//     existence. There is no public-suffix list in this process, so any suffix without an
//     inner dot is refused rather than silently widened to a whole TLD.
//
// Error names the offending key so the operator knows which line to delete.
func validateHostPattern(n string) error {
	if !strings.Contains(n, "*") {
		return nil
	}
	if n == "*" {
		return fmt.Errorf("host %q matches nothing: list the concrete hostnames, or use an explicit %q pattern", n, "*.example.com")
	}
	if !strings.HasPrefix(n, "*.") {
		return fmt.Errorf("invalid wildcard host %q: a wildcard is only supported as the whole leftmost label, i.e. %q", n, "*.example.com")
	}
	if suffix := n[1:]; !strings.Contains(suffix[1:], ".") {
		return fmt.Errorf("invalid wildcard host %q: the wildcard suffix must be a domain with at least two labels, i.e. %q", n, "*.example.com")
	}
	return nil
}

// lookupHost prefers exact Host match, then longest *.suffix wildcard.
func lookupHost(m map[string]http.Handler, host string) (http.Handler, bool) {
	host = normalizeHost(host)
	if h, ok := m[host]; ok {
		return h, true
	}

	var best string
	var bestH http.Handler
	for pattern, h := range m {
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		suffix := pattern[1:] // ".example.com"
		if !strings.HasSuffix(host, suffix) || len(host) <= len(suffix) {
			continue
		}
		if len(pattern) >= len(best) {
			best = pattern
			bestH = h
		}
	}
	if best == "" {
		return nil, false
	}
	return bestH, true
}
