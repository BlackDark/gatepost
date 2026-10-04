package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	src "github.com/BlackDark/gatepost/src"
)

func main() {
	configPath := configFilePath()

	trustedProxies, err := parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gatepost-extauthz: invalid TRUSTED_PROXIES: %v\n", err)
		os.Exit(1)
	}
	if len(trustedProxies) == 0 {
		fmt.Println("gatepost-extauthz: WARNING: TRUSTED_PROXIES is unset - X-Forwarded-* headers will not be trusted from any source, all HTTP-mode requests will be treated as their own literal request (no path/method rewriting)")
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9002"
	}

	allow := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		for name, values := range req.Header {
			for _, v := range values {
				rw.Header().Add(name, v)
			}
		}
		rw.WriteHeader(http.StatusOK)
	})

	ctx := context.Background()
	router := newHostRouter()
	factory := handlerFactory(src.New)
	var reloadMu sync.Mutex

	if err := reloadFromFile(ctx, router, configPath, allow, factory); err != nil {
		fmt.Fprintf(os.Stderr, "gatepost-extauthz: config error: %v\n", err)
		os.Exit(1)
	}

	// Log the routing table so an operator can confirm which Host maps to which
	// client without guessing from a 403, and so a mis-keyed config shows up in
	// the startup log rather than only at request time. Re-logged on every hot
	// reload by doReload.
	if startupCfg, err := parseMultiConfigFile(configPath); err == nil {
		for _, c := range startupCfg.Clients {
			fmt.Printf("gatepost-extauthz: client %q serving host(s) %v\n", c.ID, c.Hosts)
		}
	}

	reload := func() {
		doReload(ctx, &reloadMu, router, configPath, allow, factory)
	}
	go watchConfig(ctx, configPath, parseSecretWatchDirs(os.Getenv("SECRET_WATCH_DIRS")), reload)
	go watchSIGHUP(ctx, reload)

	grpcAddr := os.Getenv("GRPC_LISTEN_ADDR")
	if grpcAddr != "" {
		go func() {
			fmt.Printf("gatepost-extauthz (grpc) listening on %s\n", grpcAddr)
			if err := runGRPCServer(grpcAddr, router); err != nil {
				fmt.Fprintf(os.Stderr, "gatepost-extauthz: grpc: %v\n", err)
				os.Exit(1)
			}
		}()
	}

	// Log the routing table so an operator can confirm which Host maps to which
	// client without guessing from a 403, and so a mis-keyed config is visible in
	// the startup log rather than only at request time.
	fmt.Println("gatepost-extauthz: multi-client Host routing — restrict ingress to the gateway (NetworkPolicy); set TRUSTED_PROXIES narrowly for HTTP mode")
	fmt.Printf("gatepost-extauthz listening on %s\n", listenAddr)
	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           forwardedRequest(trustedProxies, router),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "gatepost-extauthz: %v\n", err)
		os.Exit(1)
	}
}

// forwardedRequest rewrites req.Method/URL/RequestURI from the
// X-Forwarded-Method/Proto/Host/Uri headers Traefik's forwardAuth (and
// similar auth_request-style integrations) send describing the client's
// original request, since the auth server itself is always called with a
// fixed address/path.
//
// These headers are only honored when the request's peer address matches
// one of trustedProxies. Without this check, anyone who can reach this
// listener directly (misconfigured Service type, missing NetworkPolicy, a
// compromised pod on the same network) could set X-Forwarded-Uri to an
// arbitrary path - e.g. claiming to be /oidc/callback - and reach code paths
// meant only for the real callback/login/logout routes. This mirrors the
// exact vulnerability class fixed in oauth2-proxy's --trusted-proxy-ip
// (CVE-2026-40575): unconditionally trusting client-suppliable
// X-Forwarded-Uri when a "reverse proxy mode" is enabled.
//
// If trustedProxies is empty, X-Forwarded-* headers are never honored and
// the request is always processed as its own literal request - safe by
// default, but only correct when this service is not actually behind such
// a gateway (e.g. direct testing, or an ext_authz caller that uses the real
// request line/gRPC's structured attributes instead, like Envoy's HTTP and
// gRPC ext_authz do).
func forwardedRequest(trustedProxies []*net.IPNet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !peerIsTrusted(req.RemoteAddr, trustedProxies) {
			next.ServeHTTP(rw, req)
			return
		}

		if method := req.Header.Get("X-Forwarded-Method"); method != "" {
			req.Method = method
		}

		uri := req.Header.Get("X-Forwarded-Uri")
		if uri == "" {
			uri = req.URL.RequestURI()
		}
		parsedURI, err := url.ParseRequestURI(uri)
		if err != nil {
			http.Error(rw, "invalid X-Forwarded-Uri", http.StatusBadRequest)
			return
		}

		// Each proxy in a chain appends its own entry, so the value added by the
		// closest - and only trusted - hop is the RIGHTMOST one. Taking the
		// leftmost would let a client-supplied value win. A proxy that replaces
		// rather than appends emits a single entry, where the two agree.
		if host := lastForwardedValue(req.Header.Get("X-Forwarded-Host")); host != "" {
			req.Host = host
			parsedURI.Host = host
		}
		if proto := lastForwardedValue(req.Header.Get("X-Forwarded-Proto")); proto != "" && validForwardedProto(proto) {
			parsedURI.Scheme = proto
		}

		req.URL = parsedURI
		req.RequestURI = uri

		next.ServeHTTP(rw, req)
	})
}

// lastForwardedValue returns the rightmost entry of a possibly comma-separated
// forwarded header value, trimmed of surrounding whitespace. It returns "" when
// the value is empty or its rightmost entry is blank.
func lastForwardedValue(value string) string {
	if index := strings.LastIndex(value, ","); index >= 0 {
		value = value[index+1:]
	}

	return strings.TrimSpace(value)
}

// validForwardedProto keeps a forwarded scheme to the four values a gateway can
// legitimately assert. Without this, an arbitrary string reaches url.URL.Scheme
// and ends up in absolute URLs this service emits.
func validForwardedProto(proto string) bool {
	switch proto {
	case "http", "https", "ws", "wss":
		return true
	default:
		return false
	}
}

// peerIsTrusted reports whether remoteAddr (an http.Request.RemoteAddr,
// "host:port") falls inside any of trustedProxies. Always false when
// trustedProxies is empty.
func peerIsTrusted(remoteAddr string, trustedProxies []*net.IPNet) bool {
	if len(trustedProxies) == 0 {
		return false
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // RemoteAddr without a port, e.g. in some test contexts
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseTrustedProxies parses a comma-separated list of IPs or CIDR ranges
// from TRUSTED_PROXIES. A bare IP is treated as a /32 (or /128 for IPv6).
func parseTrustedProxies(value string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP or CIDR: %q", entry)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			entry = fmt.Sprintf("%s/%d", entry, bits)
		}

		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR: %q: %w", entry, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}
