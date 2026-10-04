package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHostRouter_RoutesByHost(t *testing.T) {
	var hitA, hitB atomic.Int32
	r := newHostRouter()
	r.swap(map[string]http.Handler{
		"a.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			hitA.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		"b.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			hitB.Add(1)
			w.WriteHeader(http.StatusAccepted)
		}),
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://a.example.com/x", nil)
	req.Host = "A.example.com:443"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK || hitA.Load() != 1 {
		t.Fatalf("A: code=%d hitA=%d", rw.Code, hitA.Load())
	}

	rw = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://b.example.com/x", nil)
	req.Host = "b.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusAccepted || hitB.Load() != 1 {
		t.Fatalf("B: code=%d hitB=%d", rw.Code, hitB.Load())
	}
}

func TestHostRouter_UnknownHostForbidden(t *testing.T) {
	r := newHostRouter()
	r.swap(map[string]http.Handler{
		"a.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	req.Host = "unknown.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
}

func TestHostRouter_WildcardFallback(t *testing.T) {
	var hitExact, hitWild atomic.Int32
	r := newHostRouter()
	r.swap(map[string]http.Handler{
		"grafana.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			hitExact.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		"*.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			hitWild.Add(1)
			w.WriteHeader(http.StatusAccepted)
		}),
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://grafana.example.com/", nil)
	req.Host = "grafana.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK || hitExact.Load() != 1 || hitWild.Load() != 0 {
		t.Fatalf("exact should win: code=%d exact=%d wild=%d", rw.Code, hitExact.Load(), hitWild.Load())
	}

	rw = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://other.example.com/", nil)
	req.Host = "other.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusAccepted || hitWild.Load() != 1 {
		t.Fatalf("wildcard: code=%d wild=%d", rw.Code, hitWild.Load())
	}

	// apex must not match *.example.com
	rw = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("apex status=%d want 403", rw.Code)
	}
}

func TestHostRouter_SwapAtomic(t *testing.T) {
	r := newHostRouter()
	r.swap(map[string]http.Handler{
		"a.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})
	r.swap(map[string]http.Handler{
		"a.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://a.example.com/", nil)
	req.Host = "a.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusTeapot {
		t.Fatalf("status=%d want 418 after swap", rw.Code)
	}
}

// Finding 6: a fully-qualified Host ("a.example.com.", RFC 1035 5.1) is the same host as the
// relative spelling, and some clients send the dotted form. normalizeHost strips the dot on
// BOTH sides, so an exact tenant and a wildcard tenant must both match with and without it.
func TestLookupHost_TrailingDot(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {})
	m := map[string]http.Handler{
		"tenant-a.example.com": ok,
		"*.wild.example.com":   ok,
	}
	for _, host := range []string{
		"tenant-a.example.com",
		"tenant-a.example.com.",
		"TENANT-A.EXAMPLE.COM.:8443",
		"sub.wild.example.com",
		"sub.wild.example.com.",
		"xn--80ak6aa92e.com.", // never matches: different tenant, proves the dot is not the reason
	} {
		h, matched := lookupHost(m, host)
		if host == "xn--80ak6aa92e.com." {
			if matched {
				t.Fatalf("lookupHost(%q) matched an unrelated host", host)
			}
			continue
		}
		if !matched || h == nil {
			t.Errorf("lookupHost(%q) did not match; a trailing FQDN dot must be ignored", host)
		}
	}
}

// The exact match must still win over the wildcard when the request carries a trailing dot.
func TestHostRouter_TrailingDotPrefersExact(t *testing.T) {
	r := newHostRouter()
	r.swap(map[string]http.Handler{
		"grafana.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) }),
		"*.example.com":       http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusAccepted) }),
	})
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://grafana.example.com/", nil)
	req.Host = "grafana.example.com.:443"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("code=%d want 200 from the exact tenant, not the wildcard", rw.Code)
	}
}
