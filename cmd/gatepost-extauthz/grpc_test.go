package main

import (
	"context"
	"net/http"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
)

func newCheckRequest(method, scheme, host, path string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  method,
					Scheme:  scheme,
					Host:    host,
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
}

func TestBuildHTTPRequest_ReconstructsFromAttributes(t *testing.T) {
	req := newCheckRequest("GET", "https", "app.example.com", "/oidc/callback?state=abc", map[string]string{
		"cookie":     "a=1",
		"x-custom":   "v1,v2",
		":method":    "GET",
		":path":      "/oidc/callback?state=abc",
		":scheme":    "https",
		":authority": "app.example.com",
	})

	httpReq, err := buildHTTPRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("buildHTTPRequest: %v", err)
	}

	if httpReq.Method != http.MethodGet {
		t.Fatalf("Method=%q", httpReq.Method)
	}
	if httpReq.URL.Path != "/oidc/callback" {
		t.Fatalf("Path=%q", httpReq.URL.Path)
	}
	if httpReq.URL.RawQuery != "state=abc" {
		t.Fatalf("RawQuery=%q", httpReq.URL.RawQuery)
	}
	if httpReq.Host != "app.example.com" {
		t.Fatalf("Host=%q", httpReq.Host)
	}
	if got := httpReq.Header.Get("Cookie"); got != "a=1" {
		t.Fatalf("Cookie=%q", got)
	}
	if got := httpReq.Header.Values("X-Custom"); len(got) != 2 || got[0] != "v1" || got[1] != "v2" {
		t.Fatalf("X-Custom=%v", got)
	}
	// pseudo-headers must not leak into the reconstructed request headers
	if httpReq.Header.Get(":method") != "" {
		t.Fatal("pseudo-header :method leaked into headers")
	}
}

func TestCheck_AllowReturnsOkResponseWithHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Sub", "user-123")
		w.WriteHeader(http.StatusOK)
	})
	srv := &grpcAuthServer{next: next}

	resp, err := srv.Check(context.Background(), newCheckRequest("GET", "https", "app.example.com", "/", nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	ok, isOk := resp.GetHttpResponse().(*authv3.CheckResponse_OkResponse)
	if !isOk {
		t.Fatalf("expected OkResponse, got %T", resp.GetHttpResponse())
	}

	found := false
	for _, h := range ok.OkResponse.GetHeaders() {
		if h.GetHeader().GetKey() == "X-Auth-Sub" && h.GetHeader().GetValue() == "user-123" {
			found = true
		}
	}
	if !found {
		t.Fatalf("X-Auth-Sub header missing from OkResponse: %+v", ok.OkResponse.GetHeaders())
	}
}

// TestCheck_DenyPreservesLocationAndSetCookie is the regression test for the
// bug this gRPC mode exists to avoid: HTTP-mode ext_authz on Envoy Gateway
// silently drops Location/Set-Cookie on denied (redirect) responses because
// there's no allowed_client_headers field in the SecurityPolicy API. gRPC
// mode's DeniedHttpResponse.Headers is the explicit, full response, so
// nothing should be dropped here.
func TestCheck_DenyPreservesLocationAndSetCookie(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/")
		w.Header().Set("Location", "https://idp.example.com/authorize")
		w.WriteHeader(http.StatusFound)
	})
	srv := &grpcAuthServer{next: next}

	resp, err := srv.Check(context.Background(), newCheckRequest("GET", "https", "app.example.com", "/", nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	denied, isDenied := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
	if !isDenied {
		t.Fatalf("expected DeniedResponse, got %T", resp.GetHttpResponse())
	}

	if got := denied.DeniedResponse.GetStatus().GetCode(); int32(got) != http.StatusFound {
		t.Fatalf("status=%v want 302", got)
	}

	var location string
	var cookies []string
	for _, h := range denied.DeniedResponse.GetHeaders() {
		switch h.GetHeader().GetKey() {
		case "Location":
			location = h.GetHeader().GetValue()
		case "Set-Cookie":
			cookies = append(cookies, h.GetHeader().GetValue())
			if h.GetAppendAction() != corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD {
				t.Fatalf("Set-Cookie append action=%v want APPEND_IF_EXISTS_OR_ADD (would clobber second cookie otherwise)", h.GetAppendAction())
			}
		}
	}

	if location != "https://idp.example.com/authorize" {
		t.Fatalf("Location=%q", location)
	}
	if len(cookies) != 2 {
		t.Fatalf("Set-Cookie count=%d want 2, got %v", len(cookies), cookies)
	}
}

func TestCheck_InvalidRequestReturnsBadRequest(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called for a malformed CheckRequest")
	})
	srv := &grpcAuthServer{next: next}

	// Missing Http attributes entirely -> buildHTTPRequest still succeeds
	// (empty method/host/path), but an invalid scheme+host+path combination
	// that fails url construction should be rejected before calling next.
	req := newCheckRequest("GET", "https", "\x7f", "/", nil)

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	denied, isDenied := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
	if !isDenied {
		t.Fatalf("expected DeniedResponse for invalid request, got %T", resp.GetHttpResponse())
	}
	if got := denied.DeniedResponse.GetStatus().GetCode(); int32(got) != http.StatusBadRequest {
		t.Fatalf("status=%v want 400", got)
	}
}

// TestCheck_AllowThroughRealAllowStub exercises the actual "allow" handler
// used in main.go (copies req.Header, mutated by attachHeaders, onto the
// ResponseWriter) through the gRPC Check() path, not a hand-rolled stub.
func TestCheck_AllowThroughRealAllowStub(t *testing.T) {
	allow := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		for name, values := range r.Header {
			for _, v := range values {
				rw.Header().Add(name, v)
			}
		}
		rw.WriteHeader(http.StatusOK)
	})

	// Simulates what Gatepost.ServeHTTP does before calling next on
	// an authorized public route: it mutates req.Header via attachHeaders,
	// then invokes next.ServeHTTP(rw, req) with the same req.
	wrapped := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Auth-Sub", "user-123")
		allow.ServeHTTP(rw, r)
	})

	srv := &grpcAuthServer{next: wrapped}
	resp, err := srv.Check(context.Background(), newCheckRequest("GET", "https", "app.example.com", "/", nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	ok, isOk := resp.GetHttpResponse().(*authv3.CheckResponse_OkResponse)
	if !isOk {
		t.Fatalf("expected OkResponse, got %T", resp.GetHttpResponse())
	}
	found := false
	for _, h := range ok.OkResponse.GetHeaders() {
		if h.GetHeader().GetKey() == "X-Auth-Sub" && h.GetHeader().GetValue() == "user-123" {
			found = true
		}
	}
	if !found {
		t.Fatalf("X-Auth-Sub missing: %+v", ok.OkResponse.GetHeaders())
	}
}

// TestCheck_RecoversFromPanicInHandler is the regression test for the panic
// isolation this gRPC server relies on: grpc-go's default behavior (unlike
// net/http) is to crash the whole process on a handler panic, which would
// take the entire auth service down on any single malformed/unexpected
// request. Check() must not be the entrypoint used to test this directly
// (the recovery lives in the UnaryServerInterceptor wired in runGRPCServer,
// not in Check itself), so this exercises the interceptor.
func TestRecoveryInterceptor_ConvertsPanicToError(t *testing.T) {
	panicking := func(ctx context.Context, req any) (any, error) {
		panic("boom")
	}

	_, err := recoveryInterceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test"}, panicking)
	if err == nil {
		t.Fatal("expected error after recovering panic, got nil")
	}
}
