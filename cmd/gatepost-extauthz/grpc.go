// gRPC ext_authz mode (envoy.service.auth.v3.Authorization/Check).
//
// Unlike HTTP mode, Envoy's gRPC ext_authz sends the client's original
// method/path/host/scheme as structured fields on CheckRequest, so no
// X-Forwarded-* parsing is needed here - buildHTTPRequest reconstructs the
// request directly. The response is captured via httptest.NewRecorder()
// (Gatepost.ServeHTTP writes straight to a http.ResponseWriter) and
// translated into a CheckResponse. Because DeniedHttpResponse.Headers is the
// full, explicit response Envoy sends to the client, this mode isn't subject
// to the ext_authz HTTP mode allowed_client_headers gap that drops
// Location/Set-Cookie on redirect-based deny responses.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type grpcAuthServer struct {
	authv3.UnimplementedAuthorizationServer
	next http.Handler
}

func (s *grpcAuthServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq, err := buildHTTPRequest(ctx, req)
	if err != nil {
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.InvalidArgument)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_BadRequest},
					Body:   err.Error(),
				},
			},
		}, nil
	}

	rec := httptest.NewRecorder()
	s.next.ServeHTTP(rec, httpReq)
	result := rec.Result()
	defer result.Body.Close()

	if result.StatusCode >= 200 && result.StatusCode < 300 {
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{
					Headers: headerValueOptions(result.Header),
				},
			},
		}, nil
	}

	body := rec.Body.String()
	statusCode := result.StatusCode
	if statusCode < 100 || statusCode > 599 {
		statusCode = http.StatusInternalServerError
	}
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode(statusCode)}, //nolint:gosec // bounds-checked above
				Headers: headerValueOptions(result.Header),
				Body:    body,
			},
		},
	}, nil
}

// buildHTTPRequest reconstructs the client's original request from the
// structured CheckRequest attributes (method/path/host/scheme/headers/body),
// matching what Gatepost.ServeHTTP expects from a real *http.Request.
func buildHTTPRequest(ctx context.Context, req *authv3.CheckRequest) (*http.Request, error) {
	httpAttrs := req.GetAttributes().GetRequest().GetHttp()

	scheme := httpAttrs.GetScheme()
	if scheme == "" {
		scheme = "https"
	}
	host := httpAttrs.GetHost()
	path := httpAttrs.GetPath()

	httpReq, err := http.NewRequestWithContext(ctx, httpAttrs.GetMethod(), scheme+"://"+host+path, strings.NewReader(httpAttrs.GetBody()))
	if err != nil {
		return nil, err
	}
	httpReq.Host = host
	httpReq.RequestURI = path

	for key, value := range httpAttrs.GetHeaders() {
		if key == ":authority" || key == ":method" || key == ":path" || key == ":scheme" {
			continue
		}
		for _, v := range strings.Split(value, ",") {
			httpReq.Header.Add(key, strings.TrimSpace(v))
		}
	}

	return httpReq, nil
}

// headerValueOptions converts an http.Header into the repeated
// HeaderValueOption Envoy expects, preserving multi-value headers
// (e.g. multiple Set-Cookie) as separate appended entries rather than
// overwriting each other.
func headerValueOptions(h http.Header) []*corev3.HeaderValueOption {
	var out []*corev3.HeaderValueOption
	for name, values := range h {
		for _, v := range values {
			out = append(out, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   name,
					Value: v,
				},
				AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
			})
		}
	}
	return out
}

func runGRPCServer(listenAddr string, next http.Handler) error {
	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(recoveryInterceptor),
		grpc.ConnectionTimeout(10*time.Second),
	)
	authv3.RegisterAuthorizationServer(grpcServer, &grpcAuthServer{next: next})

	return grpcServer.Serve(lis)
}

// recoveryInterceptor prevents a panic in Gatepost.ServeHTTP (e.g. an
// unexpected claim shape or malformed request) from crashing the whole
// process, which is grpc-go's default behavior for handler panics (unlike
// net/http, which only aborts the one connection).
func recoveryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("gatepost-extauthz: panic in %s: %v\n%s\n", info.FullMethod, r, debug.Stack())
			err = errors.New("internal error")
		}
	}()
	return handler(ctx, req)
}
