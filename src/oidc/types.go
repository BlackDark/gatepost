package oidc

import "sort"

// OidcDiscovery represents the discovered OIDC endpoints
type OidcDiscovery struct {
	AcrValuesSupported                                        []string `json:"acr_values_supported"`
	AuthorizationEncryptionAlgValuesSupported                 []string `json:"authorization_encryption_alg_values_supported"`
	AuthorizationEncryptionEncValuesSupported                 []string `json:"authorization_encryption_enc_values_supported"`
	AuthorizationEndpoint                                     string   `json:"authorization_endpoint"`
	AuthorizationSigningAlgValuesSupported                    []string `json:"authorization_signing_alg_values_supported"`
	BackchannelAuthenticationEndpoint                         string   `json:"backchannel_authentication_endpoint"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported"`
	BackchannelLogoutSessionSupported                         bool     `json:"backchannel_logout_session_supported"`
	BackchannelLogoutSupported                                bool     `json:"backchannel_logout_supported"`
	BackchannelTokenDeliveryModesSupported                    []string `json:"backchannel_token_delivery_modes_supported"`
	CheckSessionIframe                                        string   `json:"check_session_iframe"`
	ClaimsParameterSupported                                  bool     `json:"claims_parameter_supported"`
	ClaimsSupported                                           []string `json:"claims_supported"`
	ClaimTypesSupported                                       []string `json:"claim_types_supported"`

	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported"`
	DeviceAuthorizationEndpoint                        string   `json:"device_authorization_endpoint"`
	DisplayValuesSupported                             []string `json:"display_values_supported"`
	EndSessionEndpoint                                 string   `json:"end_session_endpoint"`
	FrontchannelLogoutSessionSupported                 bool     `json:"frontchannel_logout_session_supported"`
	FrontchannelLogoutSupported                        bool     `json:"frontchannel_logout_supported"`
	GrantTypesSupported                                []string `json:"grant_types_supported"`
	HttpLogoutSupported                                bool     `json:"http_logout_supported"`
	IdTokenEncryptionAlgValuesSupported                []string `json:"id_token_encryption_alg_values_supported"`
	IdTokenEncryptionEncValuesSupported                []string `json:"id_token_encryption_enc_values_supported"`
	IdTokenSigningAlgValuesSupported                   []string `json:"id_token_signing_alg_values_supported"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	Issuer                                             string   `json:"issuer"`
	JWKSURI                                            string   `json:"jwks_uri"`

	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`

	RegistrationEndpoint                            string   `json:"registration_endpoint"`
	RequestObjectEncryptionAlgValuesSupported       []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported       []string `json:"request_object_encryption_enc_values_supported"`
	RequestObjectSigningAlgValuesSupported          []string `json:"request_object_signing_alg_values_supported"`
	RequestParameterSupported                       bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported                    bool     `json:"request_uri_parameter_supported"`
	RequirePushedAuthorizationRequests              bool     `json:"require_pushed_authorization_requests"`
	RequireRequestUriRegistration                   bool     `json:"require_request_uri_registration"`
	ResponseModesSupported                          []string `json:"response_modes_supported"`
	ResponseTypesSupported                          []string `json:"response_types_supported"`
	RevocationEndpoint                              string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported          []string `json:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                                 []string `json:"scopes_supported"`
	SubjectTypesSupported                           []string `json:"subject_types_supported"`

	TlsClientCertificateBoundAccessTokens      bool     `json:"tls_client_certificate_bound_access_tokens"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`

	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported"`
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported"`
	UserinfoEndpoint                     string   `json:"userinfo_endpoint"`
	UserinfoSigningAlgValuesSupported    []string `json:"userinfo_signing_alg_values_supported"`
}

// AllowedAlgorithms returns the signing algorithms this plugin accepts, taken from
// the single allowlist in jwks.go so a token parser can never end up with a
// different (looser or stricter) set than the key lookup.
func AllowedAlgorithms() []string {
	algs := make([]string, 0, len(allowedAlgorithms))
	for alg := range allowedAlgorithms {
		algs = append(algs, alg)
	}

	sort.Strings(algs)

	return algs
}

type OidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}
