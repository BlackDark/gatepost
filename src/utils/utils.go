package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type AcceptType struct {
	Type   string
	Weight float64
}

// Expands the environment variable if it is enclosed in ${}. If the variable is not present, the original value is returned.
// Also supports reading the value from a file via ${file:/path/to/file}, eg. to consume a Docker/Kubernetes
// secret mounted as a file, since environment variables can be read by anyone with access to `docker inspect`.
func ExpandEnvironmentVariableString(value string) string {
	after, hasPrefix := strings.CutPrefix(value, "${")

	if hasPrefix {
		variableName, hasSuffix := strings.CutSuffix(after, "}")

		if hasSuffix {
			if filePath, isFile := strings.CutPrefix(variableName, "file:"); isFile {
				fileContent, err := os.ReadFile(filePath)

				if err == nil {
					return strings.TrimSpace(string(fileContent))
				}
			} else {
				variableValue, isDefined := os.LookupEnv(variableName)

				if isDefined {
					return variableValue
				}
			}
		}
	}

	return value
}

func ExpandEnvironmentVariableBoolean(value string, defaultValue bool) (bool, error) {
	after, hasPrefix := strings.CutPrefix(value, "${")

	if hasPrefix {
		variableName, hasSuffix := strings.CutSuffix(after, "}")

		if hasSuffix {
			variableValue, isDefined := os.LookupEnv(variableName)

			if isDefined {
				value = variableValue
			}
		}
	}

	if value == "true" || value == "1" {
		return true, nil
	} else if value == "false" || value == "0" {
		return false, nil
	} else if value != "" {
		return false, fmt.Errorf("invalid boolean value \"%s\": boolean values must be true/false or 1/0", value)
	}

	return defaultValue, nil
}

func UrlIsAbsolute(u *url.URL) bool {
	return u.Scheme != "" && u.Host != ""
}

func ParseUrl(rawUrl string) (*url.URL, error) {
	if rawUrl == "" {
		return nil, errors.New("invalid empty url")
	}
	if !strings.Contains(rawUrl, "://") {
		rawUrl = "https://" + rawUrl
	}
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u.Scheme, "http") {
		return nil, fmt.Errorf("%v is not a valid scheme", u.Scheme)
	}
	return u, nil
}

func getSchemeFromRequest(req *http.Request) string {
	scheme := req.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme
}

func FillHostSchemeFromRequest(req *http.Request, u *url.URL) *url.URL {
	scheme := getSchemeFromRequest(req)
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}
	u.Scheme = scheme
	u.Host = host
	return u
}

func GetFullHost(req *http.Request) string {
	scheme := getSchemeFromRequest(req)
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func EnsureAbsoluteUrl(req *http.Request, url string) string {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}

	host := GetFullHost(req)

	if !strings.HasPrefix(url, "/") {
		url = "/" + url
	}

	return host + url
}

func ParseBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return big.NewInt(0).SetBytes(b), nil
}

func ParseInt(s string) (int, error) {
	v, err := ParseBigInt(s)
	if err != nil {
		return -1, err
	}

	return int(v.Int64()), nil
}

// Purposes for purpose-bound (AAD) encryption. Binding the purpose into the
// GCM additional authenticated data prevents a value sealed for one context
// (e.g. the session cookie) from being replayed into another (e.g. the ?state=
// callback parameter) and silently decrypting to a zero-valued struct.
const (
	PurposeOidcState = "oidc-state"
	PurposeSession   = "session"
)

// additionalDataForPurpose keeps the legacy (empty purpose) ciphertext
// byte-identical to what GCM produces with a nil AAD, so existing callers that
// still use Encrypt/Decrypt can decrypt values produced by older versions.
func additionalDataForPurpose(purpose string) []byte {
	if purpose == "" {
		return nil
	}

	return []byte(purpose)
}

func Encrypt(plaintext string, secret string) (string, error) {
	return EncryptWithPurpose(plaintext, secret, "")
}

func EncryptWithPurpose(plaintext string, secret string, purpose string) (string, error) {
	aesCipher, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return "", err
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), additionalDataForPurpose(purpose))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(ciphertext string, secret string) (string, error) {
	return DecryptWithPurpose(ciphertext, secret, "")
}

func DecryptWithPurpose(ciphertext string, secret string, purpose string) (string, error) {
	if ciphertext == "" {
		return "", errors.New("ciphertext must not be an empty string")
	}

	cipherbytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	aesCipher, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return "", err
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	// The input is fully attacker-controlled (session cookie, ?state= callback
	// parameter), so the length must be validated before slicing: a short input
	// used to panic here and take down the whole Traefik process.
	nonceSize := gcm.NonceSize()
	if len(cipherbytes) < nonceSize {
		return "", fmt.Errorf("invalid ciphertext: got %d bytes, need at least %d bytes for the nonce", len(cipherbytes), nonceSize)
	}

	nonce, sealed := cipherbytes[:nonceSize], cipherbytes[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, sealed, additionalDataForPurpose(purpose))
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func ChunkString(input string, chunkSize int) []string {
	var chunks []string

	for i := 0; i < len(input); i += chunkSize {
		end := i + chunkSize
		if end > len(input) {
			end = len(input)
		}
		chunks = append(chunks, input[i:end])
	}

	return chunks
}

// ValidateRedirectUri checks redirectUri against validUris. Exact matches are always allowed.
// Wildcards are a security-sensitive, operator-controlled opt-in.
func ValidateRedirectUri(redirectUri string, validUris []string, wildcardsEnabled bool) (string, error) {
	if redirectUri == "" {
		return "", nil
	}

	for _, validUri := range validUris {
		if redirectUri == validUri {
			return redirectUri, nil
		}
	}

	if !wildcardsEnabled || unsafeWildcardRedirect(redirectUri) {
		return "", errors.New("invalid redirect uri")
	}

	for _, validUri := range validUris {
		if !strings.Contains(validUri, "*") {
			continue
		}
		if matchUriTemplate(redirectUri, validUri) {
			return redirectUri, nil
		}
	}

	return "", errors.New("invalid redirect uri")
}

func matchUriTemplate(value, template string) bool {
	if template == "*" {
		return true
	}

	valueScheme, valueAuthority, valuePath, valueHasAuthority := splitSchemeAuthorityPath(value)
	templateScheme, templateAuthority, templatePath, templateHasAuthority := splitSchemeAuthorityPath(template)

	if templateHasAuthority != valueHasAuthority {
		return false
	}

	if templateHasAuthority {
		if !strings.EqualFold(templateScheme, valueScheme) {
			return false
		}

		if !validAuthorityTemplate(templateAuthority) ||
			!matchAuthorityTemplate(valueAuthority, templateAuthority) {
			return false
		}
	}

	return matchPathTemplate(valuePath, templatePath)
}

func splitSchemeAuthorityPath(value string) (scheme, authority, pathAndBeyond string, hasAuthority bool) {
	schemeSeparator := strings.Index(value, "://")
	if schemeSeparator == -1 {
		return "", "", value, false
	}

	scheme = value[:schemeSeparator]
	rest := value[schemeSeparator+3:]
	if pathIndex := strings.IndexAny(rest, "/?#"); pathIndex != -1 {
		return scheme, rest[:pathIndex], rest[pathIndex:], true
	}

	return scheme, rest, "", true
}

func matchPathTemplate(value, template string) bool {
	if value == template {
		return true
	}

	// Path wildcards are only supported as the final character. Templates with a
	// query or fragment remain exact-only.
	if !strings.HasSuffix(template, "*") || strings.ContainsAny(template, "?#") {
		return false
	}

	value = stripQueryAndFragment(value)
	prefix := strings.TrimSuffix(template, "*")
	return strings.HasPrefix(value, prefix) || value == strings.TrimSuffix(prefix, "/")
}

func stripQueryAndFragment(value string) string {
	if index := strings.IndexAny(value, "?#"); index != -1 {
		return value[:index]
	}

	return value
}

func matchAuthorityTemplate(value, template string) bool {
	if strings.EqualFold(value, template) {
		return true
	}

	escapedTemplate := regexp.QuoteMeta(template)
	escapedTemplate = strings.ReplaceAll(escapedTemplate, "\\*", "[-A-Za-z0-9_]+")
	regex, err := regexp.Compile(fmt.Sprintf("(?i)^%s$", escapedTemplate))
	if err != nil {
		return false
	}

	return regex.MatchString(value)
}

func validAuthorityTemplate(template string) bool {
	for index, char := range template {
		if char != '*' {
			continue
		}

		beforeBoundary := index == 0 || template[index-1] == '.' || template[index-1] == ':'
		afterBoundary := index == len(template)-1 || template[index+1] == '.' || template[index+1] == ':'
		if !beforeBoundary || !afterBoundary {
			return false
		}
	}

	return true
}

func unsafeWildcardRedirect(value string) bool {
	if strings.HasPrefix(value, "//") {
		return true
	}

	scheme, authority, pathAndBeyond, hasAuthority := splitSchemeAuthorityPath(value)
	if hasAuthority && (scheme == "" || authority == "" || strings.Contains(authority, "@")) {
		return true
	}

	return hasPathTraversal(stripQueryAndFragment(pathAndBeyond))
}

func hasPathTraversal(rawPath string) bool {
	candidate := rawPath
	for i := 0; i < 8; i++ {
		candidate = strings.ReplaceAll(candidate, "\\", "/")
		for _, segment := range strings.Split(candidate, "/") {
			if segment == ".." ||
				(strings.HasPrefix(segment, "..") && len(segment) > 2 &&
					(segment[2] == ';' || segment[2] < ' ')) {
				return true
			}
		}

		decoded, err := url.PathUnescape(candidate)
		if err != nil {
			return true
		}
		if decoded == candidate {
			return false
		}
		candidate = decoded
	}

	// Fail closed on excessive encoding depth.
	return true
}

func ParseAcceptType(raw string) AcceptType {
	// Parse MIME type and parameters
	mimeType, params, err := mime.ParseMediaType(raw)
	if err != nil {
		return AcceptType{}
	}

	weight := 1.0 // Default weight is 1.0

	// Take weight from the "q" parameter if it exists
	if weightString, ok := params["q"]; ok {
		weight, err = strconv.ParseFloat(weightString, 64)
		if err != nil {
			return AcceptType{}
		}
	}

	return AcceptType{
		Type:   mimeType,
		Weight: weight,
	}
}

func ParseAcceptHeader(raw string) []AcceptType {
	var acceptTypes []AcceptType

	for _, part := range strings.Split(raw, ",") {
		acceptType := ParseAcceptType(part)

		if acceptType.Type == "" {
			continue
		}

		acceptTypes = append(acceptTypes, acceptType)
	}

	// Sort by weight in descending order
	sort.Slice(acceptTypes, func(i, j int) bool {
		return acceptTypes[i].Weight > acceptTypes[j].Weight
	})

	return acceptTypes
}

func IsHtmlRequest(req *http.Request) bool {
	acceptTypes := ParseAcceptHeader(req.Header.Get("Accept"))

	if len(acceptTypes) == 0 {
		// Assume it's not an HTML request if no Accept header is present
		return false
	}

	// Assume HTML request have text/html or application/xhtml+xml with the highest weight
	return acceptTypes[0].Type == "text/html" || acceptTypes[0].Type == "application/xhtml+xml"
}
