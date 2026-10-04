package src

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/BlackDark/gatepost/src/config"
)

// WHY THIS FILE EXISTS
//
// Traefik decodes plugin configuration with mapstructure, NOT encoding/json, and it does
// NOT set DecoderConfig.TagName. See Traefik v3.5, pkg/plugins/middlewareyaegi.go:93-102:
//
//	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
//		DecodeHook:       mapstructure.StringToSliceHookFunc(","),
//		WeaklyTypedInput: true,
//		Result:           vConfig,
//	})
//
// With no TagName, mapstructure falls back to the GO FIELD NAME and matches it
// case-insensitively; the `json:"..."` struct tags in src/config/config.go are ignored
// entirely on the Traefik path. So a plugin option documented as `max_session_lifetime_seconds`
// decodes to the zero value and every Traefik deployment silently loses that security control.
//
// The `json:"..."` tags are NOT what cmd/gatepost-extauthz reads any more. That service loads a
// YAML multi-client config with gopkg.in/yaml.v3 against the `yaml:"..."` tags; the
// snake_case encoding/json single-client surface was removed. The `yaml:"..."` tags are
// required to be the lowerCamel form of the Go field name, which is EXACTLY what Traefik
// matches - see YamlTagsAreTheLowerCamelGoFieldName below - so one spelling serves both
// surfaces and the guard's scope is Traefik only. The historical reason the two spellings
// diverged is gone; keep an eye on that when editing.
//
// WHAT THIS FILE ACTUALLY GUARDS (and what it used to miss)
//
// An earlier version of this file only compared Go struct fields against a hardcoded table.
// That catches a Go FIELD RENAME, but it never read a single byte of documentation: re-typing a
// key in website/docs/**  (or in README.md) as snake_case left CI green, which is the exact
// regression the file claims to prevent - the spelling is the thing that reaches the operator,
// not the struct tag. So the guard now has two halves:
//
//  1. the structural half (unchanged): every documented Traefik key must resolve to a real Go
//     field by field name, the json tag must not be equal-folding to it, and the json tag must
//     stay snake_case for CONFIG_FILE;
//  2. the documentation half (new): the Traefik-facing docs - website/docs/**/*.md and
//     README.md - are actually READ and scanned for snake_case json tags sitting in a
//     plausible config-key position, and every camelCase key in the table below must really
//     appear there.
//
// SCAN HEURISTIC (precision over recall, deliberately)
//
// Failing a build on legitimate documentation is far worse than missing one bad key, so the
// scanner only looks at positions where a config key genuinely appears:
//
//   (a) YAML keys inside fenced code blocks tagged yml / yaml / json / toml. A line whose first
//       token (optionally a quoted string, optionally after a "- " list marker) matches a
//       snake_case json tag exactly, or matches the last segment of a dotted path.
//   (b) Markdown table cells in website/docs/** + README.md whose whole content is a single
//       backticked token (optionally followed by "*"), i.e. the "Name"/"Option"/"YAML key"
//       column of an option reference table. Every column is scanned - there is no longer a
//       second-surface column that snake_case would be legitimate in.
//
// Positions that are NOT scanned, and why:
//
//   - Bare prose / inline code spans. Traefik's own docs must name OAuth/OIDC protocol
//     parameters - `client_id`, `redirect_uri`, `max_age`, `acr_values`, `id_token_hint`,
//     `auth_time` - and several of those strings are coincidentally identical to a json tag of
//     an unrelated field (`client_id` is ProviderConfig's tag, `max_age` is
//     SessionCookieConfig's). Matching them would make this test cry wolf.
//   - Table cells that hold prose rather than a bare key.
//
// There is deliberately NO "other surface" column exemption any more. It used to skip any
// column whose header mentioned CONFIG_FILE / snake_case / encoding/json, which was correct
// while gatepost-extauthz really was a snake_case JSON surface - and became exactly the hole
// that let middleware-configuration.md keep documenting the deleted surface while CI stayed
// green. Both surfaces are now camelCase YAML, so a snake_case key in a Traefik-facing doc is
// ALWAYS wrong and every column is scanned.
//
// The repo root is located from this source file's own path (runtime.Caller), NOT from the
// working directory, so the test behaves identically whether `go test` is invoked as ./src,
// ./..., or from an absolute path. If the docs cannot be found the test FAILS LOUDLY - it must
// never pass vacuously because the documentation moved.
//
// This test is dependency-free (stdlib reflect + os only): mapstructure is deliberately not
// vendored, because Traefik runs this plugin under Yaegi and the vendor tree is kept minimal.
// It is deterministic and offline: it only reads files from the working tree.

type dockey struct {
	// documentedKey is the key that appears in the Traefik documentation / dynamic config.
	documentedKey string
	// owner is the struct that Traefik decodes this option into.
	owner reflect.Type
	// fieldName is the expected Go field name, i.e. the case-insensitive key Traefik
	// actually matches. It is asserted to exist rather than hardcoded into the lookup.
	fieldName string
	// documented says whether this key is supposed to appear in website/docs/** today.
	// False means it is deliberately undocumented (e.g. the *_Bool shims, which exist for the
	// encoding/json CONFIG_FILE surface and are not Traefik options), and the guard then
	// requires that neither spelling shows up in the docs.
	documented bool
}

// hasSnakeTag reports whether f carries a multi-word snake_case json tag, i.e. one that actually
// diverges from the Go field name Traefik matches. Options whose tag is a single word equal to
// the lowercased field name (`secret`, `scopes`, `provider`, `url`, `name`, `path`, `domain`,
// `secure`, `values`, ...) are spelled IDENTICALLY on both surfaces: there is no divergence to
// guard, so the two strict tag checks below skip them. Asserting "the tag must not equal-fold
// the field name" for those would be asserting something false about encoding/json, which
// matches json tags case-insensitively too.
func hasSnakeTag(f reflect.StructField) bool {
	tag, ok := jsonTagName(f)
	return ok && strings.Contains(tag, "_")
}

var (
	cfgType   = reflect.TypeOf(config.Config{})
	provType  = reflect.TypeOf(config.ProviderConfig{})
	cookieTyp = reflect.TypeOf(config.SessionCookieConfig{})
	hdrType   = reflect.TypeOf(config.AuthorizationHeaderConfig{})
	cookType  = reflect.TypeOf(config.AuthorizationCookieConfig{})
	authType  = reflect.TypeOf(config.AuthorizationConfig{})
	headType  = reflect.TypeOf(config.HeaderConfig{})
	claimType = reflect.TypeOf(config.ClaimAssertion{})
)

// configStructs is every operator-facing config struct. The json tags make up the snake_case
// spelling that must never leak into the Traefik-facing documentation; the yaml tags must be
// the lowerCamel Go field name (YamlTagsAreTheLowerCamelGoFieldName).
var configStructs = []reflect.Type{
	cfgType, provType, cookieTyp, hdrType, cookType, authType, headType, claimType,
}

// traefikConfigKeys is the table of documented Traefik option keys covered by this branch,
// mapped to the struct that owns them. Adding an option here documents the two spellings AND
// pins it to a real Go field name and to the docs.
//
// Entries with documented=false are real Traefik-acceptable Go field names that the Traefik
// docs deliberately do NOT offer. The *Bool shims are the clearest example: on the Traefik
// path the string field (revokeTokensOnLogout: "true") is the documented option, while the
// bool field exists so cmd/gatepost-extauthz's YAML CONFIG_FILE can carry a native boolean
// instead of the string Traefik needs. See the casing table in
// website/docs/getting-started/middleware-configuration.md.
var traefikConfigKeys = []dockey{
	// Top-level Config options.
	{"maxSessionLifetimeSeconds", cfgType, "MaxSessionLifetimeSeconds", true},
	{"sessionIdleTimeoutSeconds", cfgType, "SessionIdleTimeoutSeconds", true},
	{"trustedProxies", cfgType, "TrustedProxies", true},
	{"authorizationParamsOverridable", cfgType, "AuthorizationParamsOverridable", true},
	{"sessionStorageType", cfgType, "SessionStorageType", true},
	{"logLevel", cfgType, "LogLevel", true},
	{"secret", cfgType, "Secret", true},
	{"scopes", cfgType, "Scopes", true},
	{"provider", cfgType, "Provider", true},
	{"callbackUri", cfgType, "CallbackUri", true},
	{"loginUri", cfgType, "LoginUri", true},
	{"logoutUri", cfgType, "LogoutUri", true},
	{"postLoginRedirectUri", cfgType, "PostLoginRedirectUri", true},
	{"validPostLoginRedirectUris", cfgType, "ValidPostLoginRedirectUris", true},
	{"postLogoutRedirectUri", cfgType, "PostLogoutRedirectUri", true},
	{"validPostLogoutRedirectUris", cfgType, "ValidPostLogoutRedirectUris", true},
	{"frontChannelLogoutUri", cfgType, "FrontChannelLogoutUri", true},
	{"cookieNamePrefix", cfgType, "CookieNamePrefix", true},
	{"sessionCookie", cfgType, "SessionCookie", true},
	{"authorizationHeader", cfgType, "AuthorizationHeader", true},
	{"authorizationCookie", cfgType, "AuthorizationCookie", true},
	{"unauthenticatedBehavior", cfgType, "UnauthenticatedBehavior", true},
	{"unauthorizedBehavior", cfgType, "UnauthorizedBehavior", true},
	{"authorization", cfgType, "Authorization", true},
	{"headers", cfgType, "Headers", true},
	{"bypassAuthenticationRule", cfgType, "BypassAuthenticationRule", true},
	{"errorPages", cfgType, "ErrorPages", true},
	{"requestedResources", cfgType, "RequestedResources", true},
	{"authorizationParams", cfgType, "AuthorizationParams", true},

	// provider.* scoped options: reachable under Config.Provider, keyed by the ProviderConfig
	// field name, never by a top-level key.
	{"oidcTimeoutSeconds", provType, "OidcTimeoutSeconds", true},
	{"revokeTokensOnLogout", provType, "RevokeTokensOnLogout", true},
	{"maxAuthAgeSeconds", provType, "MaxAuthAgeSeconds", true},
	{"url", provType, "Url", true},
	{"insecureSkipVerify", provType, "InsecureSkipVerify", true},
	{"cABundle", provType, "CABundle", true},
	{"cABundleFile", provType, "CABundleFile", true},
	{"clientId", provType, "ClientId", true},
	{"clientSecret", provType, "ClientSecret", true},
	{"clientJwtPrivateKey", provType, "ClientJwtPrivateKey", true},
	{"clientJwtPrivateKeyId", provType, "ClientJwtPrivateKeyId", true},
	{"usePkce", provType, "UsePkce", true},
	{"validateAudience", provType, "ValidateAudience", true},
	{"validAudience", provType, "ValidAudience", true},
	{"validateIssuer", provType, "ValidateIssuer", true},
	{"validIssuer", provType, "ValidIssuer", true},
	{"tokenValidation", provType, "TokenValidation", true},
	{"tokenRenewalThreshold", provType, "TokenRenewalThreshold", true},
	{"useClaimsFromUserInfo", provType, "UseClaimsFromUserInfo", true},

	// The *Bool shims. Traefik accepts these Go field names (mapstructure matches them
	// case-insensitively, exactly like the string field above it), but they are NOT offered
	// as Traefik options: they exist for cmd/gatepost-extauthz's YAML CONFIG_FILE, which can
	// carry a native boolean rather than Traefik's string. The json tag must not be
	// documented as a Traefik key either.
	{"revokeTokensOnLogoutBool", provType, "RevokeTokensOnLogoutBool", false},
	{"insecureSkipVerifyBool", provType, "InsecureSkipVerifyBool", false},
	{"usePkceBool", provType, "UsePkceBool", false},
	{"validateIssuerBool", provType, "ValidateIssuerBool", false},
	{"validateAudienceBool", provType, "ValidateAudienceBool", false},
	{"validateNonceBool", provType, "ValidateNonceBool", false},
	{"useClaimsFromUserInfoBool", provType, "UseClaimsFromUserInfoBool", false},

	// Clock-skew leeway and nonce enforcement: real Traefik keys (mapstructure accepts the Go
	// field names) that the website reference does not document yet. documented=false keeps the
	// table honest in both directions: as soon as one of them is written down, this guard makes
	// the author flip the flag, so the docs and the Go fields cannot drift apart unnoticed.
	{"tokenClockSkewSeconds", provType, "TokenClockSkewSeconds", true},
	{"validateNonce", provType, "ValidateNonce", true},

	// sessionCookie / authorizationHeader / authorizationCookie / authorization / header /
	// claim-assertion sub-blocks.
	{"httpOnly", cookieTyp, "HttpOnly", true},
	{"sameSite", cookieTyp, "SameSite", true},
	{"maxAge", cookieTyp, "MaxAge", true},
	{"includeWhen", headType, "IncludeWhen", true},
	{"checkOnEveryRequest", authType, "CheckOnEveryRequest", true},
	{"assertClaims", authType, "AssertClaims", true},
}

// configDocFail teaches the correct spelling at the point of failure.
const configDocFail = "\nTraefik decodes this plugin's config with mapstructure and NO DecoderConfig.TagName " +
	"(Traefik v3.5 pkg/plugins/middlewareyaegi.go:93-102), so it matches the GO FIELD NAME " +
	"case-insensitively and IGNORES the `json:\"...\"` struct tags entirely.\n" +
	"The snake_case spelling belongs to neither surface: cmd/gatepost-extauthz's CONFIG_FILE is " +
	"loaded with gopkg.in/yaml.v3 (cmd/gatepost-extauthz/config_multi.go).\n" +
	"Fix the documented Traefik key to the Go field name, or rename the Go field; do not add a " +
	"mapstructure tag and assume Traefik reads it."

// fieldByFold returns the exported field of t whose name EqualFold-matches name, mimicking
// mapstructure's case-insensitive field matching (and nothing else: no tag lookup).
func fieldByFold(t reflect.Type, name string) (reflect.StructField, bool) {
	if t.Kind() != reflect.Struct {
		return reflect.StructField{}, false
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if strings.EqualFold(f.Name, name) {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

func jsonTagName(f reflect.StructField) (string, bool) {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return "", false
	}
	return strings.Split(tag, ",")[0], true
}

func yamlTagName(f reflect.StructField) (string, bool) {
	tag, ok := f.Tag.Lookup("yaml")
	if !ok {
		return "", false
	}
	return strings.Split(tag, ",")[0], true
}

// lowerCamel renders the lowerCamel form of a Go field name, i.e. the spelling BOTH config
// surfaces accept.
func lowerCamel(field string) string {
	if field == "" {
		return ""
	}
	return strings.ToLower(field[:1]) + field[1:]
}

// snakeTags maps every snake_case json tag of every operator-facing config struct to the Go
// field name Traefik actually accepts for that option. Tags without "_" are skipped on
// purpose: a single-word tag such as `name` or `path` cannot be told apart from ordinary prose,
// and a single-word tag that equals its field name is not part of the divergence at all.
func snakeTags(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, st := range configStructs {
		for i := 0; i < st.NumField(); i++ {
			f := st.Field(i)
			tag, ok := jsonTagName(f)
			if !ok || tag == "-" || !strings.Contains(tag, "_") {
				continue
			}
			if prev, dup := out[tag]; dup && prev != f.Name {
				t.Fatalf("json tag %q is used by both %s and %s with different field names; "+
					"the two config surfaces can no longer be taught unambiguously", tag, prev, f.Name)
			}
			out[tag] = correctSpelling(f.Name)
		}
	}
	if len(out) < 40 {
		t.Fatalf("snake case json tag collection found only %d tags; the reflection walk broke "+
			"and every scan below would pass vacuously", len(out))
	}
	return out
}

// ---- documentation discovery -------------------------------------------------

// repoRootOverrideEnv lets the negative self-check point the scanner at a throwaway copy of
// the docs. CI never sets it; unset means "derive the root from this source file's path".
const repoRootOverrideEnv = "TOA_DOCKEYS_REPO_ROOT"

// findRepoRoot walks up from this source file's directory looking for the repository root,
// identified by both website/docs/ and README.md existing. Using runtime.Caller means the
// result does not depend on the working directory `go test` happened to run from.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	if override := os.Getenv(repoRootOverrideEnv); override != "" {
		return override
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed; cannot locate the repository root")
	}
	dir := filepath.Dir(thisFile)
	var tried []string
	for i := 0; i < 8; i++ {
		tried = append(tried, dir)
		if isRepoRoot(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate the repository root (no ancestor of %s contains both website/docs and README.md).\n"+
		"The Traefik-facing documentation is part of the guard; this test must fail loudly "+
		"rather than pass vacuously when the docs move.\nSearched: %s",
		filepath.Dir(thisFile), strings.Join(tried, ", "))
	return ""
}

func isRepoRoot(dir string) bool {
	if st, err := os.Stat(filepath.Join(dir, filepath.FromSlash(docsRelPrefix))); err != nil || !st.IsDir() {
		return false
	}
	if st, err := os.Stat(filepath.Join(dir, "README.md")); err != nil || st.IsDir() {
		return false
	}
	return true
}

// docFile is one Traefik-facing documentation file to scan.
type docFile struct {
	rel  string
	abs  string
	data []byte
}

// traefikDocs collects the Traefik-facing documentation: every *.md under website/docs plus
// the repository README.md.
//
// docs/gatepost-extauthz.md is EXCLUDED from the file walk simply because it does not live under
// website/docs: it documents cmd/gatepost-extauthz's own CONFIG_FILE rather than the Traefik
// middleware surface. Since that CONFIG_FILE became YAML it is camelCase too, so the old reason
// ("snake_case json tags are correct there") no longer holds - the tripwire below stays only as
// a guard against this file being pulled into a Traefik-facing scan.
// docsRelPrefix is the repo-relative directory holding the Traefik-facing documentation.
const docsRelPrefix = "website/docs/"

func traefikDocs(t *testing.T, root string) []docFile {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(docsRelPrefix))
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		entries, _ := os.ReadDir(root)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("Traefik-facing documentation directory %s not found (stat error: %v).\n"+
			"This guard reads website/docs/**/*.md and README.md; it must fail loudly instead of "+
			"passing vacuously when the docs are missing or were moved.\nContents of %s: %v",
			abs, err, root, names)
	}

	var files []docFile
	err = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".md") {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			rel = p
		}
		files = append(files, docFile{rel: filepath.ToSlash(rel), abs: p, data: data})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s failed: %v", abs, err)
	}

	readme := filepath.Join(root, "README.md")
	rdata, rerr := os.ReadFile(readme)
	if rerr != nil {
		t.Fatalf("reading %s failed: %v; README.md is Traefik-facing documentation and part of this guard", readme, rerr)
	}
	files = append(files, docFile{rel: "README.md", abs: readme, data: rdata})

	// Deterministic order regardless of filesystem walk order.
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })

	if len(files) < 5 {
		t.Fatalf("only %d documentation files found under %s; expected the whole website/docs tree plus README.md", len(files), abs)
	}
	for _, f := range files {
		if strings.HasSuffix(f.rel, "gatepost-extauthz.md") {
			t.Fatalf("%s must never be added to the Traefik-facing scan: it documents "+
				"cmd/gatepost-extauthz's own CONFIG_FILE, not the middleware surface", f.rel)
		}
	}
	return files
}

// ---- documentation scanner ---------------------------------------------------

// docOffense is one snake_case json tag found in a plausible Traefik config-key position.
type docOffense struct {
	file    string
	line    int
	snake   string
	camel   string // Go field name Traefik actually accepts
	context string
}

// fencedCodeKeyRE matches a YAML/JSON/TOML mapping key at the start of a line, tolerating a
// list marker and optional quoting: `- "trusted_proxies":`, `  oidc_timeout_seconds: 30`, etc.
var fencedCodeKeyRE = regexp.MustCompile(`^[ \t]*(?:-[ \t]+)?(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_.\-]+))[ \t]*:`)

// scanDocsForSnakeCaseKeys reports every snake_case json tag that appears where a Traefik
// config key genuinely appears: as a YAML/JSON key inside a fenced config block, or as a bare
// backticked token in a Markdown table cell of an option reference table. See the heuristic in
// the file header for everything that is deliberately NOT scanned.
func scanDocsForSnakeCaseKeys(files []docFile, tags map[string]string) []docOffense {
	var out []docOffense
	for _, f := range files {
		lines := strings.Split(string(f.data), "\n")
		fenceLang := ""
		var fenceStart int
		// Per-column "this column documents the other surface" flags, tracked across the whole
		// table from its HEADER row down - the header of the casing table is what marks the
		// CONFIG_FILE column, and the offending cells sit in the data rows below it.
		inTable := false
		for i := 0; i < len(lines); i++ {
			line := strings.TrimRight(lines[i], "\r")
			if lang, ok := fenceMarker(line); ok {
				if fenceLang == "" {
					fenceLang, fenceStart = lang, i+1
				} else {
					fenceLang, fenceStart = "", 0
				}
				inTable = false
				continue
			}
			if fenceLang != "" {
				if isConfigFence(fenceLang) {
					if key, ok := yamlKey(line); ok {
						last := key
						if j := strings.LastIndex(last, "."); j >= 0 {
							last = last[j+1:]
						}
						if camel, hit := tags[last]; hit {
							out = append(out, docOffense{
								file: f.rel, line: i + 1, snake: last, camel: camel,
								context: strings.TrimSpace(line),
							})
						}
					}
				}
				_ = fenceStart
				continue
			}
			cells, isRow := tableRowCells(line)
			if !isRow {
				inTable = false
				continue
			}
			if isSeparatorRow(cells) {
				continue
			}
			if !inTable {
				// First row of a table: treated as the header. Every column is scanned;
				// there is no longer a "this column documents the other surface" exemption
				// (see the file header for why that exemption was removed).
				inTable = true
				continue
			}
			out = append(out, scanTableCells(f.rel, i+1, line, cells, tags)...)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		return out[i].snake < out[j].snake
	})
	return out
}

func fenceMarker(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "```") {
		return "", false
	}
	lang := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
	return strings.ToLower(lang), true
}

// isConfigFence limits YAML key scanning to blocks tagged as config formats, so shell, mermaid,
// html, js and Go template samples are never parsed as config.
func isConfigFence(lang string) bool {
	switch lang {
	case "yml", "yaml", "json", "toml":
		return true
	}
	return false
}

func yamlKey(line string) (string, bool) {
	m := fencedCodeKeyRE.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	for _, g := range m[1:] {
		if g != "" {
			return g, true
		}
	}
	return "", false
}

// scanTableCells reports snake_case json tags used as a bare table-cell key, in ANY column.
// An earlier version skipped columns whose header mentioned CONFIG_FILE / snake_case /
// encoding/json; both surfaces are camelCase YAML now, so a snake_case key in a
// Traefik-facing table is always wrong and that exemption only hid the stale documentation.
func scanTableCells(file string, lineNo int, line string, cells []string, tags map[string]string) []docOffense {
	var out []docOffense
	for _, cell := range cells {
		key, ok := bareBacktickedToken(cell)
		if !ok {
			continue
		}
		last := key
		if j := strings.LastIndex(last, "."); j >= 0 {
			last = last[j+1:]
		}
		if camel, hit := tags[last]; hit {
			out = append(out, docOffense{
				file: file, line: lineNo, snake: last, camel: camel, context: strings.TrimSpace(line),
			})
		}
	}
	return out
}

// tableRowCells splits a Markdown table line into its cells, reporting whether the line is a
// table row at all. A table ends at the first non-table line, so the skip mask cannot leak into
// unrelated prose further down the file.
func tableRowCells(line string) ([]string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "|") {
		return nil, false
	}
	return splitTableRow(trimmed), true
}

func isSeparatorRow(cells []string) bool {
	for _, cell := range cells {
		c := strings.TrimSpace(cell)
		if c == "" {
			continue
		}
		if strings.Trim(c, "-:") != "" {
			return false
		}
	}
	return true
}

func splitTableRow(line string) []string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "|")
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// bareBacktickedToken returns the token of a table cell whose entire content is a single
// backticked token, optionally followed by "*" - the "Name"/"Option"/"YAML key" column shape.
func bareBacktickedToken(cell string) (string, bool) {
	c := strings.TrimSpace(cell)
	c = strings.TrimSuffix(c, "*")
	c = strings.TrimSpace(c)
	if len(c) < 3 || !strings.HasPrefix(c, "`") || !strings.HasSuffix(c, "`") {
		return "", false
	}
	inner := strings.TrimSpace(c[1 : len(c)-1])
	if inner == "" || strings.Contains(inner, "`") || strings.ContainsAny(inner, " /") {
		return "", false
	}
	return inner, true
}

// ---- the guard --------------------------------------------------------------

// TestTraefikConfigKeys is the main guard. It checks the structural divergence AND reads the
// Traefik-facing documentation, because the documentation is what an operator actually types.
func TestTraefikConfigKeys(t *testing.T) {
	root := findRepoRoot(t)
	docs := traefikDocs(t, root)
	tags := snakeTags(t)

	t.Run("DocumentedKeysResolveToGoFieldNames", func(t *testing.T) {
		for _, k := range traefikConfigKeys {
			f, ok := fieldByFold(k.owner, k.fieldName)
			if !ok {
				t.Errorf("%s: no field equal-folds %q on %s.%s", k.documentedKey, k.fieldName, k.owner.PkgPath(), k.owner.Name())
				continue
			}
			if !strings.EqualFold(f.Name, k.documentedKey) {
				t.Errorf("documented Traefik key %q does not match Go field name %q on %s%s", k.documentedKey, f.Name, k.owner.Name(), configDocFail)
			}
		}
	})

	t.Run("SnakeCaseSpellingIsNotAccepted", func(t *testing.T) {
		// The bug this guards against: documenting the json tag instead of the field name.
		// A snake_case key must NOT match any field of the owning struct, otherwise the
		// documented key was accepted by accident and the guard above proves nothing.
		for _, k := range traefikConfigKeys {
			f, ok := fieldByFold(k.owner, k.fieldName)
			if !ok {
				continue // already reported above
			}
			tag, hasTag := jsonTagName(f)
			if !hasTag || tag == "-" || !hasSnakeTag(f) {
				continue // single-word tag: same spelling on both surfaces, nothing to diverge
			}
			if _, matches := fieldByFold(k.owner, tag); matches {
				t.Errorf("json tag %q on %s.%s also matches a Go field name, so the snake_case "+
					"spelling is not distinguishable from the Traefik key %s",
					tag, k.owner.Name(), f.Name, configDocFail)
			}
			if strings.EqualFold(tag, k.documentedKey) {
				t.Errorf("json tag %q on %s.%s is equal-folding to the documented Traefik key; "+
					"the two config surfaces must stay deliberately divergent%s", tag, k.owner.Name(), f.Name, configDocFail)
			}
		}
	})

	t.Run("ProviderOptionsAreReachableUnderProvider", func(t *testing.T) {
		// The provider-scoped options must be reachable as Config.Provider.<field>, i.e. the
		// documented `provider.oidcTimeoutSeconds` really does resolve. Also assert they are
		// NOT top-level Config fields, so nobody documents them without the provider prefix.
		providerField, ok := fieldByFold(cfgType, "Provider")
		if !ok {
			t.Fatal("config.Config has no Provider field")
		}
		providerType := providerField.Type
		if providerType.Kind() == reflect.Pointer {
			providerType = providerType.Elem()
		}
		if got, want := providerType, provType; got != want {
			t.Fatalf("Config.Provider resolves to %s, want config.ProviderConfig", got)
		}
		for _, k := range traefikConfigKeys {
			if k.owner != provType {
				continue
			}
			if _, top := fieldByFold(cfgType, k.fieldName); top {
				t.Errorf("%q is documented under provider.* but also exists as a top-level Config field", k.documentedKey)
			}
		}
	})

	t.Run("EveryStructHasCollectableFields", func(t *testing.T) {
		// Sanity: the reflection walk below must actually see the nested structs, otherwise
		// the guards above would pass vacuously after a refactor moves them.
		for _, st := range configStructs {
			if st.Kind() != reflect.Struct {
				t.Fatalf("%s is not a struct", st)
			}
			if st.NumField() == 0 {
				t.Errorf("%s has no fields; the dockey guard would be vacuous", st)
			}
		}
	})

	t.Run("JsonTagsStaySnakeCase", func(t *testing.T) {
		// Document the deliberate divergence: the json tag is the legacy wire spelling and is
		// NOT the Traefik spelling, and NOT the CONFIG_FILE spelling either (CONFIG_FILE is
		// yaml.v3 now). If someone "cleans up" the json tag to camelCase it stops being the
		// legacy shape - keep it snake_case, and keep it out of the docs.
		for _, k := range traefikConfigKeys {
			f, ok := fieldByFold(k.owner, k.fieldName)
			if !ok {
				continue // already reported above
			}
			tag, hasTag := jsonTagName(f)
			if !hasTag {
				t.Errorf("%s.%s has no json tag; every operator-facing config field must keep the "+
					"legacy snake_case wire shape it has always had", k.owner.Name(), f.Name)
				continue
			}
			if tag == f.Name {
				t.Errorf("%s.%s json tag %q equals the Go field name; the two config surfaces are "+
					"meant to be spelled differently, and the tag must stay the gatepost-extauthz "+
					"snake_case spelling, not the Traefik one", k.owner.Name(), f.Name, tag)
			}
			if hasSnakeTag(f) && strings.ToLower(tag) != tag {
				t.Errorf("%s.%s json tag %q is not lower snake_case; expected the gatepost-extauthz "+
					"CONFIG_FILE spelling, not the Traefik Go field name", k.owner.Name(), f.Name, tag)
			}
		}
	})

	t.Run("YamlTagsAreTheLowerCamelGoFieldName", func(t *testing.T) {
		// THE guard for the one-spelling-both-surfaces claim (docs/gatepost-extauthz.md).
		//
		// yaml.v3 matches struct fields CASE-INSENSITIVELY, so a wrong yaml tag still
		// binds on the gatepost-extauthz path and the bug stays invisible in tests; but
		// Traefik's mapstructure has no TagName and matches the GO FIELD NAME. A tag
		// spelled `caBundle` therefore works under yaml.v3 and is SILENTLY DROPPED by
		// Traefik. yaml.v3's leniency hid exactly that for CABundle/CABundleFile.
		//
		// Requiring every yaml tag to be the lowerCamel form of its Go field name makes
		// the two spellings identical by construction, so the documented
		// "one spelling serves both surfaces" is a property of the structs, not a claim.
		checked := 0
		for _, st := range configStructs {
			for i := 0; i < st.NumField(); i++ {
				f := st.Field(i)
				if f.PkgPath != "" { // unexported
					continue
				}
				tag, ok := yamlTagName(f)
				if !ok {
					t.Errorf("%s.%s has no yaml tag; cmd/gatepost-extauthz's CONFIG_FILE is decoded "+
						"with gopkg.in/yaml.v3 and the key would be dropped silently", st.Name(), f.Name)
					continue
				}
				if tag == "-" || tag == "" {
					checked++
					continue // deliberately excluded from the YAML surface
				}
				checked++
				if want := lowerCamel(f.Name); tag != want {
					t.Errorf("%s.%s has yaml tag %q, want %q (the lowerCamel form of the Go field name).\n"+
						"yaml.v3 matches case-insensitively so %q LOOKS like it works under gatepost-extauthz, but "+
						"Traefik's tagless mapstructure matches the Go field name (%s) and drops %q with no error. "+
						"Fix the tag, not the docs.",
						st.Name(), f.Name, tag, want, tag, f.Name, tag)
				}
			}
		}
		if checked < 40 {
			t.Fatalf("yaml tag walk checked only %d fields; the reflection broke and this subtest "+
				"would pass vacuously", checked)
		}
	})

	t.Run("DocsDoNotUseSnakeCaseJsonTagsAsTraefikKeys", func(t *testing.T) {
		// THE NEW GUARD. The structural checks above cannot see a documentation regression:
		// re-typing `maxSessionLifetimeSeconds` as `max_session_lifetime_seconds` in
		// website/docs/** leaves every Go field intact and CI green, while every Traefik
		// deployment silently loses the bound. So read the docs and look for the snake_case
		// json tags in positions where a Traefik config key actually appears.
		offenses := scanDocsForSnakeCaseKeys(docs, tags)
		for _, o := range offenses {
			t.Errorf("%s:%d: documentation uses the snake_case json tag %q as a Traefik config key:\n  %s\n"+
				"  Traefik matches the Go field name case-insensitively and ignores the json tag, so %q "+
				"decodes to the zero value with NO error - the option looks configured and silently does nothing.\n"+
				"  Use the camelCase spelling %q here. The snake_case spelling %q is the legacy "+
				"encoding/json wire shape and is NOT accepted by either current surface: Traefik "+
				"matches the Go field name and cmd/gatepost-extauthz's CONFIG_FILE is decoded with "+
				"gopkg.in/yaml.v3%s",
				o.file, o.line, o.snake, o.context, o.snake, o.camel, o.snake, configDocFail)
		}
	})

	t.Run("DocumentedCamelCaseKeysAppearInTheDocs", func(t *testing.T) {
		// Positive half: the docs and the Go fields cannot drift apart. Every key the table
		// marks as documented must really show up under website/docs/** - the reference the
		// operator actually reads - and every key marked as deliberately undocumented must NOT
		// show up anywhere in the Traefik-facing docs (website/docs/** plus README.md), so an
		// author who documents one is forced to flip the flag rather than let the two surfaces
		// drift apart unnoticed.
		corpus := map[string]map[string]bool{} // key -> files containing it
		corpusInDocs := map[string]map[string]bool{}
		for _, f := range docs {
			body := string(f.data)
			_, inDocs := strings.CutPrefix(f.rel, docsRelPrefix)
			for _, k := range traefikConfigKeys {
				if !containsToken(body, k.documentedKey) {
					continue
				}
				if corpus[k.documentedKey] == nil {
					corpus[k.documentedKey] = map[string]bool{}
				}
				corpus[k.documentedKey][f.rel] = true
				if !inDocs {
					continue
				}
				if corpusInDocs[k.documentedKey] == nil {
					corpusInDocs[k.documentedKey] = map[string]bool{}
				}
				corpusInDocs[k.documentedKey][f.rel] = true
			}
		}
		for _, k := range traefikConfigKeys {
			files := corpusInDocs[k.documentedKey]
			if k.documented && len(files) == 0 {
				tag, _ := jsonTagName(mustField(t, k))
				t.Errorf("documented Traefik key %q (%s.%s) does not appear anywhere under %s. "+
					"Either document it (the docs are the surface an operator actually types) or mark it "+
					"documented=false in traefikConfigKeys if it is deliberately not offered on the Traefik "+
					"surface. Its json tag is %q, which is legacy-JSON-only.%s",
					k.documentedKey, k.owner.Name(), k.fieldName, docsRelPrefix, tag, configDocFail)
			}
			if !k.documented && len(files) > 0 {
				names := make([]string, 0, len(files))
				for name := range files {
					names = append(names, name)
				}
				sort.Strings(names)
				t.Errorf("key %q is marked documented=false in traefikConfigKeys but appears in the "+
					"Traefik-facing documentation (%s). If it is now a documented Traefik option, flip "+
					"the flag so the guard keeps tracking it; and check that it is spelled as the Go field "+
					"name %q, not as the json tag%s",
					k.documentedKey, strings.Join(names, ", "), k.documentedKey, configDocFail)
			}
		}
	})

	t.Run("DocScannerActuallyDetectsABadKey", func(t *testing.T) {
		// Self-check: the scanner must actually flag a planted snake_case key in each scanned
		// position, otherwise "DocsDoNotUseSnakeCaseJsonTagsAsTraefikKeys" is green for the
		// wrong reason and re-typing a key in the docs would slip through again.
		fixtures := []docFile{
			{rel: "fixture/table.md", data: []byte("# x\n\n| Name | Required |\n|---|---|\n| `max_session_lifetime_seconds` | no |\n")},
			{rel: "fixture/yaml.md", data: []byte("```yml\ngatepost:\n  trusted_proxies:\n    - 10.0.0.0/8\n```\n")},
			{rel: "fixture/json.md", data: []byte("```json\n{\n  \"oidc_timeout_seconds\": 30\n}\n```\n")},
		}
		want := map[string]bool{
			"fixture/table.md": false, "fixture/yaml.md": false, "fixture/json.md": false,
		}
		for _, o := range scanDocsForSnakeCaseKeys(fixtures, tags) {
			want[o.file] = true
		}
		for _, rel := range []string{"fixture/table.md", "fixture/yaml.md", "fixture/json.md"} {
			if !want[rel] {
				t.Errorf("scanner failed to flag a planted snake_case config key in %s; the documentation "+
					"scan would pass vacuously", rel)
			}
		}
	})

	t.Run("DocScannerIgnoresNonKeyProse", func(t *testing.T) {
		// Counterpart of the self-check: the scanner must NOT flag the legitimate places a
		// snake_case string appears without being a config key, otherwise the guard gets
		// switched off and stops guarding. The rules are (1) prose is never a key position,
		// (2) a key only counts inside a config fence, (3) every table column counts.
		//
		// This used to be DocScannerIgnoresTheConfigFileSurface and asserted that a
		// snake_case CONFIG_FILE column was skipped. That surface was deleted, the skip
		// that hid it was removed, and this fixture now asserts the CURRENT behaviour.
		legit := []docFile{{
			rel: "fixture/legit.md",
			data: []byte("" +
				"| Option | Spelling |\n" +
				"|---|---|\n" +
				"| Log level | `logLevel` |\n" +
				"| Total session lifetime bound | `maxSessionLifetimeSeconds` |\n" +
				"| Trusted proxies | `trustedProxies` |\n" +
				"\n" +
				"The snake_case `json` tags (`log_level`, `callback_uri`, `provider.client_id`) are not " +
				"valid keys on either surface.\n" +
				"\n" +
				"```sh\n" +
				"CONFIG_FILE=./config.yaml LISTEN_ADDR=:9002 go run ./cmd/gatepost-extauthz\n" +
				"max_session_lifetime_seconds: 3600\n" +
				"```\n" +
				"\n" +
				"The reserved OAuth parameters (`client_id`, `max_age`, `acr_values`) are protocol names, " +
				"not Traefik config keys.\n"),
		}}
		for _, o := range scanDocsForSnakeCaseKeys(legit, tags) {
			t.Errorf("scanner flagged non-key prose at %s:%d (%q) in context %q; a guard that cries wolf "+
				"on the correct spelling gets deleted, so the heuristic must stay this narrow",
				o.file, o.line, o.snake, o.context)
		}
	})

	t.Run("DocScannerScansEveryTableColumn", func(t *testing.T) {
		// The regression that motivated removing the other-surface skip: a snake_case key
		// hiding in a column headed "CONFIG_FILE" used to be skipped, which is how
		// middleware-configuration.md kept documenting the deleted JSON surface with CI
		// green. Plant it in an arbitrary column and prove it is now caught.
		fixtures := []docFile{{
			rel: "fixture/every-column.md",
			data: []byte("| Option | Traefik YAML | `cmd/gatepost-extauthz` `CONFIG_FILE` |\n" +
				"|---|---|---|\n" +
				"| Total session lifetime bound | `maxSessionLifetimeSeconds` | `max_session_lifetime_seconds` |\n"),
		}}
		found := false
		for _, o := range scanDocsForSnakeCaseKeys(fixtures, tags) {
			if o.snake == "max_session_lifetime_seconds" {
				found = true
			}
		}
		if !found {
			t.Error("scanner skipped a snake_case key in a CONFIG_FILE-headed column; that skip is " +
				"exactly how the deleted JSON surface stayed documented while CI stayed green")
		}
	})
}

func mustField(t *testing.T, k dockey) reflect.StructField {
	t.Helper()
	f, ok := fieldByFold(k.owner, k.fieldName)
	if !ok {
		t.Fatalf("%s has no field equal-folding %q", k.owner.Name(), k.fieldName)
	}
	return f
}

// containsToken reports whether s contains want as a standalone token: the characters
// immediately before and after must not be identifier characters, so `usePkce` does not match
// inside `usePkceBool` and `secret` does not match inside `clientSecret`.
func containsToken(s, want string) bool {
	if want == "" {
		return false
	}
	from := 0
	for {
		i := strings.Index(s[from:], want)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(want)
		beforeOK := i == 0 || !isIdentByte(s[i-1])
		afterOK := end == len(s) || !isIdentByte(s[end])
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
}

// correctSpelling renders the Go field name the way the documentation should show it. Traefik
// matches case-insensitively so both forms work, but the docs consistently use lowerCamel, so
// report that form (with the exact Go field name in parentheses when they differ, e.g.
// CABundle -> cABundle).
func correctSpelling(field string) string {
	lower := strings.ToLower(field[:1]) + field[1:]
	if lower == field {
		return field
	}
	return lower + " (" + field + ")"
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
