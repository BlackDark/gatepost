package errorPages

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
)

func testLogger() *logging.Logger {
	return logging.CreateLogger(logging.LevelError)
}

func htmlRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Accept", "text/html")
	return req
}

func testData(description string) map[string]interface{} {
	return map[string]interface{}{
		"statusName":        "Unauthorized",
		"statusCode":        http.StatusUnauthorized,
		"description":       description,
		"statusType":        "unauthorized",
		"primaryButtonUrl":  "/login",
		"primaryButtonText": "Login",
	}
}

func TestRenderPageDefaultTemplate(t *testing.T) {
	page := &ErrorPageConfig{}

	rendered, err := renderPage(testLogger(), page, testData("Some description"))
	if err != nil {
		t.Fatalf("renderPage returned an error: %v", err)
	}

	for _, want := range []string{"Unauthorized", "401", "Some description", "/login", "Login"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("default template output does not contain %q", want)
		}
	}

	if !strings.Contains(rendered, "<!DOCTYPE html>") {
		t.Error("default template output is not a full HTML document")
	}
}

func TestRenderPageRendersOperatorTemplate(t *testing.T) {
	dir := t.TempDir()
	tplPath := filepath.Join(dir, "custom.html")
	tplBody := `<html><body><p>{{ .statusCode }}</p><p>{{ .description }}</p></body></html>`
	if err := os.WriteFile(tplPath, []byte(tplBody), 0o600); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	page := &ErrorPageConfig{FilePath: tplPath}

	rendered, err := renderPage(testLogger(), page, testData("Operator supplied"))
	if err != nil {
		t.Fatalf("renderPage returned an error: %v", err)
	}

	if !strings.Contains(rendered, "Operator supplied") || !strings.Contains(rendered, "401") {
		t.Errorf("operator template did not render the data map, got %q", rendered)
	}
	// The default template must not leak through when an operator template is configured.
	if strings.Contains(rendered, "<!DOCTYPE html>") {
		t.Error("rendered output still contains the built-in default template")
	}
}

// TestRenderPageEscapesInterpolatedValues is the regression guard for the XSS finding:
// every value that comes from the request flow is interpolated through html/template,
// which escapes it contextually. A raw concatenation (template.HTML) would break this.
func TestRenderPageEscapesInterpolatedValues(t *testing.T) {
	page := &ErrorPageConfig{}

	rendered, err := renderPage(testLogger(), page, testData(`<script>alert(1)</script>`))
	if err != nil {
		t.Fatalf("renderPage returned an error: %v", err)
	}

	if strings.Contains(rendered, "<script>alert(1)</script>") {
		t.Fatal("untrusted description was rendered as raw markup")
	}
	if !strings.Contains(rendered, "&lt;script&gt;") {
		t.Errorf("expected the script tag to be HTML-escaped, got %q", rendered)
	}
}

func TestRenderPageEscapesButtonUrlInjection(t *testing.T) {
	data := testData("harmless")
	data["primaryButtonText"] = `"><script>alert(1)</script>`
	data["primaryButtonUrl"] = `javascript:alert(1)"`

	rendered, err := renderPage(testLogger(), &ErrorPageConfig{}, data)
	if err != nil {
		t.Fatalf("renderPage returned an error: %v", err)
	}

	if strings.Contains(rendered, "<script>alert(1)</script>") {
		t.Fatal("untrusted button text was rendered as raw markup")
	}
	// html/template filters javascript: URLs out of href contexts entirely.
	if strings.Contains(rendered, `href="javascript:alert(1)"`) {
		t.Errorf("javascript: URL survived into href, got %q", rendered)
	}
}

func TestRenderPageOperatorTemplateAlsoEscapes(t *testing.T) {
	dir := t.TempDir()
	tplPath := filepath.Join(dir, "custom.html")
	if err := os.WriteFile(tplPath, []byte(`<p>{{ .description }}</p>`), 0o600); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	rendered, err := renderPage(testLogger(), &ErrorPageConfig{FilePath: tplPath}, testData(`<script>alert(1)</script>`))
	if err != nil {
		t.Fatalf("renderPage returned an error: %v", err)
	}

	if strings.Contains(rendered, "<script>") {
		t.Fatalf("operator template rendered untrusted value as raw markup, got %q", rendered)
	}
}

func TestRenderPageInvalidTemplateReturnsError(t *testing.T) {
	dir := t.TempDir()
	tplPath := filepath.Join(dir, "broken.html")
	if err := os.WriteFile(tplPath, []byte(`<p>{{ .description `), 0o600); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	if _, err := renderPage(testLogger(), &ErrorPageConfig{FilePath: tplPath}, testData("x")); err == nil {
		t.Fatal("expected an error for an unparsable template, got nil")
	}
}

// TestRenderPageMissingTemplateFileFallsBack ensures a missing operator file neither
// panics nor leaks internal detail, and that the failure is reported at WARN.
func TestRenderPageMissingTemplateFileFallsBack(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.html")

	rendered, err := renderPage(testLogger(), &ErrorPageConfig{FilePath: missing}, testData("Some description"))
	if err != nil {
		t.Fatalf("renderPage panicked or errored on a missing template: %v", err)
	}
	if !strings.Contains(rendered, "Some description") {
		t.Errorf("expected the default template fallback, got %q", rendered)
	}
}

func TestWriteErrorHtmlPath(t *testing.T) {
	rw := httptest.NewRecorder()

	WriteError(testLogger(), &ErrorPageConfig{}, rw, htmlRequest(), testData("Some description"))

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rw.Code, http.StatusUnauthorized)
	}
	if ct := rw.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(rw.Body.String(), "Some description") {
		t.Error("body does not contain the description")
	}
}

func TestWriteErrorRedirect(t *testing.T) {
	rw := httptest.NewRecorder()
	page := &ErrorPageConfig{RedirectTo: "/login-page"}

	WriteError(testLogger(), page, rw, htmlRequest(), testData("Some description"))

	if rw.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rw.Code, http.StatusFound)
	}
	if loc := rw.Header().Get("Location"); loc != "/login-page" {
		t.Errorf("Location = %q, want /login-page", loc)
	}
	if strings.Contains(rw.Body.String(), "Some description") {
		t.Error("redirect path must not render the error page body")
	}
}

func TestWriteErrorJsonPath(t *testing.T) {
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Accept", "application/json")

	WriteError(testLogger(), &ErrorPageConfig{}, rw, req, testData("Some description"))

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rw.Code, http.StatusUnauthorized)
	}
	if ct := rw.Header().Get("Content-Type"); ct != "application/json+problem" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(rw.Body.String(), `"detail":"Some description"`) {
		t.Errorf("unexpected problem body: %s", rw.Body.String())
	}
}

func TestWriteErrorMissingStatusCodeIs500(t *testing.T) {
	rw := httptest.NewRecorder()

	WriteError(testLogger(), &ErrorPageConfig{}, rw, htmlRequest(), map[string]interface{}{
		"statusName":  "Unauthorized",
		"description": "Some description",
	})

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rw.Code, http.StatusInternalServerError)
	}
}
