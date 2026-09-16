package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsSecureCookie(t *testing.T) {
	cases := []struct {
		name           string
		frontendOrigin string
		want           bool
	}{
		{"https origin → Secure", "https://app.example.com", true},
		{"https with port", "https://app.example.com:8443", true},
		{"http origin → not Secure", "http://192.168.5.5:13000", false},
		{"http localhost → not Secure", "http://localhost:3000", false},
		{"empty → not Secure", "", false},
		{"malformed → not Secure", "::not-a-url", false},
		{"uppercase scheme still matches", "HTTPS://app.example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FRONTEND_ORIGIN", tc.frontendOrigin)
			if got := isSecureCookie(); got != tc.want {
				t.Errorf("isSecureCookie() = %v, want %v (FRONTEND_ORIGIN=%q)", got, tc.want, tc.frontendOrigin)
			}
		})
	}
}

func TestCookieDomain(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"real domain", ".example.com", ".example.com"},
		{"bare domain", "example.com", "example.com"},
		{"IPv4 rejected", "192.168.5.5", ""},
		{"IPv4 with leading dot rejected", ".192.168.5.5", ""},
		{"IPv6 rejected", "::1", ""},
		{"IPv6 bracketed is not a valid IP literal → passthrough", "[::1]", "[::1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("COOKIE_DOMAIN", tc.env)
			if got := cookieDomain(); got != tc.want {
				t.Errorf("cookieDomain() = %q, want %q (COOKIE_DOMAIN=%q)", got, tc.want, tc.env)
			}
		})
	}
}

// TestSetAuthCookies_HTTPSelfHost covers the exact misconfiguration that
// shipped to users on LAN self-host: COOKIE_DOMAIN=<ip> + HTTP FRONTEND_ORIGIN.
// The cookie must land with no Domain attribute and Secure=false so browsers
// actually store it.
func TestSetAuthCookies_HTTPSelfHost(t *testing.T) {
	t.Setenv("FRONTEND_ORIGIN", "http://192.168.5.5:13000")
	t.Setenv("COOKIE_DOMAIN", "192.168.5.5")

	rec := httptest.NewRecorder()
	if err := SetAuthCookies(rec, "test-token"); err != nil {
		t.Fatalf("SetAuthCookies: %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies (auth + csrf), got %d", len(cookies))
	}
	for _, c := range cookies {
		if c.Secure {
			t.Errorf("cookie %q has Secure=true on HTTP origin; browser would reject it", c.Name)
		}
		if c.Domain != "" {
			t.Errorf("cookie %q has Domain=%q; IP-address Domain would be rejected by the browser (RFC 6265)", c.Name, c.Domain)
		}
	}
}

func TestParseAuthTokenTTL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantDur time.Duration
		wantOK  bool
	}{
		{"empty string", "", 0, false},
		{"valid 3600", "3600", time.Hour, true},
		{"valid 86400", "86400", 24 * time.Hour, true},
		{"negative", "-100", 0, false},
		{"zero", "0", 0, false},
		{"non-numeric", "abc", 0, false},
		{"whitespace trimmed", " 7200 ", 2 * time.Hour, true},
		{"duration hours", "8760h", 8760 * time.Hour, true},
		{"duration compound", "720h30m", 720*time.Hour + 30*time.Minute, true},
		{"duration minutes", "90m", 90 * time.Minute, true},
		{"duration negative", "-1h", 0, false},
		{"duration zero", "0s", 0, false},
		{"integer overflow", "9999999999", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseAuthTokenTTL(tc.raw)
			if ok != tc.wantOK || got != tc.wantDur {
				t.Errorf("parseAuthTokenTTL(%q) = (%v, %v), want (%v, %v)", tc.raw, got, ok, tc.wantDur, tc.wantOK)
			}
		})
	}
}

func TestSetAuthCookies_HTTPSProduction(t *testing.T) {
	t.Setenv("FRONTEND_ORIGIN", "https://app.example.com")
	t.Setenv("COOKIE_DOMAIN", "app.example.com")

	rec := httptest.NewRecorder()
	if err := SetAuthCookies(rec, "test-token"); err != nil {
		t.Fatalf("SetAuthCookies: %v", err)
	}

	for _, c := range rec.Result().Cookies() {
		if !c.Secure {
			t.Errorf("cookie %q missing Secure flag on HTTPS origin", c.Name)
		}
		if c.Domain != "app.example.com" {
			t.Errorf("cookie %q Domain = %q, want %q", c.Name, c.Domain, "app.example.com")
		}
	}
}

// csrfHeaderFor builds the request a browser would send: the auth cookie the
// server set, plus the CSRF cookie's value echoed in the header.
func csrfRequest(t *testing.T, authToken, csrfToken string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/issues", nil)
	req.AddCookie(&http.Cookie{Name: AuthCookieName, Value: authToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	return req
}

// setAuthCookiesFor runs the real cookie-setting path and returns the CSRF
// token it minted, so tests exercise the same code the login and renewal
// paths use rather than reimplementing the token format.
func setAuthCookiesFor(t *testing.T, authToken string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := SetAuthCookies(rec, authToken); err != nil {
		t.Fatalf("SetAuthCookies: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			return c.Value
		}
	}
	t.Fatal("no CSRF cookie was set")
	return ""
}

// The point of binding CSRF to `sid` instead of to the token string: sliding
// renewal re-issues the auth cookie mid-session, and a CSRF token another tab
// read before that must keep working afterwards (MUL-7436).
func TestValidateCSRF_SurvivesSessionRenewal(t *testing.T) {
	sid, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	claims := sessionClaims(t, time.Now().Add(20*24*time.Hour), sid)
	original := signSession(t, claims)

	// A tab reads the CSRF cookie...
	csrfToken := setAuthCookiesFor(t, original)

	// ...the session is renewed on another tab's GET, producing a different
	// auth token for the same session...
	renewed, _, err := RenewSessionToken(claims)
	if err != nil {
		t.Fatalf("RenewSessionToken: %v", err)
	}
	if renewed == original {
		t.Fatal("renewal must produce a different token")
	}

	// ...and the first tab's POST still validates against the new cookie.
	if !ValidateCSRF(csrfRequest(t, renewed, csrfToken)) {
		t.Error("CSRF token issued before renewal must stay valid after it")
	}

	// The reverse also holds: a token minted after renewal works, so both
	// tabs converge without either having to reload.
	if !ValidateCSRF(csrfRequest(t, renewed, setAuthCookiesFor(t, renewed))) {
		t.Error("CSRF token issued after renewal must validate")
	}
}

// Binding to the session must not become a way to use one session's CSRF
// token against another's cookie.
func TestValidateCSRF_RejectsTokenFromAnotherSession(t *testing.T) {
	sidA, _ := NewSessionID()
	sidB, _ := NewSessionID()
	tokenA := signSession(t, sessionClaims(t, time.Now().Add(time.Hour), sidA))
	tokenB := signSession(t, sessionClaims(t, time.Now().Add(time.Hour), sidB))

	csrfA := setAuthCookiesFor(t, tokenA)
	if ValidateCSRF(csrfRequest(t, tokenB, csrfA)) {
		t.Error("a CSRF token from another session must not validate")
	}
}

// Everyone signed in when this ships holds a cookie pair minted under the old
// binding. Those must keep working until that session renews, or the deploy
// logs the whole userbase out of every state-changing action.
func TestValidateCSRF_AcceptsLegacyTokenBinding(t *testing.T) {
	legacy := signSession(t, sessionClaims(t, time.Now().Add(20*24*time.Hour), ""))

	legacyCSRF := setAuthCookiesFor(t, legacy)
	if !ValidateCSRF(csrfRequest(t, legacy, legacyCSRF)) {
		t.Error("a pre-MUL-7436 cookie pair must still validate")
	}

	// And the legacy binding stays bound: it is keyed by the token itself, so
	// it must not validate against a different one.
	other := signSession(t, sessionClaims(t, time.Now().Add(time.Hour), ""))
	if ValidateCSRF(csrfRequest(t, other, legacyCSRF)) {
		t.Error("a legacy CSRF token must not validate against a different auth token")
	}
}

func TestValidateCSRF_RejectsMalformedAndMissing(t *testing.T) {
	sid, _ := NewSessionID()
	token := signSession(t, sessionClaims(t, time.Now().Add(time.Hour), sid))

	cases := map[string]string{
		"empty":          "",
		"no separator":   "abcdef",
		"bad nonce hex":  "zz.00",
		"bad sig hex":    "00.zz",
		"wrong sig":      "0011223344556677889900112233445566.00",
		"extra segments": "00.11.22",
	}
	for name, csrf := range cases {
		t.Run(name, func(t *testing.T) {
			if ValidateCSRF(csrfRequest(t, token, csrf)) {
				t.Errorf("malformed CSRF token %q must not validate", csrf)
			}
		})
	}

	// No auth cookie at all: nothing to bind to, so nothing validates.
	req := httptest.NewRequest(http.MethodPost, "/api/issues", nil)
	req.Header.Set("X-CSRF-Token", setAuthCookiesFor(t, token))
	if ValidateCSRF(req) {
		t.Error("CSRF must not validate without an auth cookie")
	}
}

func TestValidateCSRF_SafeMethodsSkipTheCheck(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/api/issues", nil)
		if !ValidateCSRF(req) {
			t.Errorf("%s must not require a CSRF token", method)
		}
	}
}
