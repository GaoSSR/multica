package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/multica-ai/multica/server/internal/auth"
)

// sessionToken signs a cookie-mode session expiring `remaining` from now.
//
// Lifetimes are expressed as FRACTIONS of auth.AuthRenewThreshold(), never as
// literal durations or offsets from it. AuthTokenTTL() is cached behind a
// sync.Once for the life of the process, so whichever test in this package
// touches it first decides the TTL every later test sees — currently
// TestRefreshCloudFrontCookies_UsesAuthTokenTTL, which pins it to one hour.
// A fraction holds whatever that value turns out to be.
func sessionToken(t *testing.T, remaining time.Duration, sid string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":   "test-user-id",
		"email": "test@multica.ai",
		"exp":   time.Now().Add(remaining).Unix(),
		"iat":   time.Now().Add(-time.Hour).Unix(),
	}
	if sid != "" {
		claims["sid"] = sid
	}
	return generateToken(claims, auth.JWTSecret())
}

func cookieRequest(method, token string) *http.Request {
	req := httptest.NewRequest(method, "/api/issues", nil)
	req.AddCookie(&http.Cookie{Name: auth.AuthCookieName, Value: token})
	return req
}

// renewedAuthCookie returns the auth cookie the middleware set, or "" when it
// set none.
func renewedAuthCookie(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.AuthCookieName {
			return c.Value
		}
	}
	return ""
}

func runAuth(t *testing.T, req *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	called := false
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, called
}

func TestAuth_RenewsCookieSessionInsideWindow(t *testing.T) {
	original := sessionToken(t, auth.AuthRenewThreshold()/2, "sid-renew")

	rec, called := runAuth(t, cookieRequest(http.MethodGet, original))
	if !called {
		t.Fatal("request must still be served")
	}

	renewed := renewedAuthCookie(rec)
	if renewed == "" {
		t.Fatal("expected a renewed auth cookie")
	}
	if renewed == original {
		t.Fatal("renewed cookie must carry a new token")
	}

	claims, err := auth.ParseSessionToken(renewed)
	if err != nil {
		t.Fatalf("renewed token does not parse: %v", err)
	}
	if got, _ := claims["sub"].(string); got != "test-user-id" {
		t.Errorf("renewed sub = %q, want test-user-id", got)
	}
	// The session identity is what CSRF is bound to; renewal must not change it.
	if got, _ := claims["sid"].(string); got != "sid-renew" {
		t.Errorf("renewed sid = %q, want sid-renew", got)
	}
	if remaining := time.Until(auth.SessionExpiry(claims)); remaining <= auth.AuthRenewThreshold() {
		t.Errorf("renewed session has %s left, expected more than the renewal threshold", remaining)
	}
}

// Outside the window there is nothing to do, and a Set-Cookie on every
// response would be pure noise.
func TestAuth_DoesNotRenewOutsideWindow(t *testing.T) {
	token := sessionToken(t, auth.AuthRenewThreshold()+auth.AuthRenewThreshold()/2, "sid-fresh")

	rec, called := runAuth(t, cookieRequest(http.MethodGet, token))
	if !called {
		t.Fatal("request must still be served")
	}
	if got := renewedAuthCookie(rec); got != "" {
		t.Error("a session outside the renewal window must not be re-issued")
	}
}

// Rotating the auth cookie changes what a pre-MUL-7436 CSRF token is checked
// against. Confining renewal to methods that carry no CSRF check means a
// rotation can never invalidate the request that triggered it.
func TestAuth_DoesNotRenewOnStateChangingMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			token := sessionToken(t, auth.AuthRenewThreshold()/2, "sid-x")
			req := cookieRequest(method, token)
			// Cookie-mode writes need a valid CSRF token to get past the gate.
			rec := httptest.NewRecorder()
			if err := auth.SetAuthCookies(rec, token); err != nil {
				t.Fatalf("SetAuthCookies: %v", err)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == auth.CSRFCookieName {
					req.Header.Set("X-CSRF-Token", c.Value)
				}
			}

			got, called := runAuth(t, req)
			if !called {
				t.Fatalf("%s request must still be served (status %d)", method, got.Code)
			}
			if cookie := renewedAuthCookie(got); cookie != "" {
				t.Errorf("%s must not re-issue the auth cookie", method)
			}
		})
	}
}

// A bearer-token client keeps the session in its own storage. A Set-Cookie it
// never reads would leave the server and the client disagreeing about when
// the session ends; those clients call POST /api/auth/refresh instead.
func TestAuth_DoesNotRenewBearerSessions(t *testing.T) {
	token := sessionToken(t, auth.AuthRenewThreshold()/2, "sid-bearer")
	req := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec, called := runAuth(t, req)
	if !called {
		t.Fatal("request must still be served")
	}
	if got := renewedAuthCookie(rec); got != "" {
		t.Error("a bearer-authenticated request must not be answered with a session cookie")
	}
}

// Renewal extends a live session. An expired one is rejected outright — it
// must not be renewed on the way to a 401, nor turned back into a live
// session.
func TestAuth_ExpiredCookieSessionIsRejectedNotRenewed(t *testing.T) {
	expired := sessionToken(t, -time.Minute, "sid-dead")

	rec, called := runAuth(t, cookieRequest(http.MethodGet, expired))
	if called {
		t.Fatal("an expired session must not authenticate")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := renewedAuthCookie(rec); got != "" {
		t.Error("an expired session must not be re-issued")
	}
}

// A session minted before `sid` existed renews and acquires one — this is how
// everyone already signed in migrates onto the session-bound CSRF binding.
func TestAuth_RenewsLegacySessionAndMintsSessionID(t *testing.T) {
	legacy := sessionToken(t, auth.AuthRenewThreshold()/2, "")

	rec, called := runAuth(t, cookieRequest(http.MethodGet, legacy))
	if !called {
		t.Fatal("request must still be served")
	}
	renewed := renewedAuthCookie(rec)
	if renewed == "" {
		t.Fatal("a legacy session inside the window must be renewed")
	}
	if auth.SessionIDFromToken(renewed) == "" {
		t.Error("the renewed legacy session must carry a session id")
	}
}

// Renewal is only ever reached from the JWT branch. An opaque credential has
// no claims to copy forward and must pass through untouched.
func TestAuth_DoesNotRenewOpaqueCredentials(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	req.AddCookie(&http.Cookie{Name: auth.AuthCookieName, Value: "mul_0123456789abcdef0123456789abcdef01234567"})

	rec, called := runAuth(t, req)
	if called {
		t.Fatal("an opaque token in the auth cookie must not authenticate as a session")
	}
	if got := renewedAuthCookie(rec); got != "" {
		t.Error("an opaque credential must not produce a session cookie")
	}
}

// The renewed cookie has to be a complete, usable session cookie — same
// HttpOnly/Secure/SameSite posture as the one login sets, and accompanied by
// a CSRF cookie. A renewal that drops HttpOnly would quietly downgrade every
// browser session to a readable token.
func TestAuth_RenewedCookiesKeepTheirSecurityPosture(t *testing.T) {
	t.Setenv("FRONTEND_ORIGIN", "https://app.example.com")

	rec, _ := runAuth(t, cookieRequest(http.MethodGet, sessionToken(t, auth.AuthRenewThreshold()/2, "sid-posture")))

	var authCookie, csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case auth.AuthCookieName:
			authCookie = c
		case auth.CSRFCookieName:
			csrfCookie = c
		}
	}
	if authCookie == nil {
		t.Fatal("expected a renewed auth cookie")
	}
	if !authCookie.HttpOnly {
		t.Error("renewed auth cookie must stay HttpOnly")
	}
	if !authCookie.Secure {
		t.Error("renewed auth cookie must stay Secure on an https origin")
	}
	if authCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("renewed auth cookie SameSite = %v, want Strict", authCookie.SameSite)
	}
	if csrfCookie == nil {
		t.Fatal("renewal must also refresh the CSRF cookie")
	}
	if csrfCookie.HttpOnly {
		t.Error("CSRF cookie must stay readable by the client")
	}
}
