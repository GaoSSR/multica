package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/auth"
)

// testSigner sets up env vars and creates a CloudFrontSigner with a throwaway RSA key.
func testSigner(t *testing.T) *auth.CloudFrontSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	b64Key := base64.StdEncoding.EncodeToString(pemBlock)

	t.Setenv("CLOUDFRONT_KEY_PAIR_ID", "TESTKEY")
	t.Setenv("CLOUDFRONT_DOMAIN", "cdn.example.com")
	t.Setenv("COOKIE_DOMAIN", ".example.com")
	t.Setenv("CLOUDFRONT_PRIVATE_KEY_SECRET", "")
	t.Setenv("CLOUDFRONT_PRIVATE_KEY", b64Key)

	signer := auth.NewCloudFrontSignerFromEnv()
	if signer == nil {
		t.Fatal("failed to create test CloudFrontSigner")
	}
	return signer
}

func TestRefreshCloudFrontCookies_UsesAuthTokenTTL(t *testing.T) {
	// Set a short TTL (1 hour) so we can verify the middleware does NOT use
	// the old hardcoded 30-day value.
	t.Setenv("AUTH_TOKEN_TTL", "1h")

	signer := testSigner(t)
	handler := RefreshCloudFrontCookies(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected CloudFront cookies to be set")
	}

	for _, c := range cookies {
		// Cookie expiry should be ~1 hour from now, not ~30 days.
		untilExpiry := time.Until(c.Expires)
		if untilExpiry > 2*time.Hour {
			t.Errorf("cookie %q expires in %v; expected ~1h (AUTH_TOKEN_TTL), got what looks like 30-day hardcode", c.Name, untilExpiry)
		}
	}
}

func TestRefreshCloudFrontCookies_NilSigner(t *testing.T) {
	handler := RefreshCloudFrontCookies(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if len(rec.Result().Cookies()) != 0 {
		t.Error("nil signer should not set any cookies")
	}
}

func TestRefreshCloudFrontCookies_SkipsWhenCookiePresent(t *testing.T) {
	signer := testSigner(t)
	handler := RefreshCloudFrontCookies(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "CloudFront-Policy", Value: "existing"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if len(rec.Result().Cookies()) != 0 {
		t.Error("should not refresh cookies when CloudFront-Policy is already present")
	}
}

// The CDN cookies are signed for the same lifetime as the session that
// created them. Once sessions slide, a renewal that did not re-sign would
// leave the CDN policy pinned to the original login — and a session that now
// never expires would 403 every asset for as long as the stale cookie lived.
func TestRefreshCloudFrontCookies_ReSignsWhenSessionRenewed(t *testing.T) {
	signer := testSigner(t)

	var served bool
	handler := Auth(nil, nil, nil)(
		RefreshCloudFrontCookies(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served = true
			w.WriteHeader(http.StatusOK)
		})),
	)

	req := cookieRequest(http.MethodGet, sessionToken(t, auth.AuthRenewThreshold()/2, "sid-cdn"))
	// A live CloudFront policy is already present: without the renewal signal
	// the middleware would leave it alone.
	req.AddCookie(&http.Cookie{Name: "CloudFront-Policy", Value: "existing-policy"})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !served {
		t.Fatal("request must still be served")
	}
	var policy *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "CloudFront-Policy" {
			policy = c
		}
	}
	if policy == nil {
		t.Fatal("a renewed session must re-sign the CloudFront cookies")
	}
	if policy.Value == "existing-policy" {
		t.Error("CloudFront policy was not re-signed")
	}
	if !policy.Expires.After(time.Now().Add(auth.AuthRenewThreshold())) {
		t.Errorf("re-signed CloudFront cookie expires at %s, which is not past the renewal threshold", policy.Expires)
	}
}

// Without a renewal, an existing policy cookie is still left alone — this is
// the pre-existing behaviour and the reason responses aren't full of
// Set-Cookie headers.
func TestRefreshCloudFrontCookies_LeavesLivePolicyAloneWithoutRenewal(t *testing.T) {
	signer := testSigner(t)

	handler := RefreshCloudFrontCookies(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "CloudFront-Policy", Value: "existing-policy"})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if len(rec.Result().Cookies()) != 0 {
		t.Error("an unrenewed request with a live policy must not re-sign")
	}
}
