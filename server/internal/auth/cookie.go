package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	AuthCookieName      = "multica_auth"
	CSRFCookieName      = "multica_csrf"
	defaultAuthTokenTTL = 30 * 24 * time.Hour // 30 days
)

var (
	ipCookieDomainWarnOnce sync.Once
	authTokenTTLOnce       sync.Once
	authTokenTTLCached     time.Duration
)

// parseAuthTokenTTL parses a raw AUTH_TOKEN_TTL value into a duration.
// It first tries time.ParseDuration (e.g. "8760h", "720h30m"), then falls
// back to parsing as integer seconds. Returns the parsed duration and true
// on success; zero and false when the input is empty or invalid.
func parseAuthTokenTTL(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}

	// Try Go duration string first (e.g. "8760h", "720h30m").
	if d, err := time.ParseDuration(raw); err == nil {
		if d <= 0 {
			return 0, false
		}
		if d > 10*365*24*time.Hour {
			slog.Warn("AUTH_TOKEN_TTL exceeds 10 years; accepting but verify this is intentional",
				"value", raw, "hours", d.Hours())
		}
		return d, true
	}

	// Fall back to plain integer seconds.
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || secs <= 0 {
		return 0, false
	}
	if secs > int64(math.MaxInt64/int64(time.Second)) {
		return 0, false
	}
	d := time.Duration(secs) * time.Second
	if d > 10*365*24*time.Hour {
		slog.Warn("AUTH_TOKEN_TTL exceeds 10 years; accepting but verify this is intentional",
			"value", raw, "hours", d.Hours())
	}
	return d, true
}

// AuthTokenTTL returns the configured auth token lifetime. It reads the
// AUTH_TOKEN_TTL environment variable (Go duration string or integer seconds) on first call and caches
// the result. When the variable is unset or invalid the default of 30 days
// is used.
func AuthTokenTTL() time.Duration {
	authTokenTTLOnce.Do(func() {
		raw := os.Getenv("AUTH_TOKEN_TTL")
		if ttl, ok := parseAuthTokenTTL(raw); ok {
			authTokenTTLCached = ttl
			slog.Info("auth token TTL configured", "seconds", int(ttl.Seconds()))
			return
		}
		authTokenTTLCached = defaultAuthTokenTTL
		if strings.TrimSpace(raw) != "" {
			slog.Warn("AUTH_TOKEN_TTL is not a valid duration or positive integer; using default",
				"value", raw, "default_seconds", int(defaultAuthTokenTTL.Seconds()))
		}
	})
	return authTokenTTLCached
}

// cookieDomain returns the trimmed COOKIE_DOMAIN env value, or "" if it looks
// like an IP address. RFC 6265 §4.1.2.3 forbids IP literals in the cookie
// Domain attribute, so browsers silently drop Set-Cookie headers that carry
// one. An IP value here is almost always a misconfiguration.
func cookieDomain() string {
	raw := strings.TrimSpace(os.Getenv("COOKIE_DOMAIN"))
	if raw == "" {
		return ""
	}
	// A leading dot ("." for subdomain matching) is legal syntax but doesn't
	// change whether the remainder is an IP literal.
	if ip := net.ParseIP(strings.TrimPrefix(raw, ".")); ip != nil {
		ipCookieDomainWarnOnce.Do(func() {
			slog.Warn(
				"COOKIE_DOMAIN looks like an IP address; ignoring. RFC 6265 forbids IP literals in the cookie Domain attribute, so browsers would drop the Set-Cookie. Leave COOKIE_DOMAIN empty for single-host deployments, or use a real domain.",
				"value", raw,
			)
		})
		return ""
	}
	return raw
}

// isSecureCookie reports whether session cookies should carry the Secure flag.
// Derived from the scheme of FRONTEND_ORIGIN — browsers silently drop Secure
// cookies received on a plain-HTTP page, so the flag has to track the actual
// user-facing scheme rather than a coarser environment name.
func isSecureCookie() bool {
	raw := strings.TrimSpace(os.Getenv("FRONTEND_ORIGIN"))
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https")
}

// csrfSignature computes the signature half of a CSRF token.
//
// Two bindings exist, and which one applies is decided by whether the auth
// token carries a `sid` claim:
//
//   - Session-bound (sessionID != ""): HMAC-SHA256 keyed by the server's JWT
//     secret over (sessionID, nonce). `sid` survives renewal, so re-signing
//     the auth cookie leaves every CSRF token already issued for that session
//     valid — which is the whole reason sliding renewal does not race other
//     tabs (MUL-7436). This is the HMAC-based Token Pattern OWASP recommends.
//   - Legacy (sessionID == ""): HMAC-SHA256 keyed by the auth token itself
//     over the nonce. This is the pre-MUL-7436 scheme, kept so cookies issued
//     before this code shipped keep working until their session renews.
//
// Both bindings defend the same thing: an attacker who can write cookies on a
// sibling subdomain cannot produce a CSRF token matching the auth cookie
// without already holding the session it belongs to.
func csrfSignature(sessionID, authToken string, nonce []byte) []byte {
	if sessionID != "" {
		mac := hmac.New(sha256.New, JWTSecret())
		mac.Write([]byte(sessionID))
		// Domain separator: without it a (sessionID, nonce) pair could be
		// re-split, letting one session's token be read as another's.
		mac.Write([]byte{0})
		mac.Write(nonce)
		return mac.Sum(nil)
	}

	mac := hmac.New(sha256.New, []byte(authToken))
	mac.Write(nonce)
	return mac.Sum(nil)
}

// generateCSRFToken creates a CSRF token for an auth token.
// Format: hex(nonce) + "." + hex(signature); see csrfSignature for the binding.
func generateCSRFToken(authToken string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sig := csrfSignature(SessionIDFromToken(authToken), authToken, nonce)
	return hex.EncodeToString(nonce) + "." + hex.EncodeToString(sig), nil
}

// SetAuthCookies sets the HttpOnly auth cookie and the readable CSRF cookie on the response.
func SetAuthCookies(w http.ResponseWriter, token string) error {
	secure := isSecureCookie()
	domain := cookieDomain()
	ttl := AuthTokenTTL()
	now := time.Now()

	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    token,
		Path:     "/",
		Domain:   domain,
		MaxAge:   int(ttl.Seconds()),
		Expires:  now.Add(ttl),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	csrfToken, err := generateCSRFToken(token)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		Domain:   domain,
		MaxAge:   int(ttl.Seconds()),
		Expires:  now.Add(ttl),
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

// ClearAuthCookies removes the auth and CSRF cookies.
func ClearAuthCookies(w http.ResponseWriter) {
	domain := cookieDomain()
	secure := isSecureCookie()

	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// IsSafeMethod reports whether a method is read-only under RFC 9110, i.e. one
// that carries no CSRF requirement. Exported because the session-renewal
// middleware reuses it: re-issuing the auth cookie is itself a write to the
// client's cookie jar, and doing it only on safe requests keeps a rotation
// from ever racing the CSRF token of the request that triggered it.
func IsSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// ValidateCSRF checks the X-CSRF-Token header against the auth cookie.
// The CSRF token is HMAC-signed (see csrfSignature), so the server verifies a
// signature rather than simply comparing cookie == header.
// Returns true if validation passes (including for safe methods that don't need CSRF).
//
// Both bindings are accepted. A session-bound token is the normal case; the
// legacy auth-token binding is still honoured so a cookie pair issued before
// MUL-7436 keeps working until that session is renewed.
func ValidateCSRF(r *http.Request) bool {
	if IsSafeMethod(r.Method) {
		return true
	}

	csrfHeader := r.Header.Get("X-CSRF-Token")
	if csrfHeader == "" {
		return false
	}

	authCookie, err := r.Cookie(AuthCookieName)
	if err != nil || authCookie.Value == "" {
		return false
	}

	parts := strings.SplitN(csrfHeader, ".", 2)
	if len(parts) != 2 {
		return false
	}

	nonce, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}

	presentedSig, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	if sid := SessionIDFromToken(authCookie.Value); sid != "" {
		if hmac.Equal(csrfSignature(sid, "", nonce), presentedSig) {
			return true
		}
	}
	return hmac.Equal(csrfSignature("", authCookie.Value, nonce), presentedSig)
}
