package middleware

import (
	"net/http"
	"time"

	"github.com/multica-ai/multica/server/internal/auth"
)

// RefreshCloudFrontCookies is middleware that refreshes CloudFront signed cookies
// on authenticated requests when the cookie is missing (expired or first request
// after login). This prevents 403s from the CDN when cookies expire before the
// user's session does.
//
// It also re-signs whenever the auth middleware just renewed the session. The
// CDN cookies are signed for the same lifetime as the session that created
// them, so without this they would keep the expiry of the ORIGINAL login
// while the session itself slid forward — and a session that now never
// expires would hit a dead policy every TTL, 403ing every image and
// attachment until the cookie finally expired and this middleware noticed it
// was gone. Re-signing at renewal keeps the two clocks locked together
// (MUL-7436).
func RefreshCloudFrontCookies(signer *auth.CloudFrontSigner) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if signer == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := r.Cookie("CloudFront-Policy")
			if err != nil || SessionRenewed(r) {
				ttl := auth.AuthTokenTTL()
				for _, cookie := range signer.SignedCookies(time.Now().Add(ttl)) {
					http.SetCookie(w, cookie)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
