/**
 * Sliding session renewal (MUL-7436).
 *
 * Mirrors packages/core/platform/session-renewal.ts in contract, not in code:
 * mobile owns its own API client and stores the token in the Keychain behind
 * an async API, so this is a mobile-local implementation of the same two
 * rules.
 *
 * Renewal follows USE, not time. There is no interval timer — a check runs at
 * launch and whenever the app returns to the foreground. A backgrounded phone
 * is the normal state of a phone, and a timer there would keep a session
 * alive for a user who stopped using the app months ago.
 *
 * Renewal is not a session event. It swaps a credential in place and must
 * never look like a login or a logout. Offline, 5xx and a malformed response
 * all leave the current session untouched: it is still valid for at least
 * another half TTL, so there is nothing to recover from. Only a real 401 ends
 * a session, and `onUnauthorized` in app/_layout.tsx already owns that.
 */
import { api, ApiError } from "./api";
import { getToken, setToken } from "./secure-storage";

/** Applies only between launch and the first response; every response carries
 *  the server's own cadence, derived from the deployment's token TTL. */
const FALLBACK_CHECK_INTERVAL_MS = 60 * 60 * 1000;

/** Floor, so a nonsensical `check_again_in_seconds` cannot spin the app. */
const MIN_CHECK_INTERVAL_MS = 60 * 1000;

let checkIntervalMs = FALLBACK_CHECK_INTERVAL_MS;
let lastAttemptAt = 0;
// Collapses concurrent triggers: launch and a foreground transition can land
// together, and two renewals would leave two valid tokens racing to be the
// one written to the Keychain.
let inFlight: Promise<void> | null = null;

/**
 * Run a renewal check now, regardless of how recently one ran. Use at launch;
 * everywhere else prefer `maybeRenewSession`.
 */
export async function renewSessionNow(): Promise<void> {
  if (inFlight) return inFlight;

  // Assigned before the first await, so two callers in the same tick cannot
  // both get past the guard above. Reading the Keychain is itself async, so
  // doing that first — outside the promise — would reopen the window this
  // guard exists to close.
  inFlight = (async () => {
    try {
      // The session this attempt is for. Anything applied below is checked
      // against it, so an attempt that outlives its own session writes
      // nothing.
      const startedFrom = await getToken();
      if (!startedFrom) return;

      lastAttemptAt = Date.now();

      const result = await api.refreshSession();
      if (result.check_again_in_seconds > 0) {
        checkIntervalMs = Math.max(
          MIN_CHECK_INTERVAL_MS,
          result.check_again_in_seconds * 1000,
        );
      }
      if (!result.renewed || !result.token) return;

      // Late-result guard: a logout or an expiry during the round trip
      // already cleared the Keychain, and writing our token back would
      // resurrect a session the app has torn down.
      const current = await getToken();
      if (current !== startedFrom) return;

      await setToken(result.token);
      api.setToken(result.token);
    } catch (err) {
      // A 401 has already been routed to the sign-out path by the client's
      // onUnauthorized hook. Everything else — airplane mode, a captive
      // portal, a 5xx — says nothing about the session, which just
      // authenticated this request. Keep it.
      if (!(err instanceof ApiError) || err.status !== 401) {
        console.log("[auth] session renewal deferred", err);
      }
    } finally {
      inFlight = null;
    }
  })();

  return inFlight;
}

/** Run a check unless one ran inside the current interval. */
export function maybeRenewSession(): void {
  if (Date.now() - lastAttemptAt < checkIntervalMs) return;
  void renewSessionNow();
}

/** Test seam: forget the cadence and the last-attempt timestamp. */
export function resetSessionRenewalForTest(): void {
  checkIntervalMs = FALLBACK_CHECK_INTERVAL_MS;
  lastAttemptAt = 0;
  inFlight = null;
}
