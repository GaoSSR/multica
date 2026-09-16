/**
 * @vitest-environment jsdom
 */
// jsdom rather than node: watchSessionActivity binds to window/document, and
// under node it would take the `typeof window === "undefined"` branch and
// "pass" without ever touching the listeners this file is about.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { StorageAdapter } from "../types/storage";
import type { RefreshSessionResponse } from "../api/schemas";
import { createSessionRenewal, watchSessionActivity } from "./session-renewal";

const TOKEN_KEY = "multica_token";

function makeStorage(
  initial: Record<string, string> = {},
): StorageAdapter & { snapshot: () => Record<string, string> } {
  const values = { ...initial };
  return {
    getItem: (key) => values[key] ?? null,
    setItem: (key, value) => {
      values[key] = value;
    },
    removeItem: (key) => {
      delete values[key];
    },
    snapshot: () => ({ ...values }),
  };
}

function renewedResponse(
  token: string,
  checkAgainInSeconds = 3600,
): RefreshSessionResponse {
  return {
    token,
    expires_at: "2026-10-16T00:00:00Z",
    renewed: true,
    check_again_in_seconds: checkAgainInSeconds,
  };
}

function notYetResponse(checkAgainInSeconds = 3600): RefreshSessionResponse {
  return {
    expires_at: "2026-10-16T00:00:00Z",
    renewed: false,
    check_again_in_seconds: checkAgainInSeconds,
  };
}

interface Harness {
  api: { refreshSession: ReturnType<typeof vi.fn>; setToken: ReturnType<typeof vi.fn> };
  storage: ReturnType<typeof makeStorage>;
  authenticated: { value: boolean };
}

function makeHarness(initialToken: string | null = "token-v1"): Harness {
  return {
    api: { refreshSession: vi.fn(), setToken: vi.fn() },
    storage: makeStorage(initialToken ? { [TOKEN_KEY]: initialToken } : {}),
    authenticated: { value: true },
  };
}

function renewalFor(h: Harness) {
  return createSessionRenewal({
    api: h.api as unknown as ApiClient,
    storage: h.storage,
    isAuthenticated: () => h.authenticated.value,
  });
}

describe("createSessionRenewal", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it("persists a renewed token to storage and to the API client", async () => {
    const h = makeHarness();
    h.api.refreshSession.mockResolvedValue(renewedResponse("token-v2"));

    await renewalFor(h).renewNow();

    expect(h.storage.snapshot()[TOKEN_KEY]).toBe("token-v2");
    expect(h.api.setToken).toHaveBeenCalledWith("token-v2");
  });

  // The common answer. Asking before the window opens must change nothing —
  // in particular it must not clear or rewrite the token in play.
  it("leaves the session alone when the server says it is not time yet", async () => {
    const h = makeHarness();
    h.api.refreshSession.mockResolvedValue(notYetResponse());

    await renewalFor(h).renewNow();

    expect(h.storage.snapshot()[TOKEN_KEY]).toBe("token-v1");
    expect(h.api.setToken).not.toHaveBeenCalled();
  });

  // A foreground event and a click can land in the same tick. Two renewals
  // would produce two valid tokens racing to be the one stored.
  it("coalesces concurrent renewals into one request", async () => {
    const h = makeHarness();
    let resolve!: (value: RefreshSessionResponse) => void;
    h.api.refreshSession.mockReturnValue(
      new Promise<RefreshSessionResponse>((r) => {
        resolve = r;
      }),
    );

    const renewal = renewalFor(h);
    const first = renewal.renewNow();
    const second = renewal.renewNow();
    renewal.maybeRenew();

    resolve(renewedResponse("token-v2"));
    await Promise.all([first, second]);

    expect(h.api.refreshSession).toHaveBeenCalledTimes(1);
    expect(h.storage.snapshot()[TOKEN_KEY]).toBe("token-v2");
  });

  // The whole point of the design: an app nobody is touching does not keep
  // its own session alive. maybeRenew is wired to activity, so it has to
  // decline until the server-supplied interval has actually elapsed.
  it("declines a repeat check until the server-supplied interval elapses", async () => {
    const h = makeHarness();
    h.api.refreshSession.mockResolvedValue(notYetResponse(3600));

    const renewal = renewalFor(h);
    await renewal.renewNow();
    expect(h.api.refreshSession).toHaveBeenCalledTimes(1);

    // Simulate a busy user: many activity events, well inside the interval.
    for (let i = 0; i < 50; i++) renewal.maybeRenew();
    await Promise.resolve();

    expect(h.api.refreshSession).toHaveBeenCalledTimes(1);
  });

  it("checks again once the interval has passed", async () => {
    const h = makeHarness();
    h.api.refreshSession.mockResolvedValue(notYetResponse(60));

    const renewal = renewalFor(h);
    await renewal.renewNow();

    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now + 61_000);
    renewal.maybeRenew();
    await vi.waitFor(() =>
      expect(h.api.refreshSession).toHaveBeenCalledTimes(2),
    );
    vi.mocked(Date.now).mockRestore();
  });

  // MUL-7028 made session teardown clear every client-side store — drafts,
  // tab layout, the Query cache. A renewal that treats a network blip as the
  // end of the session would fire all of that on a flaky connection.
  it.each([
    ["offline", new TypeError("Failed to fetch")],
    ["server error", new ApiError("boom", 500, "Internal Server Error")],
    ["gateway error", new ApiError("bad gateway", 502, "Bad Gateway")],
  ])("keeps the current session when renewal fails (%s)", async (_name, err) => {
    const h = makeHarness();
    h.api.refreshSession.mockRejectedValue(err);

    await renewalFor(h).renewNow();

    expect(h.storage.snapshot()[TOKEN_KEY]).toBe("token-v1");
    expect(h.api.setToken).not.toHaveBeenCalled();
  });

  // A 401 IS handled — by ApiClient, before this code sees the rejection.
  // What matters here is that the renewal path does not additionally clear
  // anything, which would race the teardown already under way.
  it("does not tear anything down itself on a 401", async () => {
    const h = makeHarness();
    h.api.refreshSession.mockRejectedValue(
      new ApiError("invalid token", 401, "Unauthorized"),
    );

    await renewalFor(h).renewNow();

    expect(h.api.setToken).not.toHaveBeenCalled();
    // Storage is the auth store's to clear, and it already did.
    expect(h.storage.snapshot()[TOKEN_KEY]).toBe("token-v1");
  });

  // Log out while a renewal is in flight and the response lands afterwards.
  // Writing the token back would resurrect a session the app has torn down.
  it("discards a response that arrives after logout", async () => {
    const h = makeHarness();
    let resolve!: (value: RefreshSessionResponse) => void;
    h.api.refreshSession.mockReturnValue(
      new Promise<RefreshSessionResponse>((r) => {
        resolve = r;
      }),
    );

    const pending = renewalFor(h).renewNow();

    // Logout, exactly as the auth store does it.
    h.storage.removeItem(TOKEN_KEY);
    h.authenticated.value = false;

    resolve(renewedResponse("token-v2"));
    await pending;

    expect(h.storage.snapshot()[TOKEN_KEY]).toBeUndefined();
    expect(h.api.setToken).not.toHaveBeenCalled();
  });

  // Same shape, different cause: a second account signed in during the round
  // trip. The late token belongs to the previous user.
  it("discards a response that arrives after an account switch", async () => {
    const h = makeHarness();
    let resolve!: (value: RefreshSessionResponse) => void;
    h.api.refreshSession.mockReturnValue(
      new Promise<RefreshSessionResponse>((r) => {
        resolve = r;
      }),
    );

    const pending = renewalFor(h).renewNow();
    h.storage.setItem(TOKEN_KEY, "someone-elses-token");

    resolve(renewedResponse("token-v2"));
    await pending;

    expect(h.storage.snapshot()[TOKEN_KEY]).toBe("someone-elses-token");
    expect(h.api.setToken).not.toHaveBeenCalled();
  });

  it("does nothing while signed out or still booting", async () => {
    const h = makeHarness();
    h.authenticated.value = false;

    await renewalFor(h).renewNow();

    expect(h.api.refreshSession).not.toHaveBeenCalled();
  });

  it("does nothing when there is no stored session", async () => {
    const h = makeHarness(null);

    await renewalFor(h).renewNow();

    expect(h.api.refreshSession).not.toHaveBeenCalled();
  });

  // A skipped attempt must not consume the interval, or a check that landed
  // one tick before the boot probe finished would postpone the real one.
  it("does not consume the interval when it declines to run", async () => {
    const h = makeHarness();
    h.authenticated.value = false;
    h.api.refreshSession.mockResolvedValue(notYetResponse());

    const renewal = renewalFor(h);
    renewal.maybeRenew();
    expect(h.api.refreshSession).not.toHaveBeenCalled();

    h.authenticated.value = true;
    renewal.maybeRenew();
    await vi.waitFor(() =>
      expect(h.api.refreshSession).toHaveBeenCalledTimes(1),
    );
  });
});

describe("watchSessionActivity", () => {
  it("checks on foreground and on interaction, never on a timer", async () => {
    vi.useFakeTimers();
    const renewal = {
      maybeRenew: vi.fn(),
      renewNow: vi.fn().mockResolvedValue(undefined),
      reset: vi.fn(),
    };

    const stop = watchSessionActivity(renewal);

    // No timer anywhere: an untouched app must not renew itself, however
    // long it is left open.
    vi.advanceTimersByTime(7 * 24 * 60 * 60 * 1000);
    expect(renewal.maybeRenew).not.toHaveBeenCalled();

    window.dispatchEvent(new Event("focus"));
    expect(renewal.maybeRenew).toHaveBeenCalledTimes(1);

    window.dispatchEvent(new Event("pointerdown"));
    expect(renewal.maybeRenew).toHaveBeenCalledTimes(2);

    window.dispatchEvent(new Event("keydown"));
    expect(renewal.maybeRenew).toHaveBeenCalledTimes(3);

    document.dispatchEvent(new Event("visibilitychange"));
    expect(renewal.maybeRenew).toHaveBeenCalledTimes(4);

    stop();
    window.dispatchEvent(new Event("focus"));
    window.dispatchEvent(new Event("pointerdown"));
    expect(renewal.maybeRenew).toHaveBeenCalledTimes(4);

    vi.useRealTimers();
  });
});
