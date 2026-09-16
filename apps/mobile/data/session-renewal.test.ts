// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

// The Keychain is async, and that is the whole point of these tests: `defer`
// lets one operation be started and finished at a chosen moment, so a logout
// and a renewal can be interleaved in either order.
const keychain = vi.hoisted(() => ({
  value: null as string | null,
  // When held, the operation suspends on entry and stays there until the test
  // releases it. `onSetEnter` fires at that moment, so a test can await the
  // exact instant a write is in flight instead of guessing at microtask
  // counts — the difference between pinning an interleaving and hoping for one.
  holdSet: false,
  releaseSet: null as null | (() => void),
  onSetEnter: null as null | (() => void),
  holdClear: false,
  releaseClear: null as null | (() => void),
}));

vi.mock("./secure-storage", () => ({
  getToken: vi.fn(async () => keychain.value),
  setToken: vi.fn(async (token: string) => {
    if (keychain.holdSet) {
      await new Promise<void>((resolve) => {
        keychain.releaseSet = resolve;
        keychain.onSetEnter?.();
      });
    }
    keychain.value = token;
  }),
  clearToken: vi.fn(async () => {
    if (keychain.holdClear) {
      await new Promise<void>((resolve) => {
        keychain.releaseClear = resolve;
      });
    }
    keychain.value = null;
  }),
}));

function resetKeychain() {
  keychain.value = "token-v1";
  keychain.holdSet = false;
  keychain.releaseSet = null;
  keychain.onSetEnter = null;
  keychain.holdClear = false;
  keychain.releaseClear = null;
}

const apiMock = vi.hoisted(() => ({
  refreshSession: vi.fn(),
  setToken: vi.fn(),
}));

vi.mock("./api", async () => {
  class ApiError extends Error {
    constructor(
      message: string,
      readonly status: number,
    ) {
      super(message);
      this.name = "ApiError";
    }
  }
  return { api: apiMock, ApiError };
});

import { ApiError } from "./api";
import {
  maybeRenewSession,
  renewSessionNow,
  resetSessionRenewalForTest,
} from "./session-renewal";
import { invalidateSessionEpoch } from "./session-epoch";
import { sessionActivityResponderConfig } from "./session-activity";
import { clearToken, getToken, setToken } from "./secure-storage";

function renewed(token: string, checkAgainInSeconds = 3600) {
  return {
    token,
    expires_at: "2026-10-16T00:00:00Z",
    renewed: true,
    check_again_in_seconds: checkAgainInSeconds,
  };
}

function notYet(checkAgainInSeconds = 3600) {
  return {
    expires_at: "2026-10-16T00:00:00Z",
    renewed: false,
    check_again_in_seconds: checkAgainInSeconds,
  };
}

describe("mobile session renewal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetKeychain();
    resetSessionRenewalForTest();
  });

  it("writes a renewed token to the Keychain and the API client", async () => {
    apiMock.refreshSession.mockResolvedValue(renewed("token-v2"));

    await renewSessionNow();

    expect(await getToken()).toBe("token-v2");
    expect(apiMock.setToken).toHaveBeenCalledWith("token-v2");
  });

  it("leaves the session alone when the server says it is not time yet", async () => {
    apiMock.refreshSession.mockResolvedValue(notYet());

    await renewSessionNow();

    expect(await getToken()).toBe("token-v1");
    expect(vi.mocked(setToken)).not.toHaveBeenCalled();
  });

  // Launch and a foreground transition land together all the time on iOS.
  it("coalesces concurrent renewals into one request", async () => {
    let resolve!: (value: unknown) => void;
    apiMock.refreshSession.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );

    const first = renewSessionNow();
    const second = renewSessionNow();
    resolve(renewed("token-v2"));
    await Promise.all([first, second]);

    expect(apiMock.refreshSession).toHaveBeenCalledTimes(1);
  });

  // Phones background constantly. A timer would keep the session of someone
  // who stopped opening the app alive forever; the interval gate is what
  // makes foreground checks safe to fire on every activation.
  it("declines a repeat check until the server-supplied interval elapses", async () => {
    apiMock.refreshSession.mockResolvedValue(notYet(3600));

    await renewSessionNow();
    for (let i = 0; i < 20; i++) maybeRenewSession();
    await Promise.resolve();

    expect(apiMock.refreshSession).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["offline", new TypeError("Network request failed")],
    ["server error", new ApiError("boom", 500)],
  ])("keeps the current session when renewal fails (%s)", async (_name, err) => {
    apiMock.refreshSession.mockRejectedValue(err);

    await renewSessionNow();

    expect(await getToken()).toBe("token-v1");
    expect(apiMock.setToken).not.toHaveBeenCalled();
  });

  it("discards a response that arrives after sign-out", async () => {
    let resolve!: (value: unknown) => void;
    apiMock.refreshSession.mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );

    const pending = renewSessionNow();
    keychain.value = null; // logout cleared the Keychain mid-flight

    resolve(renewed("token-v2"));
    await pending;

    expect(await getToken()).toBeNull();
    expect(apiMock.setToken).not.toHaveBeenCalled();
  });

  it("does nothing when there is no session to extend", async () => {
    keychain.value = null;

    await renewSessionNow();

    expect(apiMock.refreshSession).not.toHaveBeenCalled();
  });
});

// Logging out is not instantaneous on mobile: `clearToken` is a Keychain
// write, so between "the user tapped Sign out" and "the token is gone" there
// is a window where a read still returns it. A renewal that sampled storage in
// that window would write its replacement back and sign the user straight
// in again, on the device they just signed out of.
//
// Both completion orders are covered, because the two guards catch different
// halves: the epoch is true the instant logout starts, the token comparison
// only once the delete lands.
describe("mobile session renewal — logout races", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetKeychain();
    resetSessionRenewalForTest();
  });

  it("discards the result when logout has STARTED but its delete has not landed", async () => {
    let resolveRefresh!: (value: unknown) => void;
    apiMock.refreshSession.mockReturnValue(
      new Promise((r) => {
        resolveRefresh = r;
      }),
    );

    const pending = renewSessionNow();

    // Logout begins: the epoch moves synchronously, the Keychain delete is
    // left hanging so storage still holds the old token.
    keychain.holdClear = true;
    invalidateSessionEpoch();
    const logout = clearToken();

    resolveRefresh(renewed("token-v2"));
    await pending;

    expect(apiMock.setToken).not.toHaveBeenCalledWith("token-v2");
    expect(vi.mocked(setToken)).not.toHaveBeenCalledWith("token-v2");

    // Let logout finish; the session must still be gone.
    keychain.holdClear = false;
    keychain.releaseClear?.();
    await logout;
    expect(await getToken()).toBeNull();
  });

  it("discards the result when logout lands DURING the renewal's own write", async () => {
    let resolveRefresh!: (value: unknown) => void;
    apiMock.refreshSession.mockReturnValue(
      new Promise((r) => {
        resolveRefresh = r;
      }),
    );

    const pending = renewSessionNow();

    // Hold the renewal's own write open, and wait until it is genuinely
    // suspended inside setToken. Only from there can logout complete strictly
    // between the renewal's last check and its write landing — the ordering
    // the post-write guard exists for.
    keychain.holdSet = true;
    const writeInFlight = new Promise<void>((resolve) => {
      keychain.onSetEnter = resolve;
    });
    resolveRefresh(renewed("token-v2"));
    await writeInFlight;

    invalidateSessionEpoch();
    await clearToken();

    // Release the renewal's write. It lands AFTER the delete, so without a
    // post-write check the Keychain would be left holding a live credential
    // for a signed-out app.
    keychain.holdSet = false;
    keychain.releaseSet?.();
    await pending;

    expect(await getToken()).toBeNull();
    expect(apiMock.setToken).not.toHaveBeenCalledWith("token-v2");
  });

  it("still applies the renewal when no logout happened", async () => {
    apiMock.refreshSession.mockResolvedValue(renewed("token-v2"));

    await renewSessionNow();

    expect(await getToken()).toBe("token-v2");
    expect(apiMock.setToken).toHaveBeenCalledWith("token-v2");
  });
});

// Launch and foreground alone leave a gap: an app opened once and then used
// continuously in the foreground for longer than the check interval would
// never check again and could expire while the user was mid-sentence.
describe("session activity responder", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetKeychain();
    resetSessionRenewalForTest();
  });

  it("checks on a touch and never claims the gesture", async () => {
    apiMock.refreshSession.mockResolvedValue(notYet(3600));

    const claimed =
      sessionActivityResponderConfig.onStartShouldSetPanResponderCapture();

    // Returning true would make the wrapper the responder and swallow every
    // tap, scroll and swipe in the app.
    expect(claimed).toBe(false);
    await vi.waitFor(() =>
      expect(apiMock.refreshSession).toHaveBeenCalledTimes(1),
    );
  });

  it("throttles to the server-supplied cadence, so touches are not requests", async () => {
    apiMock.refreshSession.mockResolvedValue(notYet(3600));

    sessionActivityResponderConfig.onStartShouldSetPanResponderCapture();
    await vi.waitFor(() =>
      expect(apiMock.refreshSession).toHaveBeenCalledTimes(1),
    );

    for (let i = 0; i < 100; i++) {
      expect(
        sessionActivityResponderConfig.onStartShouldSetPanResponderCapture(),
      ).toBe(false);
    }
    await Promise.resolve();

    expect(apiMock.refreshSession).toHaveBeenCalledTimes(1);
  });
});
