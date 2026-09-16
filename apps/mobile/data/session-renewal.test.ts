// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

const keychain = vi.hoisted(() => ({ value: null as string | null }));

vi.mock("./secure-storage", () => ({
  getToken: vi.fn(async () => keychain.value),
  setToken: vi.fn(async (token: string) => {
    keychain.value = token;
  }),
  clearToken: vi.fn(async () => {
    keychain.value = null;
  }),
}));

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
import { getToken, setToken } from "./secure-storage";

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
    keychain.value = "token-v1";
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
