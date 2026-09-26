import { describe, expect, it } from "vitest";
import { decideDeletion } from "./compliance-policy";

const purgeAfter = new Date("2026-10-26T00:00:00Z");

describe("deletion orchestration decision", () => {
  it("never purges inside the retention window even with no holds", () => {
    expect(
      decideDeletion({
        requestStatus: "scheduled",
        now: new Date("2026-10-25T23:59:59Z"),
        purgeAfter,
        activeHoldCount: 0
      })
    ).toEqual({ action: "wait", reason: "within_retention_window" });
  });

  it("purges exactly once the window has elapsed and no hold exists", () => {
    expect(
      decideDeletion({
        requestStatus: "scheduled",
        now: purgeAfter,
        purgeAfter,
        activeHoldCount: 0
      })
    ).toEqual({ action: "purge", reason: "due" });
  });

  it("holds (never purges) when a legal hold is active after the window", () => {
    const result = decideDeletion({
      requestStatus: "scheduled",
      now: new Date("2026-11-01T00:00:00Z"),
      purgeAfter,
      activeHoldCount: 2
    });
    expect(result.action).toBe("hold");
  });

  it("does not purge a held request early; legal hold defers but does not shorten retention", () => {
    expect(
      decideDeletion({
        requestStatus: "held",
        now: new Date("2026-10-20T00:00:00Z"),
        purgeAfter,
        activeHoldCount: 1
      })
    ).toEqual({ action: "wait", reason: "within_retention_window" });

    expect(
      decideDeletion({
        requestStatus: "held",
        now: new Date("2026-11-01T00:00:00Z"),
        purgeAfter,
        activeHoldCount: 0
      })
    ).toEqual({ action: "purge", reason: "due" });
  });

  it("ignores completed and cancelled requests", () => {
    for (const status of ["completed", "cancelled"] as const) {
      expect(
        decideDeletion({ requestStatus: status, now: new Date("2027-01-01Z"), purgeAfter, activeHoldCount: 0 }).action
      ).toBe("wait");
    }
  });
});
