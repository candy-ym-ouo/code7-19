import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  computeComplianceEntryHash,
  COMPLIANCE_CHAIN_GENESIS,
  gateDeletion,
  hashDeletedObjectKeys,
  verifyComplianceChain,
  type ComplianceChainEntry
} from "./compliance";

function appendEntry(
  chain: ComplianceChainEntry[],
  input: {
    caseId?: string | null;
    action: string;
    subjectUserId?: string | null;
    metadata?: Record<string, unknown>;
  }
): ComplianceChainEntry {
  const prevHash = chain.length ? chain[chain.length - 1]!.entryHash : COMPLIANCE_CHAIN_GENESIS;
  const metadataJson = canonicalJson(input.metadata ?? {});
  const occurredAt = new Date("2026-09-25T10:00:00.000Z").toISOString();
  const entry = {
    seq: chain.length + 1,
    prevHash,
    caseId: input.caseId ?? null,
    actorId: null,
    action: input.action,
    subjectUserId: input.subjectUserId ?? null,
    metadataJson,
    occurredAt,
    entryHash: ""
  };
  entry.entryHash = computeComplianceEntryHash(entry);
  chain.push(entry);
  return entry;
}

describe("canonicalJson", () => {
  it("sorts object keys recursively so equivalent objects hash identically", () => {
    const a = canonicalJson({ b: 1, a: { z: 1, y: 2 }, c: [3, { d: 4, c: 5 }] });
    const b = canonicalJson({ c: [3, { c: 5, d: 4 }], a: { y: 2, z: 1 }, b: 1 });
    expect(a).toBe(b);
  });

  it("preserves array order", () => {
    expect(canonicalJson([1, 2, 3])).not.toBe(canonicalJson([3, 2, 1]));
  });
});

describe("compliance hash chain", () => {
  it("accepts a correctly linked chain", () => {
    const chain: ComplianceChainEntry[] = [];
    appendEntry(chain, { action: "deletion.requested", metadata: { retentionDays: 30 } });
    appendEntry(chain, { action: "deletion.blocked", metadata: { holdId: "h1" } });
    appendEntry(chain, { action: "deletion.resumed" });
    appendEntry(chain, { action: "deletion.completed", metadata: { scope: { features: 2 } } });
    expect(verifyComplianceChain(chain)).toEqual({ valid: true, totalEntries: 4, brokenAtSeq: null });
  });

  it("detects tampered metadata even when entry order is shuffled", () => {
    const chain: ComplianceChainEntry[] = [];
    appendEntry(chain, { action: "deletion.requested", metadata: { retentionDays: 30 } });
    appendEntry(chain, { action: "deletion.completed" });
    const tampered = [...chain].reverse();
    tampered[0] = { ...tampered[0]!, metadataJson: canonicalJson({ forged: true }) };
    const result = verifyComplianceChain(tampered);
    expect(result.valid).toBe(false);
    expect(result.brokenAtSeq).toBe(2);
  });

  it("detects a broken prev_hash link", () => {
    const chain: ComplianceChainEntry[] = [];
    appendEntry(chain, { action: "export.requested" });
    appendEntry(chain, { action: "export.completed" });
    chain[1]!.prevHash = "deadbeef";
    expect(verifyComplianceChain(chain).valid).toBe(false);
  });
});

describe("gateDeletion", () => {
  const now = new Date("2026-09-25T00:00:00.000Z");

  it("blocks deletion while retention is active even without a legal hold", () => {
    const result = gateDeletion({
      retentionUntil: new Date("2026-09-25T00:00:00.001Z"),
      activeHoldCount: 0,
      now
    });
    expect(result).toEqual({ ok: false, reason: "retention_active" });
  });

  it("allows deletion exactly at retention expiry", () => {
    const result = gateDeletion({ retentionUntil: now, activeHoldCount: 0, now });
    expect(result).toEqual({ ok: true, reason: null });
  });

  it("legal hold overrides an expired retention window", () => {
    const result = gateDeletion({
      retentionUntil: new Date("2026-01-01T00:00:00.000Z"),
      activeHoldCount: 2,
      now
    });
    expect(result).toEqual({ ok: false, reason: "legal_hold_active" });
  });
});

describe("hashDeletedObjectKeys", () => {
  it("is independent of key ordering", () => {
    expect(hashDeletedObjectKeys(["a", "b", "c"])).toBe(hashDeletedObjectKeys(["c", "a", "b"]));
  });

  it("changes when the deleted set changes", () => {
    expect(hashDeletedObjectKeys(["a"])).not.toBe(hashDeletedObjectKeys(["a", "b"]));
  });
});
