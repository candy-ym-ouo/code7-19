import { createHash } from "node:crypto";

/**
 * 数据合规归档：防篡改审计链与保留期判断的纯函数。
 * API 与 Worker 共用，保证链上哈希可独立重放验证。
 */

export const COMPLIANCE_CHAIN_GENESIS = "0".repeat(64);

export const COMPLIANCE_EVENT_ACTIONS = [
  "export.requested",
  "export.completed",
  "export.downloaded",
  "export.purged",
  "export.failed",
  "legal_hold.placed",
  "legal_hold.released",
  "deletion.requested",
  "deletion.blocked",
  "deletion.resumed",
  "deletion.completed",
  "deletion.failed"
] as const;
export type ComplianceEventAction = (typeof COMPLIANCE_EVENT_ACTIONS)[number];

/** 默认删除保留期（宽限期），与账号删除流程的 30 天一致。 */
export const DEFAULT_DELETION_RETENTION_DAYS = 30;
/** 导出归档含个人信息，仅在对象存储保留有限天数供下载。 */
export const EXPORT_ARCHIVE_TTL_DAYS = 7;

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * 确定性 JSON 序列化：对象键递归排序，数组保持顺序。
 * 审计元数据必须先 canonicalize 再入库，链哈希才能被第三方重放。
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${parts.join(",")}}`;
}

export type ComplianceEntryInput = {
  prevHash: string;
  caseId: string | null;
  actorId: string | null;
  action: string;
  subjectUserId: string | null;
  /** canonicalJson 输出，必须与入库的 metadata 文本完全一致 */
  metadataJson: string;
  /** ISO 8601 时间戳，入库与哈希共用同一值 */
  occurredAt: string;
};

export function computeComplianceEntryHash(input: ComplianceEntryInput): string {
  const envelope = JSON.stringify([
    input.prevHash,
    input.caseId ?? "",
    input.actorId ?? "",
    input.action,
    input.subjectUserId ?? "",
    input.metadataJson,
    input.occurredAt
  ]);
  return sha256Hex(envelope);
}

export type ComplianceChainEntry = {
  seq: number;
  entryHash: string;
} & ComplianceEntryInput;

export type ComplianceChainVerification = {
  valid: boolean;
  totalEntries: number;
  /** 第一个校验失败的事件 seq；全部通过时为 null */
  brokenAtSeq: number | null;
};

/** 按 seq 顺序重放整条链，任一环节 prevHash 或 entryHash 不符即判定被篡改。 */
export function verifyComplianceChain(entries: ComplianceChainEntry[]): ComplianceChainVerification {
  let prevHash = COMPLIANCE_CHAIN_GENESIS;
  const ordered = [...entries].sort((a, b) => a.seq - b.seq);
  for (const entry of ordered) {
    if (entry.prevHash !== prevHash) {
      return { valid: false, totalEntries: ordered.length, brokenAtSeq: entry.seq };
    }
    const expected = computeComplianceEntryHash(entry);
    if (expected !== entry.entryHash) {
      return { valid: false, totalEntries: ordered.length, brokenAtSeq: entry.seq };
    }
    prevHash = entry.entryHash;
  }
  return { valid: true, totalEntries: ordered.length, brokenAtSeq: null };
}

export type DeletionGateResult =
  | { ok: true; reason: null }
  | { ok: false; reason: "retention_active" | "legal_hold_active" };

/**
 * 删除执行闸门：保留期未届满或存在活跃法务保留时禁止清除。
 * Worker 执行前与数据库触发器使用同一判定口径。
 */
export function gateDeletion(input: {
  retentionUntil: Date | null;
  activeHoldCount: number;
  now: Date;
}): DeletionGateResult {
  if (input.activeHoldCount > 0) return { ok: false, reason: "legal_hold_active" };
  if (input.retentionUntil && input.retentionUntil.getTime() > input.now.getTime()) {
    return { ok: false, reason: "retention_active" };
  }
  return { ok: true, reason: null };
}

/** 已删除对象清单的聚合哈希：先排序再 canonicalize，清单顺序不影响结果。 */
export function hashDeletedObjectKeys(keys: string[]): string {
  return sha256Hex(canonicalJson([...keys].sort()));
}
