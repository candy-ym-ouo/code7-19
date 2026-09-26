import type { PoolClient } from "pg";
import { query } from "./db";
import { AppError } from "./errors";

export type LegalHoldTargetType = "user" | "feature" | "comment" | "media";

/**
 * 判断目标是否命中有效法务保留。
 * user 级别保留会覆盖该用户拥有的全部资源。
 */
export async function hasActiveHold(
  targetType: LegalHoldTargetType,
  targetId: string,
  ownerId?: string | null
): Promise<boolean> {
  const direct = await query(
    `SELECT 1 FROM legal_holds
     WHERE target_type = $1 AND target_id = $2 AND status = 'active'
       AND (expires_at IS NULL OR expires_at > now())
     LIMIT 1`,
    [targetType, targetId]
  );
  if (direct.rowCount) return true;

  if (targetType !== "user" && ownerId) {
    const inherited = await query(
      `SELECT 1 FROM legal_holds
       WHERE target_type = 'user' AND target_id = $1 AND status = 'active'
         AND (expires_at IS NULL OR expires_at > now())
       LIMIT 1`,
      [ownerId]
    );
    if (inherited.rowCount) return true;
  }
  return false;
}

export async function assertNoLegalHold(
  targetType: LegalHoldTargetType,
  targetId: string,
  ownerId?: string | null
): Promise<void> {
  if (await hasActiveHold(targetType, targetId, ownerId)) {
    throw new AppError(409, "LEGAL_HOLD_ACTIVE", "This record is under an active legal hold and cannot be deleted or purged");
  }
}

/** 校验 hold 指向的对象确实存在（管理员挂保留时给出明确错误）。 */
export async function legalHoldTargetExists(
  client: PoolClient,
  targetType: LegalHoldTargetType,
  targetId: string
): Promise<boolean> {
  const tableByType: Record<LegalHoldTargetType, string> = {
    user: "users",
    feature: "map_features",
    comment: "comments",
    media: "media_assets"
  };
  const result = await client.query(
    `SELECT 1 FROM ${tableByType[targetType]} WHERE id = $1 LIMIT 1`,
    [targetId]
  );
  return Boolean(result.rowCount);
}
