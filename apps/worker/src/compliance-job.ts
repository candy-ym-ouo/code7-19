import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { randomToken } from "@map/shared/server";
import {
  canonicalJson,
  computeComplianceEntryHash,
  gateDeletion,
  hashDeletedObjectKeys,
  COMPLIANCE_CHAIN_GENESIS,
  DEFAULT_DELETION_RETENTION_DAYS,
  EXPORT_ARCHIVE_TTL_DAYS,
  type ComplianceEventAction
} from "@map/shared/compliance";
import { config } from "./config";
import { pool } from "./db";
import { deleteObject, writeQuarantineObject } from "./storage";

const OPEN_DELETION_STATUSES = ["pending", "waiting_retention", "processing", "blocked", "failed"] as const;
const MAX_CASE_ATTEMPTS = 5;

type ComplianceCaseRow = {
  id: string;
  subject_user_id: string;
  retention_until: Date | null;
  payload: Record<string, unknown>;
};

async function appendComplianceEvent(
  client: PoolClient,
  input: {
    caseId?: string | null;
    actorId?: string | null;
    action: ComplianceEventAction;
    subjectUserId?: string | null;
    metadata?: Record<string, unknown>;
  }
): Promise<{ id: string; entryHash: string }> {
  const metadataJson = canonicalJson(input.metadata ?? {});
  await client.query("SELECT pg_advisory_xact_lock(hashtext('compliance_events_chain'))");
  const previous = await client.query<{ entry_hash: string }>(
    "SELECT entry_hash FROM compliance_events ORDER BY seq DESC LIMIT 1"
  );
  const prevHash = previous.rows[0]?.entry_hash ?? COMPLIANCE_CHAIN_GENESIS;
  const occurredAt = new Date().toISOString();
  const entryHash = computeComplianceEntryHash({
    prevHash,
    caseId: input.caseId ?? null,
    actorId: input.actorId ?? null,
    action: input.action,
    subjectUserId: input.subjectUserId ?? null,
    metadataJson,
    occurredAt
  });
  const result = await client.query<{ id: string }>(
    `INSERT INTO compliance_events(case_id, actor_id, action, subject_user_id, metadata, prev_hash, entry_hash, occurred_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id`,
    [
      input.caseId ?? null,
      input.actorId ?? null,
      input.action,
      input.subjectUserId ?? null,
      metadataJson,
      prevHash,
      entryHash,
      occurredAt
    ]
  );
  return { id: result.rows[0]!.id, entryHash };
}

async function notifyUser(
  client: PoolClient,
  input: { userId: string; type: string; title: string; body: string; link?: string | null }
): Promise<void> {
  await client.query(
    `INSERT INTO notifications(user_id, type, title, body, link)
     VALUES ($1, $2, $3, $4, $5)`,
    [input.userId, input.type, input.title, input.body, input.link ?? null]
  );
}

async function withTransaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

async function countActiveHolds(client: PoolClient, userId: string): Promise<number> {
  const result = await client.query<{ count: string }>(
    "SELECT count(*)::text AS count FROM legal_holds WHERE user_id = $1 AND released_at IS NULL",
    [userId]
  );
  return Number(result.rows[0]!.count);
}

/**
 * 历史账号迁移：deletion_pending 但尚无删除案件的用户补登记，
 * 保留期沿用账号删除申请时间 + 默认宽限期。
 */
export async function ensureDeletionCases(): Promise<void> {
  const pending = await pool.query<{ id: string; deleted_at: Date | null }>(
    `SELECT u.id, u.deleted_at FROM users u
     WHERE u.status = 'deletion_pending'
       AND NOT EXISTS (
         SELECT 1 FROM compliance_cases c
         WHERE c.subject_user_id = u.id AND c.case_type = 'deletion'
           AND c.status = ANY($1::compliance_case_status[])
       )
     LIMIT 20`,
    [[...OPEN_DELETION_STATUSES]]
  );
  for (const user of pending.rows) {
    try {
      await withTransaction(async (client) => {
        const retentionBase = user.deleted_at ?? new Date();
        const retentionUntil = new Date(
          retentionBase.getTime() + DEFAULT_DELETION_RETENTION_DAYS * 24 * 60 * 60 * 1000
        );
        const result = await client.query<{ id: string }>(
          `INSERT INTO compliance_cases(case_type, subject_user_id, status, reason, requested_by, retention_until)
           VALUES ('deletion', $1, 'waiting_retention', 'legacy_deletion_pending_backfill', NULL, $2)
           RETURNING id`,
          [user.id, retentionUntil]
        );
        await appendComplianceEvent(client, {
          caseId: result.rows[0]!.id,
          action: "deletion.requested",
          subjectUserId: user.id,
          metadata: { retentionDays: DEFAULT_DELETION_RETENTION_DAYS, source: "legacy_backfill" }
        });
      });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
    }
  }
}

/** 到期法务保留自动解除，并恢复被阻塞的删除案件。 */
export async function releaseExpiredHolds(): Promise<void> {
  const expired = await pool.query<{ id: string; user_id: string; case_id: string }>(
    `SELECT id, user_id, case_id FROM legal_holds
     WHERE released_at IS NULL AND release_after IS NOT NULL AND release_after <= now()
     LIMIT 20`
  );
  for (const hold of expired.rows) {
    await withTransaction(async (client) => {
      const released = await client.query(
        `UPDATE legal_holds
         SET released_at = now(), release_reason = 'retention_expired_auto_release'
         WHERE id = $1 AND released_at IS NULL`,
        [hold.id]
      );
      if (!released.rowCount) return;
      await client.query(
        "UPDATE compliance_cases SET status = 'completed', completed_at = now(), updated_at = now() WHERE id = $1",
        [hold.case_id]
      );
      await appendComplianceEvent(client, {
        caseId: hold.case_id,
        action: "legal_hold.released",
        subjectUserId: hold.user_id,
        metadata: { holdId: hold.id, automatic: true }
      });
      if ((await countActiveHolds(client, hold.user_id)) === 0) {
        const resumed = await client.query<{ id: string }>(
          `UPDATE compliance_cases
           SET status = 'waiting_retention', updated_at = now()
           WHERE subject_user_id = $1 AND case_type = 'deletion' AND status = 'blocked'
           RETURNING id`,
          [hold.user_id]
        );
        for (const row of resumed.rows) {
          await appendComplianceEvent(client, {
            caseId: row.id,
            action: "deletion.resumed",
            subjectUserId: hold.user_id,
            metadata: { holdId: hold.id }
          });
        }
      }
      await notifyUser(client, {
        userId: hold.user_id,
        type: "legal_hold_released",
        title: "你的账号数据法务保留已到期解除",
        body: "保留解除后，排队的删除请求将按保留策略继续执行。",
        link: "/me/notifications"
      });
    });
  }
}

async function assembleExportArchive(userId: string): Promise<Record<string, unknown>> {
  const [user, features, comments, confirmations, media, reports] = await Promise.all([
    pool.query(
      `SELECT id, email, display_name, role, status, email_verified_at, last_login_at, created_at
       FROM users WHERE id = $1`,
      [userId]
    ),
    pool.query(
      `SELECT mf.id, mf.status, mf.created_at, fr.payload
       FROM map_features mf
       JOIN feature_revisions fr ON fr.id = COALESCE(mf.current_revision_id, (
         SELECT id FROM feature_revisions WHERE feature_id = mf.id ORDER BY revision_no DESC LIMIT 1
       ))
       WHERE mf.owner_id = $1 ORDER BY mf.created_at DESC`,
      [userId]
    ),
    pool.query(
      "SELECT id, feature_id, body, status, created_at FROM comments WHERE author_id = $1 ORDER BY created_at DESC",
      [userId]
    ),
    pool.query(
      "SELECT feature_id, result, note, created_at FROM feature_confirmations WHERE user_id = $1 ORDER BY created_at DESC",
      [userId]
    ),
    pool.query(
      `SELECT id, original_filename, mime_type, byte_size, width, height, sha256, privacy_status, created_at
       FROM media_assets WHERE owner_id = $1 ORDER BY created_at DESC`,
      [userId]
    ),
    pool.query(
      "SELECT id, target_type, target_id, reason_code, status, created_at FROM reports WHERE reporter_id = $1 ORDER BY created_at DESC",
      [userId]
    )
  ]);
  return {
    subject: user.rows[0] ?? null,
    features: features.rows,
    comments: comments.rows,
    confirmations: confirmations.rows,
    media: media.rows,
    reports: reports.rows
  };
}

export async function processExportCases(): Promise<void> {
  const claimed = await pool.query<ComplianceCaseRow>(
    `UPDATE compliance_cases
     SET status = 'processing', updated_at = now()
     WHERE id IN (
       SELECT id FROM compliance_cases
       WHERE case_type = 'export' AND status = 'pending'
       ORDER BY created_at LIMIT 3
     )
     RETURNING id, subject_user_id, retention_until, payload`
  );

  for (const exportCase of claimed.rows) {
    try {
      const archive = await assembleExportArchive(exportCase.subject_user_id);
      const body = Buffer.from(
        JSON.stringify({ exportedAt: new Date().toISOString(), caseId: exportCase.id, ...archive }),
        "utf8"
      );
      const objectKey = `compliance/exports/${exportCase.id}.json`;
      await writeQuarantineObject(objectKey, body, "application/json");
      const archiveSha256 = createHash("sha256").update(body).digest("hex");
      const expiresAt = new Date(Date.now() + EXPORT_ARCHIVE_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();

      await withTransaction(async (client) => {
        await client.query(
          `UPDATE compliance_cases
           SET status = 'completed', completed_at = now(), updated_at = now(),
               payload = $2::jsonb
           WHERE id = $1`,
          [
            exportCase.id,
            JSON.stringify({
              objectKey,
              sha256: archiveSha256,
              byteSize: body.byteLength,
              expiresAt
            })
          ]
        );
        await appendComplianceEvent(client, {
          caseId: exportCase.id,
          action: "export.completed",
          subjectUserId: exportCase.subject_user_id,
          metadata: { sha256: archiveSha256, byteSize: body.byteLength, expiresAt }
        });
        await notifyUser(client, {
          userId: exportCase.subject_user_id,
          type: "export_ready",
          title: "你的数据导出已就绪",
          body: `导出归档已生成，请在 ${EXPORT_ARCHIVE_TTL_DAYS} 天内下载，过期后将被安全清除。`,
          link: "/me/notifications"
        });
      });
    } catch (error) {
      await markCaseAttemptFailed(exportCase, error, "export.failed", "pending");
    }
  }
}

type MediaKeyRow = {
  quarantine_object_key: string;
  processed_object_key: string | null;
  thumbnail_object_key: string | null;
  public_object_key: string | null;
  public_thumbnail_object_key: string | null;
};

function mediaObjectKeys(row: MediaKeyRow): Array<{ bucket: string; key: string }> {
  const keys: Array<{ bucket: string; key: string }> = [
    { bucket: config.S3_QUARANTINE_BUCKET, key: row.quarantine_object_key }
  ];
  if (row.processed_object_key) keys.push({ bucket: config.S3_QUARANTINE_BUCKET, key: row.processed_object_key });
  if (row.thumbnail_object_key) keys.push({ bucket: config.S3_QUARANTINE_BUCKET, key: row.thumbnail_object_key });
  if (row.public_object_key) keys.push({ bucket: config.S3_PUBLIC_BUCKET, key: row.public_object_key });
  if (row.public_thumbnail_object_key) keys.push({ bucket: config.S3_PUBLIC_BUCKET, key: row.public_thumbnail_object_key });
  return keys;
}

async function markCaseAttemptFailed(
  complianceCase: ComplianceCaseRow,
  error: unknown,
  terminalAction: ComplianceEventAction,
  retryStatus: "pending" | "waiting_retention"
): Promise<void> {
  const message = error instanceof Error ? error.message.slice(0, 500) : "Unknown compliance job error";
  const result = await pool.query<{ attempts: number }>(
    `UPDATE compliance_cases
     SET attempts = attempts + 1,
         last_error = $2,
         status = CASE WHEN attempts + 1 >= $3 THEN 'failed'::compliance_case_status
                       ELSE $4::compliance_case_status END,
         updated_at = now()
     WHERE id = $1
     RETURNING attempts`,
    [complianceCase.id, message, MAX_CASE_ATTEMPTS, retryStatus]
  );
  if (result.rows[0] && result.rows[0].attempts >= MAX_CASE_ATTEMPTS) {
    await withTransaction(async (client) => {
      await appendComplianceEvent(client, {
        caseId: complianceCase.id,
        action: terminalAction,
        subjectUserId: complianceCase.subject_user_id,
        metadata: { error: message, attempts: result.rows[0]!.attempts }
      });
    });
  }
  console.error({ caseId: complianceCase.id, error }, "compliance case attempt failed");
}

/** 数据库触发器（RAISE EXCEPTION = P0001）拦截说明保留期/法务保留状态已变化，不计为执行失败。 */
function isComplianceGateError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "P0001";
}

async function reGateAfterTriggerBlock(deletionCase: ComplianceCaseRow): Promise<void> {
  await withTransaction(async (client) => {
    const activeHoldCount = await countActiveHolds(client, deletionCase.subject_user_id);
    if (activeHoldCount > 0) {
      await client.query(
        "UPDATE compliance_cases SET status = 'blocked', updated_at = now() WHERE id = $1",
        [deletionCase.id]
      );
      await appendComplianceEvent(client, {
        caseId: deletionCase.id,
        action: "deletion.blocked",
        subjectUserId: deletionCase.subject_user_id
      });
    } else {
      await client.query(
        "UPDATE compliance_cases SET status = 'waiting_retention', updated_at = now() WHERE id = $1",
        [deletionCase.id]
      );
    }
  });
}

export async function processDeletionCases(): Promise<void> {
  const claimed = await pool.query<ComplianceCaseRow>(
    `UPDATE compliance_cases
     SET status = 'processing', updated_at = now()
     WHERE id IN (
       SELECT id FROM compliance_cases
       WHERE case_type = 'deletion'
         AND (
           (status = 'waiting_retention' AND (retention_until IS NULL OR retention_until <= now()))
           OR (status = 'failed' AND attempts < $1)
         )
       ORDER BY created_at LIMIT 3
     )
     RETURNING id, subject_user_id, retention_until, payload`,
    [MAX_CASE_ATTEMPTS]
  );

  for (const deletionCase of claimed.rows) {
    try {
      await executeDeletionCase(deletionCase);
    } catch (error) {
      if (isComplianceGateError(error)) {
        await reGateAfterTriggerBlock(deletionCase);
      } else {
        await markCaseAttemptFailed(deletionCase, error, "deletion.failed", "waiting_retention");
      }
    }
  }
}

async function executeDeletionCase(deletionCase: ComplianceCaseRow): Promise<void> {
  const userId = deletionCase.subject_user_id;

  const gate = await withTransaction(async (client) => {
    const activeHoldCount = await countActiveHolds(client, userId);
    return gateDeletion({
      retentionUntil: deletionCase.retention_until,
      activeHoldCount,
      now: new Date()
    });
  });
  if (!gate.ok) {
    await withTransaction(async (client) => {
      if (gate.reason === "legal_hold_active") {
        await client.query(
          "UPDATE compliance_cases SET status = 'blocked', updated_at = now() WHERE id = $1",
          [deletionCase.id]
        );
        await appendComplianceEvent(client, {
          caseId: deletionCase.id,
          action: "deletion.blocked",
          subjectUserId: userId
        });
      } else {
        // 保留期在执行前被延长：退回等待，不得提前清除。
        await client.query(
          "UPDATE compliance_cases SET status = 'waiting_retention', updated_at = now() WHERE id = $1",
          [deletionCase.id]
        );
      }
    });
    return;
  }

  const media = await pool.query<MediaKeyRow>(
    `SELECT quarantine_object_key, processed_object_key, thumbnail_object_key,
            public_object_key, public_thumbnail_object_key
     FROM media_assets WHERE owner_id = $1`,
    [userId]
  );
  const targets = media.rows.flatMap(mediaObjectKeys);
  const deletedKeys: string[] = [];
  for (const target of targets) {
    await deleteObject(target.bucket, target.key);
    deletedKeys.push(target.key);
  }

  await withTransaction(async (client) => {
    const sessions = await client.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
    const authTokens = await client.query("DELETE FROM auth_tokens WHERE user_id = $1", [userId]);
    const notifications = await client.query("DELETE FROM notifications WHERE user_id = $1", [userId]);
    const confirmations = await client.query("DELETE FROM feature_confirmations WHERE user_id = $1", [userId]);
    const comments = await client.query(
      `UPDATE comments SET status = 'deleted', deleted_at = now(), updated_at = now()
       WHERE author_id = $1 AND deleted_at IS NULL`,
      [userId]
    );
    const features = await client.query(
      `UPDATE map_features SET status = 'deleted', deleted_at = now(), updated_at = now()
       WHERE owner_id = $1 AND deleted_at IS NULL`,
      [userId]
    );
    const mediaAssets = await client.query(
      `UPDATE media_assets SET privacy_status = 'deleted', deleted_at = now(), updated_at = now()
       WHERE owner_id = $1 AND deleted_at IS NULL`,
      [userId]
    );
    await client.query(
      `UPDATE users
       SET email = $2,
           email_normalized = $3,
           display_name = '已删除用户',
           password_hash = $4,
           status = 'deleted',
           updated_at = now()
       WHERE id = $1`,
      [
        userId,
        `deleted+${userId}@invalid.local`,
        `deleted+${userId}@invalid.local`,
        `!unusable:${randomToken(24)}`
      ]
    );

    const scope = {
      sessions: sessions.rowCount ?? 0,
      authTokens: authTokens.rowCount ?? 0,
      notifications: notifications.rowCount ?? 0,
      featureConfirmations: confirmations.rowCount ?? 0,
      comments: comments.rowCount ?? 0,
      features: features.rowCount ?? 0,
      mediaAssets: mediaAssets.rowCount ?? 0,
      mediaObjects: deletedKeys.length,
      userAnonymized: true,
      retainedForAudit: ["reports", "moderation_actions", "audit_logs", "compliance_events"]
    };
    const event = await appendComplianceEvent(client, {
      caseId: deletionCase.id,
      action: "deletion.completed",
      subjectUserId: userId,
      metadata: { scope, objectKeysHash: hashDeletedObjectKeys(deletedKeys) }
    });
    await client.query(
      `INSERT INTO deletion_certificates(case_id, user_id, scope, object_keys, object_keys_hash, entry_hash)
       VALUES ($1, $2, $3::jsonb, $4::text[], $5, $6)`,
      [
        deletionCase.id,
        userId,
        JSON.stringify(scope),
        deletedKeys,
        hashDeletedObjectKeys(deletedKeys),
        event.entryHash
      ]
    );
    // 触发器在此复核保留期与法务保留；不满足则整个事务回滚。
    await client.query(
      "UPDATE compliance_cases SET status = 'completed', completed_at = now(), updated_at = now() WHERE id = $1",
      [deletionCase.id]
    );
  });
  console.log(`deletion case ${deletionCase.id} completed for subject ${userId}`);
}

/** 导出归档含个人信息，超过下载窗口后从对象存储清除并留痕。 */
export async function expireExportArchives(): Promise<void> {
  const expired = await pool.query<ComplianceCaseRow & { payload: { objectKey?: string } }>(
    `SELECT id, subject_user_id, retention_until, payload FROM compliance_cases
     WHERE case_type = 'export' AND status = 'completed'
       AND payload ? 'objectKey'
       AND NOT payload ? 'purgedAt'
       AND (payload->>'expiresAt')::timestamptz <= now()
     LIMIT 20`
  );
  for (const exportCase of expired.rows) {
    const objectKey = exportCase.payload.objectKey;
    if (!objectKey) continue;
    try {
      await deleteObject(config.S3_QUARANTINE_BUCKET, objectKey);
      await withTransaction(async (client) => {
        await client.query(
          `UPDATE compliance_cases
           SET payload = payload || jsonb_build_object('purgedAt', now()::text), updated_at = now()
           WHERE id = $1`,
          [exportCase.id]
        );
        await appendComplianceEvent(client, {
          caseId: exportCase.id,
          action: "export.purged",
          subjectUserId: exportCase.subject_user_id,
          metadata: { objectKey }
        });
      });
    } catch (error) {
      console.error({ caseId: exportCase.id, error }, "failed to purge expired export archive");
    }
  }
}

/** 合规编排入口：每个 maintenance tick 由 worker 调用。 */
export async function processComplianceCases(): Promise<void> {
  const steps: Array<[string, () => Promise<void>]> = [
    ["releaseExpiredHolds", releaseExpiredHolds],
    ["ensureDeletionCases", ensureDeletionCases],
    ["processExportCases", processExportCases],
    ["processDeletionCases", processDeletionCases],
    ["expireExportArchives", expireExportArchives]
  ];
  for (const [name, step] of steps) {
    try {
      await step();
    } catch (error) {
      console.error({ error, step: name }, "compliance step failed");
    }
  }
}
