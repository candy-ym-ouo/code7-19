import { buildExportArchive, sha256Hex } from "@map/shared/compliance";
import { randomToken } from "@map/shared/server";
import { config } from "./config";
import { pool } from "./db";
import {
  deleteExportObject,
  deleteObject,
  exportObjectExists,
  objectExists,
  putExportObject,
  readQuarantineObject
} from "./storage";

// ---------------------------------------------------------------------------
// 法务保留
// ---------------------------------------------------------------------------

/**
 * 用户是否命中有效法务保留（直接挂在用户上，或挂在其任意 feature/comment/media 上）。
 * 命中时账号清除必须延期。
 */
async function userHasActiveHold(client: import("pg").PoolClient, userId: string): Promise<boolean> {
  const result = await client.query(
    `SELECT 1 FROM legal_holds
     WHERE status = 'active'
       AND (expires_at IS NULL OR expires_at > now())
       AND (
         (target_type = 'user' AND target_id = $1)
         OR (target_type = 'feature' AND target_id IN (SELECT id FROM map_features WHERE owner_id = $1))
         OR (target_type = 'media' AND target_id IN (SELECT id FROM media_assets WHERE owner_id = $1))
         OR (target_type = 'comment' AND target_id IN (SELECT id FROM comments WHERE author_id = $1))
       )
     LIMIT 1`,
    [userId]
  );
  return Boolean(result.rowCount);
}

/** 单个资源（或其属主）是否命中有效法务保留。 */
async function resourceHeld(
  client: import("pg").PoolClient,
  targetType: "feature" | "comment" | "media",
  targetId: string
): Promise<boolean> {
  const ownerColumn = targetType === "comment" ? "author_id" : "owner_id";
  const table = targetType === "feature" ? "map_features" : targetType === "comment" ? "comments" : "media_assets";
  const result = await client.query(
    `WITH target AS (SELECT ${ownerColumn} AS owner_id FROM ${table} WHERE id = $2)
     SELECT 1 FROM legal_holds, target
     WHERE status = 'active'
       AND (expires_at IS NULL OR expires_at > now())
       AND (
         (target_type = $1 AND target_id = $2)
         OR (target_type = 'user' AND target_id = target.owner_id)
       )
     LIMIT 1`,
    [targetType, targetId]
  );
  return Boolean(result.rowCount);
}

export { resourceHeld };

// ---------------------------------------------------------------------------
// 导出构建
// ---------------------------------------------------------------------------

type ExportRow = {
  id: string;
  user_id: string;
  status: string;
};

export async function processExportJob(exportId: string): Promise<void> {
  // 原子认领：只把 pending/failed 行推进到 processing，保证同一导出不会被两个 worker 并发构建。
  const claimed = await pool.query<ExportRow>(
    `UPDATE compliance_exports
     SET status = 'processing', updated_at = now()
     WHERE id = $1 AND status IN ('pending', 'failed')
     RETURNING id, user_id, status`,
    [exportId]
  );
  const job = claimed.rows[0];
  if (!job) {
    console.log(`skip export ${exportId}: not runnable`);
    return;
  }

  const userId = job.user_id;

  try {
    const [profile, features, comments, confirmations, reports, media] = await Promise.all([
      pool.query(
        `SELECT id, email, display_name, role, status, email_verified_at, last_login_at, created_at
         FROM users WHERE id = $1`,
        [userId]
      ),
      pool.query(
        `SELECT mf.id, mf.category_key, mf.status, mf.created_at, mf.updated_at,
                fr.revision_no, fr.payload
         FROM map_features mf
         LEFT JOIN feature_revisions fr
           ON fr.id = COALESCE(mf.current_revision_id, (
             SELECT id FROM feature_revisions WHERE feature_id = mf.id ORDER BY revision_no DESC LIMIT 1
           ))
         WHERE mf.owner_id = $1
         ORDER BY mf.created_at DESC`,
        [userId]
      ),
      pool.query(
        `SELECT id, feature_id, parent_id, body, status, created_at, updated_at, deleted_at
         FROM comments WHERE author_id = $1 ORDER BY created_at DESC`,
        [userId]
      ),
      pool.query(
        `SELECT feature_id, result, note, created_at
         FROM feature_confirmations WHERE user_id = $1 ORDER BY created_at DESC`,
        [userId]
      ),
      pool.query(
        `SELECT id, target_type, target_id, reason_code, notes, status, created_at
         FROM reports WHERE reporter_id = $1 ORDER BY created_at DESC`,
        [userId]
      ),
      pool.query(
        `SELECT id, original_filename, mime_type, byte_size, width, height, sha256,
                quarantine_object_key, processed_object_key, privacy_status, created_at, deleted_at
         FROM media_assets WHERE owner_id = $1 ORDER BY created_at DESC`,
        [userId]
      )
    ]);

    const createdAt = new Date();
    const jsonSections = {
      profile: profile.rows[0] ?? null,
      features: features.rows,
      comments: comments.rows,
      confirmations: confirmations.rows,
      reports: reports.rows,
      media_index: media.rows.map(({ quarantine_object_key, processed_object_key, ...rest }) => ({
        ...rest,
        quarantineObjectIncluded: false,
        processedObjectIncluded: Boolean(processed_object_key)
      }))
    };

    // 仅导出服务端隐私处理后的派生图（WebP）；原图永不离开隔离桶。
    const mediaFiles: Array<{ path: string; data: Buffer; contentType: string }> = [];
    const mediaErrors: Array<{ mediaId: string; reason: string }> = [];
    let mediaBytes = 0;
    for (const item of media.rows) {
      if (!item.processed_object_key) continue;
      if (mediaBytes >= config.EXPORT_MEDIA_MAX_BYTES) {
        mediaErrors.push({ mediaId: item.id, reason: "export_media_size_limit_reached" });
        continue;
      }
      try {
        const data = await readQuarantineObject(item.processed_object_key);
        mediaFiles.push({ path: `media/${item.id}.webp`, data, contentType: "image/webp" });
        mediaBytes += data.length;
      } catch (error) {
        mediaErrors.push({
          mediaId: item.id,
          reason: error instanceof Error ? error.message.slice(0, 200) : "read_failed"
        });
      }
    }

    const built = buildExportArchive({
      userId,
      createdAt,
      jsonSections: { ...jsonSections, media_warnings: mediaErrors },
      media: mediaFiles,
      signingSecret: config.EXPORT_SIGNING_SECRET
    });

    const objectKey = `exports/${userId}/${exportId}.tar`;
    await putExportObject(objectKey, built.archive);

    await pool.query(
      `UPDATE compliance_exports
       SET status = 'ready', object_bucket = $2, object_key = $3, byte_size = $4,
           file_count = $5, sha256 = $6, manifest_sha256 = $7, signature = $8,
           failure_code = NULL, last_error = NULL, completed_at = now(), updated_at = now()
       WHERE id = $1`,
      [
        exportId,
        config.S3_EXPORT_BUCKET,
        objectKey,
        String(built.archive.length),
        built.manifest.files.length,
        built.archiveSha256,
        built.manifestSha256,
        built.signature,
      ]
    );

    // 站内通知 + 邮件 outbox（派发器要求邮件事件带 to/subject/text/html）。
    const userRow = await pool.query<{ email: string }>("SELECT email FROM users WHERE id = $1", [userId]);
    const title = "你的数据导出已就绪";
    const body = `导出包 #${exportId.slice(0, 8)} 将保留 ${config.EXPORT_RETENTION_DAYS} 天，到期自动删除。请在设置页下载。`;
    await pool.query(
      `INSERT INTO notifications(user_id, type, title, body, link)
       VALUES ($1, 'compliance_export_ready', $2, $3, '/settings')`,
      [userId, title, body]
    );
    if (userRow.rows[0]?.email) {
      await pool.query(
        `INSERT INTO outbox_events(event_type, aggregate_type, aggregate_id, payload)
         VALUES ('email.notification', 'compliance_export', $1, $2::jsonb)`,
        [exportId, JSON.stringify({
          to: userRow.rows[0].email,
          subject: title,
          text: body,
          html: `<p>${body}</p>`
        })]
      );
    }
    console.log(`export ${exportId} built: ${built.manifest.files.length} files, sha256=${built.archiveSha256.slice(0, 12)}`);
  } catch (error) {
    const message = error instanceof Error ? error.message.slice(0, 500) : "Unknown export error";
    await pool.query(
      `UPDATE compliance_exports SET status = 'failed', failure_code = 'build_failed', last_error = $2, updated_at = now()
       WHERE id = $1`,
      [exportId, message]
    );
    throw error;
  }
}

/** 兜底捞取停留过久的 pending 导出（Redis 通知丢失时）。 */
export async function recoverStuckExports(): Promise<string[]> {
  const result = await pool.query<{ id: string }>(
    `UPDATE compliance_exports
     SET status = 'pending', updated_at = now()
     WHERE status = 'processing' AND updated_at < now() - interval '20 minutes'
     RETURNING id`
  );
  return result.rows.map((row) => row.id);
}

/**
 * 到期导出清除：仅清除 expires_at <= now 的归档；保留期内绝不删除。
 * 每个对象删除后用 HeadObject 复验不存在，并写入删除证明。
 */
export async function sweepExpiredExports(): Promise<void> {
  // 原子认领：到期 ready 行先置为 processing（清除中），避免两个 tick 重复删除同一对象。
  // 只选择 expires_at <= now 的行：保留期内绝不会被认领。
  const claimed = await pool.query<{ id: string; object_key: string; sha256: string | null }>(
    `UPDATE compliance_exports
     SET status = 'processing', updated_at = now()
     WHERE id IN (
       SELECT id FROM compliance_exports
       WHERE status = 'ready' AND expires_at <= now() AND object_key IS NOT NULL
       LIMIT 20
     )
     RETURNING id, object_key, sha256`
  );
  const dueRows = claimed.rows.map((row) => ({ ...row, object_key: row.object_key! }));

  for (const row of dueRows) {
    const key = row.object_key;
    const existedBefore = await exportObjectExists(key);
    try {
      if (existedBefore) await deleteExportObject(key);
    } catch (error) {
      // 删除失败：退回 ready，下一轮重试，避免漏删或提前出具证明。
      await pool.query(
        "UPDATE compliance_exports SET status = 'ready', updated_at = now() WHERE id = $1 AND status = 'processing'",
        [row.id]
      );
      console.error({ exportId: row.id, error }, "expired export object deletion failed; will retry");
      continue;
    }

    // 复验：对象必须不存在。
    const verified = !(await exportObjectExists(key));
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO deletion_verifications(export_id, object_kind, location, bucket, object_key, expected_sha256, verified, check_method, detail)
         VALUES ($1, 'export_archive', $2, $3, $4, $5, $6, 's3_head_object_after_delete', $7::jsonb)`,
        [
          row.id,
          `s3://${config.S3_EXPORT_BUCKET}/${key}`,
          config.S3_EXPORT_BUCKET,
          key,
          row.sha256,
          verified,
          JSON.stringify({ existedBefore, notFoundAfter: verified, sweptAt: new Date().toISOString() })
        ]
      );
      if (!verified) {
        // 对象仍可访问：不宣告过期，留待下一轮复验。
        await client.query(
          "UPDATE compliance_exports SET status = 'ready', updated_at = now() WHERE id = $1",
          [row.id]
        );
        await client.query("COMMIT");
        continue;
      }
      await client.query(
        `UPDATE compliance_exports
         SET status = 'expired', object_bucket = NULL, object_key = NULL, updated_at = now()
         WHERE id = $1`,
        [row.id]
      );
      await client.query(
        `INSERT INTO audit_logs(action, resource_type, resource_id, metadata)
         VALUES ('compliance.export_expired', 'compliance_export', $1, $2::jsonb)`,
        [row.id, JSON.stringify({ verified, sha256: row.sha256 })]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
}

// ---------------------------------------------------------------------------
// 删除请求编排
// ---------------------------------------------------------------------------

type ObjectRef = { bucket: string; key: string; kind: string; mediaId?: string };

async function collectUserObjects(client: import("pg").PoolClient, userId: string): Promise<ObjectRef[]> {
  const media = await client.query<{
    quarantine_object_key: string;
    processed_object_key: string | null;
    thumbnail_object_key: string | null;
    public_object_key: string | null;
    public_thumbnail_object_key: string | null;
  }>(
    `SELECT quarantine_object_key, processed_object_key, thumbnail_object_key,
            public_object_key, public_thumbnail_object_key
     FROM media_assets WHERE owner_id = $1`,
    [userId]
  );
  const refs: ObjectRef[] = [];
  for (const item of media.rows) {
    refs.push({ bucket: config.S3_QUARANTINE_BUCKET, key: item.quarantine_object_key, kind: "media_original" });
    if (item.processed_object_key) refs.push({ bucket: config.S3_QUARANTINE_BUCKET, key: item.processed_object_key, kind: "media_processed" });
    if (item.thumbnail_object_key) refs.push({ bucket: config.S3_QUARANTINE_BUCKET, key: item.thumbnail_object_key, kind: "media_thumbnail" });
    if (item.public_object_key) refs.push({ bucket: config.S3_PUBLIC_BUCKET, key: item.public_object_key, kind: "media_public" });
    if (item.public_thumbnail_object_key) refs.push({ bucket: config.S3_PUBLIC_BUCKET, key: item.public_thumbnail_object_key, kind: "media_public_thumbnail" });
  }
  return refs;
}

/**
 * 处理到期删除请求：
 *  1. 行级锁选取 scheduled 且 purge_after <= now 的请求；保留期内永不入选。
 *  2. 重新检查法务保留：命中则转 held，等待释放后下一轮再评估。
 *  3. 删除全部 S3 对象并逐项 HeadObject 复验。
 *  4. 事务内更新数据库为终态（媒体/内容 deleted，用户匿名化），写入删除证明。
 */
export async function processDueDeletionRequests(): Promise<void> {
  // 原子认领：到期 scheduled 行先置 processing，保证同一请求不会被两个 tick 并发清除。
  // 只选择 purge_after <= now：保留期内永不入选，因此不存在提前清除路径。
  const claimed = await pool.query<{ id: string; user_id: string }>(
    `UPDATE deletion_requests
     SET status = 'processing', updated_at = now()
     WHERE id IN (
       SELECT id FROM deletion_requests
       WHERE status = 'scheduled' AND purge_after <= now()
       ORDER BY purge_after
       LIMIT 5
     )
     RETURNING id, user_id`
  );

  for (const requestRow of claimed.rows) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const held = await userHasActiveHold(client, requestRow.user_id);
      if (held) {
        await client.query(
          `UPDATE deletion_requests SET status = 'held', held_at = now(), updated_at = now() WHERE id = $1`,
          [requestRow.id]
        );
        await client.query(
          `INSERT INTO audit_logs(actor_id, action, resource_type, resource_id, metadata)
           VALUES (NULL, 'compliance.purge_held', 'deletion_request', $1, '{}'::jsonb)`,
          [requestRow.id]
        );
        await client.query("COMMIT");
        continue;
      }

      const objects = await collectUserObjects(client, requestRow.user_id);
      await client.query("COMMIT");

      // S3 删除在事务外执行（慢且可能重试）；幂等：不存在即视为已删除。
      const objectEvidence: Array<Record<string, unknown>> = [];
      let allVerified = true;
      for (const ref of objects) {
        const existedBefore = await objectExists(ref.bucket, ref.key).catch(() => true);
        if (existedBefore) {
          await deleteObject(ref.bucket, ref.key);
        }
        const notFoundAfter = !(await objectExists(ref.bucket, ref.key).catch(() => true));
        if (!notFoundAfter) allVerified = false;
        objectEvidence.push({
          objectKind: "s3_object",
          location: `s3://${ref.bucket}/${ref.key}`,
          bucket: ref.bucket,
          key: ref.key,
          kind: ref.kind,
          existedBefore,
          verified: notFoundAfter,
          checkMethod: "s3_head_object_after_delete"
        });
      }
      if (!allVerified) {
        // 有对象未能确认删除：退回 scheduled，下一轮重试，绝不宣告完成。
        await pool.query(
          "UPDATE deletion_requests SET status = 'scheduled', updated_at = now() WHERE id = $1 AND status = 'processing'",
          [requestRow.id]
        );
        console.error({ deletionRequestId: requestRow.id }, "purge verification incomplete; retrying later");
        continue;
      }

      await client.query("BEGIN");

      // 该用户全部导出归档也必须清除（含未到期的：账号删除优先于导出保留期），逐项证明。
      const exports = await client.query<{ id: string; object_key: string | null; sha256: string | null }>(
        `SELECT id, object_key, sha256 FROM compliance_exports
         WHERE user_id = $1 AND object_key IS NOT NULL AND status <> 'expired'
         FOR UPDATE OF compliance_exports`,
        [requestRow.user_id]
      );
      for (const exportRow of exports.rows) {
        const key = exportRow.object_key!;
        const existedBefore = await exportObjectExists(key);
        if (existedBefore) await deleteExportObject(key);
        const notFoundAfter = !(await exportObjectExists(key));
        if (!notFoundAfter) {
          allVerified = false;
          break;
        }
        await client.query(
          `INSERT INTO deletion_verifications(export_id, object_kind, location, bucket, object_key, expected_sha256, verified, check_method, detail)
           VALUES ($1, 'export_archive', $2, $3, $4, $5, true, 's3_head_object_after_delete', $6::jsonb)`,
          [
            exportRow.id,
            `s3://${config.S3_EXPORT_BUCKET}/${key}`,
            config.S3_EXPORT_BUCKET,
            key,
            exportRow.sha256,
            JSON.stringify({ existedBefore, deletedDuringAccountPurge: true })
          ]
        );
        await client.query(
          `UPDATE compliance_exports SET status = 'expired', object_bucket = NULL, object_key = NULL, updated_at = now()
           WHERE id = $1`,
          [exportRow.id]
        );
      }
      if (!allVerified) {
        await client.query("ROLLBACK");
        await pool.query(
          "UPDATE deletion_requests SET status = 'scheduled', updated_at = now() WHERE id = $1 AND status = 'processing'",
          [requestRow.id]
        );
        console.error({ deletionRequestId: requestRow.id }, "export deletion verification incomplete; retrying later");
        continue;
      }

      // 数据库终态。
      await client.query(
        `UPDATE media_assets
         SET privacy_status = 'deleted',
             quarantine_object_key = 'deleted/' || id || '.object',
             processed_object_key = NULL, thumbnail_object_key = NULL,
             public_object_key = NULL, public_thumbnail_object_key = NULL,
             delete_after = NULL, deleted_at = now(), updated_at = now()
         WHERE owner_id = $1`,
        [requestRow.user_id]
      );
      await client.query(
        `UPDATE comments SET status = 'deleted', deleted_at = now(), updated_at = now()
         WHERE author_id = $1 AND deleted_at IS NULL`,
        [requestRow.user_id]
      );
      await client.query(
        `UPDATE map_features SET status = 'deleted', deleted_at = now(), updated_at = now()
         WHERE owner_id = $1 AND deleted_at IS NULL`,
        [requestRow.user_id]
      );

      const counts = await client.query<{ media: string; comments: string; features: string }>(
        `SELECT
           (SELECT count(*) FROM media_assets WHERE owner_id = $1) AS media,
           (SELECT count(*) FROM comments WHERE author_id = $1) AS comments,
           (SELECT count(*) FROM map_features WHERE owner_id = $1) AS features`,
        [requestRow.user_id]
      );

      const anonymizedEmail = `deleted+${requestRow.user_id}@invalid.local`;
      await client.query(
        `UPDATE users
         SET email = $2, email_normalized = $2, display_name = '已删除用户',
             password_hash = $3, status = 'deleted', updated_at = now()
         WHERE id = $1`,
        [requestRow.user_id, anonymizedEmail, `!unusable:${randomToken(24)}`]
      );

      // 数据库记录“清除后复验”：残留活动行必须为 0。
      const residue = await client.query<{ active_media: string; active_comments: string; active_features: string }>(
        `SELECT
           (SELECT count(*) FROM media_assets WHERE owner_id = $1 AND privacy_status <> 'deleted') AS active_media,
           (SELECT count(*) FROM comments WHERE author_id = $1 AND status <> 'deleted') AS active_comments,
           (SELECT count(*) FROM map_features WHERE owner_id = $1 AND status <> 'deleted') AS active_features`,
        [requestRow.user_id]
      );
      const dbVerified = ["active_media", "active_comments", "active_features"].every(
        (key) => Number(residue.rows[0]?.[key as "active_media"]) === 0
      );

      for (const ref of objectEvidence) {
        await client.query(
          `INSERT INTO deletion_verifications(request_id, object_kind, location, bucket, object_key, verified, check_method, detail)
           VALUES ($1, 's3_object', $2, $3, $4, $5, 's3_head_object_after_delete', $6::jsonb)`,
          [
            requestRow.id,
            ref.location,
            ref.bucket,
            ref.key,
            ref.verified,
            JSON.stringify({ kind: ref.kind, existedBefore: ref.existedBefore })
          ]
        );
      }

      await client.query(
        `INSERT INTO deletion_verifications(request_id, object_kind, location, verified, check_method, detail)
         VALUES ($1, 'database_record', $2, $3, 'sql_residual_count_after_purge', $4::jsonb)`,
        [
          requestRow.id,
          `postgres:users/${requestRow.user_id}`,
          dbVerified,
          JSON.stringify({ residue: residue.rows[0], counts: counts.rows[0] })
        ]
      );

      const evidenceDigest = sha256Hex(JSON.stringify({ objectEvidence, residue: residue.rows[0] }));
      await client.query(
        `UPDATE deletion_requests
         SET status = 'completed', completed_at = now(), purge_evidence = $2::jsonb, updated_at = now()
         WHERE id = $1`,
        [
          requestRow.id,
          JSON.stringify({
            purgedAt: new Date().toISOString(),
            objectCount: objectEvidence.length,
            allObjectsVerifiedAbsent: objectEvidence.every((item) => item.verified),
            databaseResidue: residue.rows[0],
            counts: counts.rows[0],
            evidenceDigest
          })
        ]
      );
      await client.query(
        `INSERT INTO audit_logs(actor_id, action, resource_type, resource_id, metadata)
         VALUES (NULL, 'compliance.account_purged', 'deletion_request', $1, $2::jsonb)`,
        [requestRow.id, JSON.stringify({ evidenceDigest, objectCount: objectEvidence.length, dbVerified })]
      );
      await client.query("COMMIT");
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // 连接可能已中断。
      }
      // 崩溃/异常后退回 scheduled，由下一个 tick 幂等重试；不会提前或重复完成。
      await pool
        .query(
          "UPDATE deletion_requests SET status = 'scheduled', updated_at = now() WHERE id = $1 AND status = 'processing'",
          [requestRow.id]
        )
        .catch(() => undefined);
      console.error({ deletionRequestId: requestRow.id, error }, "deletion request processing failed");
    } finally {
      client.release();
    }
  }
}

/**
 * 法务保留释放后，held 请求重新进入调度：
 * 清除时刻以原 purge_after 为准（保证没有提前清除）；若当时已到期，下一轮立即处理。
 */
export async function reevaluateHeldDeletions(): Promise<void> {
  await pool.query(
    `UPDATE deletion_requests dr
     SET status = 'scheduled', updated_at = now()
     WHERE dr.status = 'held'
       AND NOT EXISTS (
         SELECT 1 FROM legal_holds lh
         WHERE lh.status = 'active'
           AND (lh.expires_at IS NULL OR lh.expires_at > now())
           AND (
             (lh.target_type = 'user' AND lh.target_id = dr.user_id)
             OR (lh.target_type = 'feature' AND lh.target_id IN (SELECT id FROM map_features WHERE owner_id = dr.user_id))
             OR (lh.target_type = 'media' AND lh.target_id IN (SELECT id FROM media_assets WHERE owner_id = dr.user_id))
             OR (lh.target_type = 'comment' AND lh.target_id IN (SELECT id FROM comments WHERE author_id = dr.user_id))
           )
       )`
  );
}

/** 崩溃恢复：processing 超过 10 分钟的删除请求退回 scheduled，由下一轮幂等重试。 */
export async function recoverStuckDeletions(): Promise<void> {
  await pool.query(
    `UPDATE deletion_requests
     SET status = 'scheduled', updated_at = now()
     WHERE status = 'processing' AND updated_at < now() - interval '10 minutes'`
  );
}
