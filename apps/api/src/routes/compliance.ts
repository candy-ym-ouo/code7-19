import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { query, transaction } from "../db";
import { AppError, conflict, notFound } from "../errors";
import { requireAdmin, requireAuth } from "../auth";
import { config } from "../config";
import { recordAudit } from "../audit";
import { createExportDownloadUrl } from "../storage";
import { enqueueExportBuild } from "../queue";
import { clearSessionCookies, revokeSessions } from "./auth";
import { assertNoLegalHold, legalHoldTargetExists, type LegalHoldTargetType } from "../legal-hold";

const exportStatusSchema = z.enum(["pending", "processing", "ready", "failed", "expired"]);

type ExportListRow = {
  id: string;
  status: string;
  byte_size: string | null;
  file_count: number | null;
  sha256: string | null;
  failure_code: string | null;
  expires_at: Date;
  completed_at: Date | null;
  created_at: Date;
};

function serializeExport(row: ExportListRow) {
  return {
    id: row.id,
    status: row.status,
    byteSize: row.byte_size === null ? null : Number(row.byte_size),
    fileCount: row.file_count,
    sha256: row.sha256,
    failureCode: row.failure_code,
    expiresAt: row.expires_at,
    completedAt: row.completed_at,
    createdAt: row.created_at
  };
}

const holdTargetSchema = z.enum(["user", "feature", "comment", "media"]);

export async function complianceRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // 用户侧：导出
  // -------------------------------------------------------------------------

  app.post("/me/compliance/exports", { preHandler: requireAuth, config: { rateLimit: { max: 12, timeWindow: "1 hour" } } }, async (request, reply) => {
    const userId = request.user!.id;
    const active = await query(
      `SELECT id FROM compliance_exports
       WHERE user_id = $1 AND status IN ('pending', 'processing')
       LIMIT 1`,
      [userId]
    );
    if (active.rowCount) throw conflict("An export is already being prepared");

    const inserted = await transaction(async (client) => {
      const result = await client.query<{ id: string; expires_at: Date }>(
        `INSERT INTO compliance_exports(user_id, requested_by, expires_at)
         VALUES ($1, $1, now() + ($2 || ' days')::interval)
         RETURNING id, expires_at`,
        [userId, String(config.EXPORT_RETENTION_DAYS)]
      );
      await recordAudit(client, {
        actorId: userId,
        action: "compliance.export_requested",
        resourceType: "compliance_export",
        resourceId: result.rows[0]!.id
      });
      return result.rows[0]!;
    });

    await enqueueExportBuild(inserted.id);
    return reply.code(202).send({ id: inserted.id, status: "pending", expiresAt: inserted.expires_at });
  });

  app.get("/me/compliance/exports", { preHandler: requireAuth }, async (request) => {
    const result = await query<ExportListRow>(
      `SELECT id, status, byte_size, file_count, sha256, failure_code, expires_at, completed_at, created_at
       FROM compliance_exports WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [request.user!.id]
    );
    return result.rows.map(serializeExport);
  });

  app.get("/me/compliance/exports/:id", { preHandler: requireAuth }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await query<ExportListRow & { user_id: string; manifest_sha256: string | null; signature: string | null; object_key: string | null }>(
      `SELECT id, user_id, status, byte_size, file_count, sha256, manifest_sha256, signature,
              object_key, failure_code, expires_at, completed_at, created_at
       FROM compliance_exports WHERE id = $1`,
      [params.id]
    );
    const row = result.rows[0];
    if (!row || row.user_id !== request.user!.id) throw notFound("Export not found");
    return { ...serializeExport(row), manifestSha256: row.manifest_sha256, signature: row.signature };
  });

  app.post("/me/compliance/exports/:id/download", { preHandler: requireAuth }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await query<{
      id: string; user_id: string; status: string; object_key: string | null; expires_at: Date;
    }>(
      "SELECT id, user_id, status, object_key, expires_at FROM compliance_exports WHERE id = $1",
      [params.id]
    );
    const row = result.rows[0];
    if (!row || row.user_id !== request.user!.id) throw notFound("Export not found");
    if (row.status !== "ready" || !row.object_key) throw new AppError(409, "EXPORT_NOT_READY", "Export is not available for download");
    if (row.expires_at <= new Date()) throw new AppError(410, "EXPORT_EXPIRED", "Export archive has expired and been deleted");
    const url = await createExportDownloadUrl(row.object_key);
    return { downloadUrl: url, expiresInSeconds: 600 };
  });

  // -------------------------------------------------------------------------
  // 用户侧：删除请求（保留期内不可提前清除，冷静期可撤销）
  // -------------------------------------------------------------------------

  app.post("/me/compliance/deletion-requests", { preHandler: requireAuth, config: { rateLimit: { max: 6, timeWindow: "1 hour" } } }, async (request, reply) => {
    const userId = request.user!.id;
    const input = z.object({ reason: z.string().trim().max(500).optional() }).parse(request.body ?? {});
    await assertNoLegalHold("user", userId);

    const created = await transaction(async (client) => {
      const open = await client.query(
        `SELECT id FROM deletion_requests
         WHERE user_id = $1 AND status IN ('scheduled', 'held', 'processing') LIMIT 1 FOR UPDATE`,
        [userId]
      );
      if (open.rowCount) throw conflict("An open deletion request already exists");

      const graceDays = String(config.ACCOUNT_DELETION_GRACE_DAYS);
      const inserted = await client.query<{ id: string; purge_after: Date }>(
        `INSERT INTO deletion_requests(user_id, requested_by, reason_code, purge_after)
         VALUES ($1, $1, 'user_request', now() + ($2 || ' days')::interval)
         RETURNING id, purge_after`,
        [userId, graceDays]
      );
      const requestId = inserted.rows[0]!.id;
      const before = await client.query(
        `SELECT
           (SELECT count(*) FROM map_features WHERE owner_id = $1) AS feature_count,
           (SELECT count(*) FROM comments WHERE author_id = $1) AS comment_count,
           (SELECT count(*) FROM media_assets WHERE owner_id = $1) AS media_count`,
        [userId]
      );
      await client.query("UPDATE deletion_requests SET before_state = $2::jsonb WHERE id = $1", [
        requestId,
        JSON.stringify({ ...before.rows[0], reason: input.reason ?? null })
      ]);
      await client.query(
        `UPDATE users SET status = 'deletion_pending', updated_at = now()
         WHERE id = $1 AND status <> 'deletion_pending'`,
        [userId]
      );
      await revokeSessions(userId);
      await recordAudit(client, {
        actorId: userId,
        action: "compliance.deletion_requested",
        resourceType: "deletion_request",
        resourceId: requestId,
        metadata: { purgeAfter: inserted.rows[0]!.purge_after, graceDays: config.ACCOUNT_DELETION_GRACE_DAYS }
      });
      return inserted.rows[0]!;
    });

    clearSessionCookies(reply);
    return reply.code(202).send({
      id: created.id,
      status: "scheduled",
      purgeAfter: created.purge_after,
      gracePeriodDays: config.ACCOUNT_DELETION_GRACE_DAYS
    });
  });

  app.get("/me/compliance/deletion-requests", { preHandler: requireAuth }, async (request) => {
    const result = await query(
      `SELECT id, status, reason_code, purge_after, held_at, completed_at, cancelled_at,
              before_state, purge_evidence, created_at
       FROM deletion_requests WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
      [request.user!.id]
    );
    return result.rows;
  });

  app.post("/me/compliance/deletion-requests/:id/cancel", { preHandler: requireAuth }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    await transaction(async (client) => {
      const result = await client.query<{ user_id: string; status: string }>(
        `SELECT user_id, status FROM deletion_requests WHERE id = $1 FOR UPDATE`,
        [params.id]
      );
      const row = result.rows[0];
      if (!row || row.user_id !== request.user!.id) throw notFound("Deletion request not found");
      if (row.status !== "scheduled" && row.status !== "held") {
        throw conflict("Only scheduled or held deletion requests can be cancelled");
      }
      await client.query(
        `UPDATE deletion_requests
         SET status = 'cancelled', cancelled_at = now(), cancel_reason = 'user_cancelled', updated_at = now()
         WHERE id = $1`,
        [params.id]
      );
      await client.query(
        `UPDATE users SET status = 'active', updated_at = now()
         WHERE id = $1 AND status = 'deletion_pending'`,
        [request.user!.id]
      );
      await recordAudit(client, {
        actorId: request.user!.id,
        action: "compliance.deletion_cancelled",
        resourceType: "deletion_request",
        resourceId: params.id
      });
    });
    return { status: "cancelled" };
  });

  app.get("/me/compliance/deletion-requests/:id/certificate", { preHandler: requireAuth }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await query(
      `SELECT dr.id, dr.user_id, dr.status, dr.purge_after, dr.completed_at, dr.before_state, dr.purge_evidence
       FROM deletion_requests dr WHERE dr.id = $1`,
      [params.id]
    );
    const row = result.rows[0];
    if (!row || row.user_id !== request.user!.id) throw notFound("Deletion request not found");
    if (row.status !== "completed") throw new AppError(409, "DELETION_NOT_COMPLETE", "Deletion has not been executed yet");
    const verifications = await query(
      `SELECT object_kind, location, bucket, object_key, expected_sha256, verified, check_method, detail, checked_at
       FROM deletion_verifications WHERE request_id = $1 ORDER BY checked_at ASC`,
      [params.id]
    );
    return {
      certificateType: "data_deletion_certificate",
      deletionRequestId: row.id,
      status: row.status,
      scheduledPurgeAfter: row.purge_after,
      completedAt: row.completed_at,
      beforeState: row.before_state,
      purgeEvidence: row.purge_evidence,
      verifications: verifications.rows
    };
  });

  // -------------------------------------------------------------------------
  // 管理员侧：保留策略
  // -------------------------------------------------------------------------

  app.get("/admin/retention-policies", { preHandler: requireAdmin }, async () => {
    const result = await query(
      `SELECT policy_key, display_name, description, scope, retain_for_days, updated_at
       FROM retention_policies ORDER BY policy_key`
    );
    return result.rows;
  });

  app.patch("/admin/retention-policies/:key", { preHandler: requireAdmin }, async (request) => {
    const params = z.object({ key: z.string().min(1).max(64) }).parse(request.params);
    const input = z.object({
      retainForDays: z.number().int().min(0),
      description: z.string().trim().max(500).optional()
    }).parse(request.body);

    const updated = await transaction(async (client) => {
      const result = await client.query<{ policy_key: string; retain_for_days: number }>(
        `UPDATE retention_policies
         SET retain_for_days = $2,
             description = COALESCE($3, description),
             updated_at = now()
         WHERE policy_key = $1
         RETURNING policy_key, retain_for_days`,
        [params.key, input.retainForDays, input.description ?? null]
      );
      if (!result.rowCount) throw notFound("Retention policy not found");
      await recordAudit(client, {
        actorId: request.user!.id,
        action: "compliance.retention_policy_updated",
        resourceType: "retention_policy",
        metadata: { policyKey: params.key, retainForDays: input.retainForDays }
      });
      return result.rows[0]!;
    });
    return updated;
  });

  // -------------------------------------------------------------------------
  // 管理员侧：法务保留
  // -------------------------------------------------------------------------

  app.post("/admin/legal-holds", { preHandler: requireAdmin }, async (request, reply) => {
    const input = z.object({
      holdReference: z.string().trim().min(3).max(120),
      targetType: holdTargetSchema,
      targetId: z.string().uuid(),
      reason: z.string().trim().min(3).max(1000),
      expiresAt: z.coerce.date().optional()
    }).parse(request.body);
    if (input.expiresAt && input.expiresAt <= new Date()) {
      throw new AppError(400, "VALIDATION_FAILED", "Legal hold expiry must be in the future");
    }

    const hold = await transaction(async (client) => {
      if (!(await legalHoldTargetExists(client, input.targetType as LegalHoldTargetType, input.targetId))) {
        throw new AppError(400, "VALIDATION_FAILED", "Legal hold target does not exist");
      }
      const duplicated = await client.query("SELECT 1 FROM legal_holds WHERE hold_reference = $1", [input.holdReference]);
      if (duplicated.rowCount) throw conflict("Hold reference already exists");

      const inserted = await client.query<{ id: string }>(
        `INSERT INTO legal_holds(hold_reference, target_type, target_id, reason, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id`,
        [input.holdReference, input.targetType, input.targetId, input.reason, request.user!.id, input.expiresAt ?? null]
      );
      await recordAudit(client, {
        actorId: request.user!.id,
        action: "compliance.hold_created",
        resourceType: "legal_hold",
        resourceId: inserted.rows[0]!.id,
        metadata: { holdReference: input.holdReference, targetType: input.targetType, targetId: input.targetId }
      });
      return inserted.rows[0]!;
    });
    return reply.code(201).send({ id: hold.id, status: "active" });
  });

  app.get("/admin/legal-holds", { preHandler: requireAdmin }, async (request) => {
    const input = z.object({
      status: z.enum(["active", "released", "all"]).default("active"),
      targetType: holdTargetSchema.optional(),
      targetId: z.string().uuid().optional(),
      limit: z.coerce.number().int().min(1).max(200).default(50)
    }).parse(request.query);

    const clauses: string[] = [];
    const values: unknown[] = [];
    if (input.status !== "all") {
      values.push(input.status);
      clauses.push(`lh.status = $${values.length}`);
    }
    if (input.targetType) {
      values.push(input.targetType);
      clauses.push(`lh.target_type = $${values.length}`);
    }
    if (input.targetId) {
      values.push(input.targetId);
      clauses.push(`lh.target_id = $${values.length}`);
    }
    values.push(input.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await query(
      `SELECT lh.id, lh.hold_reference, lh.target_type, lh.target_id, lh.reason, lh.status,
              lh.expires_at, lh.released_at, lh.created_at,
              creator.display_name AS created_by_name,
              releaser.display_name AS released_by_name
       FROM legal_holds lh
       LEFT JOIN users creator ON creator.id = lh.created_by
       LEFT JOIN users releaser ON releaser.id = lh.released_by
       ${where}
       ORDER BY lh.created_at DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows;
  });

  app.post("/admin/legal-holds/:id/release", { preHandler: requireAdmin }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    await transaction(async (client) => {
      const result = await client.query<{ status: string; target_type: string; target_id: string }>(
        "SELECT status, target_type, target_id FROM legal_holds WHERE id = $1 FOR UPDATE",
        [params.id]
      );
      const row = result.rows[0];
      if (!row) throw notFound("Legal hold not found");
      if (row.status !== "active") throw conflict("Legal hold is already released");
      await client.query(
        `UPDATE legal_holds SET status = 'released', released_by = $2, released_at = now(), updated_at = now()
         WHERE id = $1`,
        [params.id, request.user!.id]
      );
      await recordAudit(client, {
        actorId: request.user!.id,
        action: "compliance.hold_released",
        resourceType: "legal_hold",
        resourceId: params.id,
        metadata: { targetType: row.target_type, targetId: row.target_id }
      });
    });
    return { status: "released" };
  });

  // -------------------------------------------------------------------------
  // 管理员侧：删除请求、导出、删除证明
  // -------------------------------------------------------------------------

  app.get("/admin/deletion-requests", { preHandler: requireAdmin }, async (request) => {
    const input = z.object({
      status: z.enum(["scheduled", "held", "processing", "completed", "cancelled", "all"]).default("all"),
      userId: z.string().uuid().optional(),
      limit: z.coerce.number().int().min(1).max(200).default(50)
    }).parse(request.query);
    const clauses: string[] = [];
    const values: unknown[] = [];
    if (input.status !== "all") {
      values.push(input.status);
      clauses.push(`dr.status = $${values.length}`);
    }
    if (input.userId) {
      values.push(input.userId);
      clauses.push(`dr.user_id = $${values.length}`);
    }
    values.push(input.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await query(
      `SELECT dr.id, dr.user_id, dr.status, dr.reason_code, dr.purge_after, dr.held_at,
              dr.completed_at, dr.cancelled_at, dr.created_at, u.email
       FROM deletion_requests dr
       JOIN users u ON u.id = dr.user_id
       ${where}
       ORDER BY dr.created_at DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows;
  });

  app.get("/admin/deletion-requests/:id/certificate", { preHandler: requireAdmin }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await query(
      `SELECT id, user_id, status, purge_after, completed_at, before_state, purge_evidence
       FROM deletion_requests WHERE id = $1`,
      [params.id]
    );
    const row = result.rows[0];
    if (!row) throw notFound("Deletion request not found");
    const verifications = await query(
      `SELECT object_kind, location, bucket, object_key, expected_sha256, verified, check_method, detail, checked_at
       FROM deletion_verifications WHERE request_id = $1 ORDER BY checked_at ASC`,
      [params.id]
    );
    return { ...row, verifications: verifications.rows };
  });

  app.get("/admin/exports", { preHandler: requireAdmin }, async (request) => {
    const input = z.object({
      status: exportStatusSchema.optional(),
      userId: z.string().uuid().optional(),
      limit: z.coerce.number().int().min(1).max(200).default(50)
    }).parse(request.query);
    const clauses: string[] = [];
    const values: unknown[] = [];
    if (input.status) {
      values.push(input.status);
      clauses.push(`status = $${values.length}`);
    }
    if (input.userId) {
      values.push(input.userId);
      clauses.push(`user_id = $${values.length}`);
    }
    values.push(input.limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await query(
      `SELECT id, user_id, requested_by, status, byte_size, file_count, sha256,
              failure_code, expires_at, completed_at, created_at
       FROM compliance_exports ${where} ORDER BY created_at DESC LIMIT $${values.length}`,
      values
    );
    return result.rows;
  });

  // 导出对象仅由 worker 在保留期到期后删除，不提供任何提前清除路径。

  // 健康检查辅助：确认导出对象确实不存在（证明端）。
  app.get("/admin/exports/:id/verifications", { preHandler: requireAdmin }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await query(
      `SELECT object_kind, location, bucket, object_key, expected_sha256, verified, check_method, detail, checked_at
       FROM deletion_verifications WHERE export_id = $1 ORDER BY checked_at ASC`,
      [params.id]
    );
    return result.rows;
  });
}
