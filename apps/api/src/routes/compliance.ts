import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  complianceCaseQuerySchema,
  createDeletionCaseSchema,
  createExportCaseSchema,
  createLegalHoldSchema,
  releaseLegalHoldSchema
} from "@map/shared/contracts";
import { verifyComplianceChain, DEFAULT_DELETION_RETENTION_DAYS } from "@map/shared/compliance";
import { query, transaction } from "../db";
import { AppError, conflict, notFound } from "../errors";
import { requireAdmin, requireAuth } from "../auth";
import { appendComplianceEvent } from "../compliance";
import { notifyUser } from "../notifications";
import { createPreviewUrl } from "../storage";

const OPEN_DELETION_STATUSES = ["pending", "waiting_retention", "processing", "blocked", "failed"] as const;

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

async function loadSubjectUser(userId: string) {
  const result = await query<{ id: string; status: string; email: string }>(
    "SELECT id, status, email FROM users WHERE id = $1",
    [userId]
  );
  const user = result.rows[0];
  if (!user) throw notFound("Subject user not found");
  return user;
}

async function countActiveHolds(userId: string): Promise<number> {
  const result = await query<{ count: string }>(
    "SELECT count(*)::text AS count FROM legal_holds WHERE user_id = $1 AND released_at IS NULL",
    [userId]
  );
  return Number(result.rows[0]!.count);
}

export async function complianceRoutes(app: FastifyInstance) {
  app.get("/compliance/cases", { preHandler: requireAdmin }, async (request) => {
    const input = complianceCaseQuerySchema.parse(request.query);
    const conditions: string[] = [];
    const values: unknown[] = [];
    if (input.type) {
      values.push(input.type);
      conditions.push(`c.case_type = $${values.length}`);
    }
    if (input.status) {
      values.push(input.status);
      conditions.push(`c.status = $${values.length}`);
    }
    if (input.userId) {
      values.push(input.userId);
      conditions.push(`c.subject_user_id = $${values.length}`);
    }
    values.push(input.limit);
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const result = await query(
      `SELECT c.id, c.case_type, c.status, c.reason, c.subject_user_id,
              u.display_name AS subject_display_name, u.email AS subject_email,
              c.requested_by, c.retention_until, c.legal_hold_id, c.payload,
              c.attempts, c.last_error, c.created_at, c.updated_at, c.completed_at
       FROM compliance_cases c
       JOIN users u ON u.id = c.subject_user_id
       ${where}
       ORDER BY c.created_at DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows;
  });

  app.post("/compliance/exports", { preHandler: requireAdmin }, async (request, reply) => {
    const input = createExportCaseSchema.parse(request.body);
    await loadSubjectUser(input.userId);
    const created = await transaction(async (client) => {
      const result = await client.query<{ id: string }>(
        `INSERT INTO compliance_cases(case_type, subject_user_id, status, reason, requested_by)
         VALUES ('export', $1, 'pending', $2, $3)
         RETURNING id`,
        [input.userId, input.reason, request.user!.id]
      );
      const caseId = result.rows[0]!.id;
      await appendComplianceEvent(client, {
        caseId,
        actorId: request.user!.id,
        action: "export.requested",
        subjectUserId: input.userId,
        metadata: { reason: input.reason }
      });
      return caseId;
    });
    return reply.code(201).send({ caseId: created, status: "pending" });
  });

  app.get("/compliance/exports/:id/download", { preHandler: requireAuth }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await query<{
      id: string;
      case_type: string;
      status: string;
      subject_user_id: string;
      payload: { objectKey?: string; expiresAt?: string; purgedAt?: string };
    }>(
      "SELECT id, case_type, status, subject_user_id, payload FROM compliance_cases WHERE id = $1",
      [params.id]
    );
    const exportCase = result.rows[0];
    if (!exportCase || exportCase.case_type !== "export") throw notFound("Export case not found");
    if (request.user!.role !== "admin" && request.user!.id !== exportCase.subject_user_id) {
      throw new AppError(403, "FORBIDDEN", "Only the data subject or an administrator can download an export");
    }
    if (exportCase.status !== "completed" || !exportCase.payload.objectKey) {
      throw conflict("Export archive is not ready yet");
    }
    if (exportCase.payload.purgedAt) {
      throw new AppError(410, "EXPORT_EXPIRED", "Export archive has been purged after its retention window");
    }
    if (exportCase.payload.expiresAt && new Date(exportCase.payload.expiresAt).getTime() <= Date.now()) {
      throw new AppError(410, "EXPORT_EXPIRED", "Export archive has expired");
    }
    const url = await createPreviewUrl(exportCase.payload.objectKey, 600);
    await transaction(async (client) => {
      await appendComplianceEvent(client, {
        caseId: exportCase.id,
        actorId: request.user!.id,
        action: "export.downloaded",
        subjectUserId: exportCase.subject_user_id
      });
    });
    return { url, expiresIn: 600 };
  });

  app.post("/compliance/legal-holds", { preHandler: requireAdmin }, async (request, reply) => {
    const input = createLegalHoldSchema.parse(request.body);
    const user = await loadSubjectUser(input.userId);
    if (user.status === "deleted") throw conflict("Cannot place a legal hold on a deleted account");

    const created = await transaction(async (client) => {
      const caseResult = await client.query<{ id: string }>(
        `INSERT INTO compliance_cases(case_type, subject_user_id, status, reason, requested_by, retention_until)
         VALUES ('legal_hold', $1, 'active', $2, $3, $4)
         RETURNING id`,
        [input.userId, input.reason, request.user!.id, input.releaseAfter ?? null]
      );
      const caseId = caseResult.rows[0]!.id;
      const holdResult = await client.query<{ id: string }>(
        `INSERT INTO legal_holds(user_id, case_id, reason, placed_by, release_after)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [input.userId, caseId, input.reason, request.user!.id, input.releaseAfter ?? null]
      );
      const holdId = holdResult.rows[0]!.id;
      await client.query("UPDATE compliance_cases SET legal_hold_id = $2, updated_at = now() WHERE id = $1", [caseId, holdId]);

      const blocked = await client.query<{ id: string }>(
        `UPDATE compliance_cases
         SET status = 'blocked', updated_at = now()
         WHERE subject_user_id = $1 AND case_type = 'deletion' AND status = ANY($2::compliance_case_status[])
         RETURNING id`,
        [input.userId, [...OPEN_DELETION_STATUSES]]
      );
      await appendComplianceEvent(client, {
        caseId,
        actorId: request.user!.id,
        action: "legal_hold.placed",
        subjectUserId: input.userId,
        metadata: { reason: input.reason, releaseAfter: input.releaseAfter ?? null, holdId }
      });
      for (const row of blocked.rows) {
        await appendComplianceEvent(client, {
          caseId: row.id,
          actorId: request.user!.id,
          action: "deletion.blocked",
          subjectUserId: input.userId,
          metadata: { holdId }
        });
      }
      await notifyUser(client, {
        userId: input.userId,
        type: "legal_hold_placed",
        title: "你的账号数据已被依法保留",
        body: "因法务要求，你的账号数据在保留解除前不会被删除。",
        link: "/me/notifications"
      });
      return { caseId, holdId };
    });
    return reply.code(201).send({ ...created, status: "active" });
  });

  app.post("/compliance/legal-holds/:id/release", { preHandler: requireAdmin }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const input = releaseLegalHoldSchema.parse(request.body);

    await transaction(async (client) => {
      const holdResult = await client.query<{
        id: string;
        user_id: string;
        case_id: string;
        released_at: string | null;
      }>(
        "SELECT id, user_id, case_id, released_at FROM legal_holds WHERE id = $1 FOR UPDATE",
        [params.id]
      );
      const hold = holdResult.rows[0];
      if (!hold) throw notFound("Legal hold not found");
      if (hold.released_at) throw conflict("Legal hold has already been released");

      await client.query(
        `UPDATE legal_holds
         SET released_at = now(), released_by = $2, release_reason = $3
         WHERE id = $1`,
        [params.id, request.user!.id, input.reason]
      );
      await client.query(
        "UPDATE compliance_cases SET status = 'completed', completed_at = now(), updated_at = now() WHERE id = $1",
        [hold.case_id]
      );
      await appendComplianceEvent(client, {
        caseId: hold.case_id,
        actorId: request.user!.id,
        action: "legal_hold.released",
        subjectUserId: hold.user_id,
        metadata: { reason: input.reason, holdId: hold.id }
      });

      const remaining = await client.query<{ count: string }>(
        "SELECT count(*)::text AS count FROM legal_holds WHERE user_id = $1 AND released_at IS NULL",
        [hold.user_id]
      );
      if (Number(remaining.rows[0]!.count) === 0) {
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
            actorId: request.user!.id,
            action: "deletion.resumed",
            subjectUserId: hold.user_id,
            metadata: { holdId: hold.id }
          });
        }
      }
      await notifyUser(client, {
        userId: hold.user_id,
        type: "legal_hold_released",
        title: "你的账号数据法务保留已解除",
        body: "保留解除后，排队的删除请求将按保留策略继续执行。",
        link: "/me/notifications"
      });
    });
    return { status: "released" };
  });

  app.post("/compliance/deletions", { preHandler: requireAdmin }, async (request, reply) => {
    const input = createDeletionCaseSchema.parse(request.body);
    const user = await loadSubjectUser(input.userId);
    if (user.status === "deleted") throw conflict("Account is already deleted");
    const activeHolds = await countActiveHolds(input.userId);
    if (activeHolds > 0) {
      throw new AppError(409, "LEGAL_HOLD_ACTIVE", "Subject is under an active legal hold; deletion cannot be scheduled");
    }

    const retentionDays = input.retentionDays ?? DEFAULT_DELETION_RETENTION_DAYS;
    try {
      const created = await transaction(async (client) => {
        const result = await client.query<{ id: string; retention_until: string }>(
          `INSERT INTO compliance_cases(case_type, subject_user_id, status, reason, requested_by, retention_until)
           VALUES ('deletion', $1, 'waiting_retention', $2, $3, now() + ($4::text || ' days')::interval)
           RETURNING id, retention_until`,
          [input.userId, input.reason, request.user!.id, String(retentionDays)]
        );
        const row = result.rows[0]!;
        await client.query(
          `UPDATE users
           SET status = 'deletion_pending', deleted_at = COALESCE(deleted_at, now()), updated_at = now()
           WHERE id = $1 AND status <> 'deleted'`,
          [input.userId]
        );
        await client.query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1", [input.userId]);
        await appendComplianceEvent(client, {
          caseId: row.id,
          actorId: request.user!.id,
          action: "deletion.requested",
          subjectUserId: input.userId,
          metadata: { reason: input.reason, retentionDays, source: "admin" }
        });
        return row;
      });
      return reply.code(201).send({
        caseId: created.id,
        status: "waiting_retention",
        retentionUntil: created.retention_until
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new AppError(409, "DELETION_CASE_EXISTS", "An open deletion case already exists for this subject");
      }
      throw error;
    }
  });

  app.get("/compliance/deletions/:id/certificate", { preHandler: requireAdmin }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await query<{
      case_id: string;
      case_type: string;
      case_status: string;
      certificate_id: string | null;
      user_id: string | null;
      scope: unknown;
      object_keys: string[] | null;
      object_keys_hash: string | null;
      entry_hash: string | null;
      issued_at: string | null;
    }>(
      `SELECT c.id AS case_id, c.case_type, c.status AS case_status,
              d.id AS certificate_id, d.user_id, d.scope, d.object_keys,
              d.object_keys_hash, d.entry_hash, d.created_at AS issued_at
       FROM compliance_cases c
       LEFT JOIN deletion_certificates d ON d.case_id = c.id
       WHERE c.id = $1`,
      [params.id]
    );
    const row = result.rows[0];
    if (!row || row.case_type !== "deletion") throw notFound("Deletion case not found");
    if (!row.certificate_id) throw conflict("Deletion case has not completed; no certificate issued");
    return {
      caseId: row.case_id,
      certificateId: row.certificate_id,
      userId: row.user_id,
      scope: row.scope,
      objectKeys: row.object_keys,
      objectKeysHash: row.object_keys_hash,
      entryHash: row.entry_hash,
      issuedAt: row.issued_at
    };
  });

  app.get("/compliance/audit", { preHandler: requireAdmin }, async (request) => {
    const input = z
      .object({
        caseId: z.string().uuid().optional(),
        userId: z.string().uuid().optional(),
        limit: z.coerce.number().int().min(1).max(500).default(100)
      })
      .parse(request.query);
    const conditions: string[] = [];
    const values: unknown[] = [];
    if (input.caseId) {
      values.push(input.caseId);
      conditions.push(`case_id = $${values.length}`);
    }
    if (input.userId) {
      values.push(input.userId);
      conditions.push(`subject_user_id = $${values.length}`);
    }
    values.push(input.limit);
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const result = await query<{
      seq: string;
      case_id: string | null;
      actor_id: string | null;
      action: string;
      subject_user_id: string | null;
      metadata: string;
      prev_hash: string;
      entry_hash: string;
      occurred_at: Date;
    }>(
      `SELECT seq, case_id, actor_id, action, subject_user_id, metadata, prev_hash, entry_hash, occurred_at
       FROM compliance_events
       ${where}
       ORDER BY seq DESC
       LIMIT $${values.length}`,
      values
    );
    return result.rows.map((row) => ({
      seq: Number(row.seq),
      caseId: row.case_id,
      actorId: row.actor_id,
      action: row.action,
      subjectUserId: row.subject_user_id,
      metadata: JSON.parse(row.metadata) as unknown,
      prevHash: row.prev_hash,
      entryHash: row.entry_hash,
      occurredAt: row.occurred_at
    }));
  });

  app.get("/compliance/audit/verify", { preHandler: requireAdmin }, async () => {
    const result = await query<{
      seq: string;
      case_id: string | null;
      actor_id: string | null;
      action: string;
      subject_user_id: string | null;
      metadata: string;
      prev_hash: string;
      entry_hash: string;
      occurred_at: Date;
    }>(
      `SELECT seq, case_id, actor_id, action, subject_user_id, metadata, prev_hash, entry_hash, occurred_at
       FROM compliance_events ORDER BY seq ASC`
    );
    const verification = verifyComplianceChain(
      result.rows.map((row) => ({
        seq: Number(row.seq),
        prevHash: row.prev_hash,
        caseId: row.case_id,
        actorId: row.actor_id,
        action: row.action,
        subjectUserId: row.subject_user_id,
        metadataJson: row.metadata,
        occurredAt: row.occurred_at.toISOString(),
        entryHash: row.entry_hash
      }))
    );
    return verification;
  });
}
