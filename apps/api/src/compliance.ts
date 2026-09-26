import type { PoolClient } from "pg";
import {
  canonicalJson,
  computeComplianceEntryHash,
  COMPLIANCE_CHAIN_GENESIS,
  type ComplianceEventAction
} from "@map/shared/compliance";

/**
 * 向防篡改审计链追加一条事件。
 * 必须在事务内调用：advisory 锁串行化链追加，保证 prev_hash 不会分叉。
 */
export async function appendComplianceEvent(
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
