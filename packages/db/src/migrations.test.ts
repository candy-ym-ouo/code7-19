import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const migration = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../migrations/0001_init.sql"),
  "utf8"
);

describe("initial migration", () => {
  it("contains the core audited entities", () => {
    for (const table of [
      "users", "sessions", "auth_tokens", "categories", "map_features",
      "feature_revisions", "media_assets", "comments", "reports",
      "moderation_actions", "outbox_events", "audit_logs", "notifications"
    ]) {
      expect(migration).toContain(`CREATE TABLE ${table}`);
    }
  });

  it("adds public thumbnail and outbox recovery fields in migration 0002", () => {
    const followup = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../migrations/0002_media_public_thumb.sql"),
      "utf8"
    );
    expect(followup).toContain("public_thumbnail_object_key");
    expect(followup).toContain("updated_at timestamptz");
  });

  it("creates the compliance orchestration tables in migration 0003", () => {
    const compliance = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../migrations/0003_compliance.sql"),
      "utf8"
    );
    for (const table of [
      "retention_policies",
      "legal_holds",
      "compliance_exports",
      "deletion_requests",
      "deletion_verifications"
    ]) {
      expect(compliance).toContain(`CREATE TABLE ${table}`);
    }
    // 保留期约束：删除请求必须带 purge_after；法务保留带 active/released 状态。
    expect(compliance).toContain("purge_after timestamptz NOT NULL");
    expect(compliance).toContain("legal_hold_status AS ENUM ('active', 'released')");
    // 删除证明必须挂到删除请求或导出二者之一。
    expect(compliance).toContain("num_nonnulls(request_id, export_id) = 1");
    // 默认保留策略种子。
    expect(compliance).toContain("account_pending_deletion");
    expect(compliance).toContain("export_archive");
  });

  it("uses PostGIS geography points and spatial indexes", () => {
    expect(migration).toContain("geography(Point, 4326)");
    expect(migration).toContain("USING gist (geom)");
  });
});
