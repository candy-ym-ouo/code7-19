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

  it("uses PostGIS geography points and spatial indexes", () => {
    expect(migration).toContain("geography(Point, 4326)");
    expect(migration).toContain("USING gist (geom)");
  });

  it("creates the compliance orchestration schema in migration 0003", () => {
    const compliance = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../migrations/0003_compliance.sql"),
      "utf8"
    );
    for (const table of [
      "compliance_cases",
      "legal_holds",
      "deletion_certificates",
      "compliance_events"
    ]) {
      expect(compliance).toContain(`CREATE TABLE ${table}`);
    }
  });

  it("enforces retention and legal holds with database triggers", () => {
    const compliance = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../migrations/0003_compliance.sql"),
      "utf8"
    );
    // 删除案件在 retention_until 届满或存在活跃法务保留时不得置为 completed。
    expect(compliance).toContain("CREATE FUNCTION enforce_deletion_retention()");
    expect(compliance).toContain("retention_until > now()");
    expect(compliance).toContain("released_at IS NULL");
    // 活跃法务保留下不得把账号匿名化为 deleted。
    expect(compliance).toContain("CREATE FUNCTION enforce_legal_hold_on_user_delete()");
    // 审计证据只追加。
    expect(compliance).toContain("BEFORE UPDATE OR DELETE ON compliance_events");
    expect(compliance).toContain("BEFORE UPDATE OR DELETE ON deletion_certificates");
    // 审计链按全局 seq 串行化并支持独立重放。
    expect(compliance).toContain("GENERATED ALWAYS AS IDENTITY");
  });
});
