import { describe, expect, it } from "vitest";
import {
  buildExportArchive,
  buildTarArchive,
  canonicalManifest,
  isWithinRetention,
  purgeAfter,
  readTarArchive,
  sha256Hex,
  verifyExportArchive,
  type ExportManifest
} from "./compliance";

describe("retention window helpers", () => {
  it("keeps data inside the retention window and releases it after", () => {
    const now = new Date("2026-09-26T00:00:00Z");
    const due = purgeAfter(now, 30);
    expect(due.toISOString()).toBe("2026-10-26T00:00:00.000Z");
    expect(isWithinRetention(now, due)).toBe(true);
    expect(isWithinRetention(new Date("2026-10-25T23:59:59Z"), due)).toBe(true);
    expect(isWithinRetention(new Date("2026-10-26T00:00:00Z"), due)).toBe(false);
  });

  it("treats a missing purge deadline as not retained", () => {
    expect(isWithinRetention(new Date(), null)).toBe(false);
    expect(isWithinRetention(new Date(), undefined)).toBe(false);
  });
});

describe("deterministic tar archive", () => {
  it("round-trips entries and pads records to 512-byte blocks", () => {
    const entries = [
      { path: "data/a.json", data: Buffer.from("hello", "utf8") },
      { path: "media/b.bin", data: Buffer.alloc(1000, 7) }
    ];
    const tar = buildTarArchive(entries);
    expect(tar.length % 512).toBe(0);
    const read = readTarArchive(tar);
    expect(read.get("data/a.json")?.toString()).toBe("hello");
    expect(read.get("media/b.bin")?.equals(Buffer.alloc(1000, 7))).toBe(true);
  });

  it("produces byte-identical archives regardless of entry order", () => {
    const first = buildTarArchive([
      { path: "a.txt", data: Buffer.from("1") },
      { path: "b.txt", data: Buffer.from("22") }
    ]);
    const second = buildTarArchive([
      { path: "b.txt", data: Buffer.from("22") },
      { path: "a.txt", data: Buffer.from("1") }
    ]);
    expect(second.equals(first)).toBe(true);
  });
});

describe("export archive manifest and signature", () => {
  function sampleArchive(secret?: string) {
    return buildExportArchive({
      userId: "11111111-1111-1111-1111-111111111111",
      createdAt: new Date("2026-09-26T08:30:00Z"),
      jsonSections: {
        profile: { email: "a@example.test" },
        features: [{ id: "f1" }]
      },
      media: [{ path: "media/one.txt", data: Buffer.from("image-bytes"), contentType: "text/plain" }],
      ...(secret ? { signingSecret: secret } : {})
    });
  }

  it("records a SHA-256 for every file and a stable manifest hash", () => {
    const built = sampleArchive();
    expect(built.manifest.files.map((file) => file.path)).toEqual([
      "data/features.json",
      "data/profile.json",
      "media/one.txt"
    ]);
    expect(built.manifest.files.every((file) => /^[0-9a-f]{64}$/.test(file.sha256))).toBe(true);
    expect(built.archiveSha256).toBe(sha256Hex(built.archive));
    expect(built.signature).toBeNull();

    const verified = verifyExportArchive(built.archive);
    expect(verified.valid).toBe(true);
    expect(verified.archiveSha256).toBe(built.archiveSha256);
  });

  it("is deterministic for the same input", () => {
    expect(sampleArchive().archive.equals(sampleArchive().archive)).toBe(true);
  });

  it("signs the manifest and rejects tampering or wrong secret", () => {
    const built = sampleArchive("s3cret");
    expect(built.signature).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyExportArchive(built.archive, "s3cret").valid).toBe(true);
    expect(verifyExportArchive(built.archive, "other").valid).toBe(false);

    const files = readTarArchive(built.archive);
    const profile = files.get("data/profile.json")!;
    const tampered = Buffer.from(profile.toString("utf8").replace("a@example.test", "b@example.test"), "utf8");
    const rebuilt = buildTarArchive(
      [...files.entries()]
        .filter(([path]) => path !== "data/profile.json")
        .map(([path, data]) => ({ path, data }))
        .concat([{ path: "data/profile.json", data: tampered }])
    );
    expect(verifyExportArchive(rebuilt, "s3cret").valid).toBe(false);
  });

  it("canonicalizes manifest key order", () => {
    const a: ExportManifest = {
      format: "map-data-export",
      formatVersion: 1,
      userId: "u",
      createdAt: "t",
      files: [{ path: "x", sha256: "h", byteSize: 1, contentType: "application/json" }]
    };
    const reordered: ExportManifest = {
      files: [...a.files].reverse(),
      userId: "u",
      formatVersion: 1,
      format: "map-data-export",
      createdAt: "t"
    };
    expect(canonicalManifest(reordered)).toBe(canonicalManifest(a));
  });
});
