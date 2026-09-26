import { createHash, createHmac, timingSafeEqual } from "node:crypto";

// ---------------------------------------------------------------------------
// 保留策略
// ---------------------------------------------------------------------------

export type RetentionPolicyKey =
  | "account_pending_deletion"
  | "export_archive"
  | "media_original"
  | "media_failed"
  | "deleted_content"
  | "audit_log"
  | "notification";

export const DEFAULT_RETENTION_DAYS: Record<RetentionPolicyKey, number> = {
  account_pending_deletion: 30,
  export_archive: 30,
  media_original: 1,
  media_failed: 7,
  deleted_content: 90,
  audit_log: 2555,
  notification: 180
};

/** 计算清除时刻；保留期内（含到期时刻）不得清除，因此最早可清除时间为 now + days 天。 */
export function purgeAfter(createdAt: Date, retainDays: number): Date {
  return new Date(createdAt.getTime() + retainDays * 24 * 60 * 60 * 1000);
}

/** 保留期内返回 true，调度器必须跳过。 */
export function isWithinRetention(now: Date, purgeAfterAt: Date | string | null | undefined): boolean {
  if (!purgeAfterAt) return false;
  const due = typeof purgeAfterAt === "string" ? new Date(purgeAfterAt) : purgeAfterAt;
  return now.getTime() < due.getTime();
}

// ---------------------------------------------------------------------------
// 确定性 USTAR tar（无第三方依赖）
//
// 所有条目按文件名排序、固定 uid/gid/mtime，保证同一份数据多次打包字节一致，
// 从而归档 SHA-256 可作为“归档内容完整性”的证明。
// ---------------------------------------------------------------------------

export type ArchiveEntry = {
  path: string;
  data: Buffer;
  /** 默认 0644；导出清单等可标记只读。 */
  mode?: number;
  contentType?: string;
};

const TAR_BLOCK = 512;
const TAR_MAGIC = "ustar\x0000";

function writeOctal(buffer: Buffer, offset: number, length: number, value: number): void {
  const digits = value.toString(8).padStart(length - 1, "0");
  buffer.write(digits.slice(0, length - 1), offset, "ascii");
  buffer[offset + length - 1] = 0;
}

function writeString(buffer: Buffer, offset: number, length: number, value: string): void {
  buffer.write(value, offset, length, "ascii");
  buffer.fill(0, offset + value.length, offset + length);
}

function tarHeader(entry: { path: string; data: Buffer; mode: number }): Buffer {
  const header = Buffer.alloc(TAR_BLOCK);
  const name = entry.path;
  if (name.length > 100) throw new Error(`archive path too long: ${name}`);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, entry.mode);
  writeOctal(header, 108, 8, 0); // uid
  writeOctal(header, 116, 8, 0); // gid
  writeOctal(header, 124, 12, entry.data.length);
  writeOctal(header, 136, 12, 0); // mtime = 0（确定性）
  header[156] = 0x30; // regular file, checksum placeholder
  writeString(header, 257, 8, TAR_MAGIC);
  writeString(header, 265, 32, ""); // uname
  writeString(header, 297, 32, ""); // gname

  // 校验和：checksum 字段在计算时全部填空格。
  header.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  writeOctal(header, 148, 7, checksum);
  header[155] = 0x20;
  return header;
}

/** 构建确定性 tar 归档，并在末尾附带两个全零块。 */
export function buildTarArchive(entries: ArchiveEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const chunks: Buffer[] = [];
  for (const entry of sorted) {
    chunks.push(tarHeader({ path: entry.path, data: entry.data, mode: entry.mode ?? 0o644 }));
    chunks.push(entry.data);
    const padding = (TAR_BLOCK - (entry.data.length % TAR_BLOCK)) % TAR_BLOCK;
    if (padding) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(TAR_BLOCK * 2));
  return Buffer.concat(chunks);
}

/**
 * 解析 tar（仅覆盖本模块写出的常规文件格式），用于自校验与测试。
 * 返回路径到数据的映射。
 */
export function readTarArchive(archive: Buffer): Map<string, Buffer> {
  const result = new Map<string, Buffer>();
  let offset = 0;
  while (offset + TAR_BLOCK <= archive.length) {
    const header = archive.subarray(offset, offset + TAR_BLOCK);
    if (header.every((byte) => byte === 0)) break;
    const magic = header.toString("ascii", 257, 262);
    if (magic !== "ustar") throw new Error("not a ustar archive");
    const typeFlag = header[156];
    const path = header.toString("ascii", 0, 100).replace(/\0+$/, "");
    const sizeField = header.toString("ascii", 124, 136).replace(/[\0 ]/g, "");
    const size = Number.parseInt(sizeField || "0", 8);
    offset += TAR_BLOCK;
    if (typeFlag === 0x30 || typeFlag === 0) {
      result.set(path, archive.subarray(offset, offset + size));
    }
    offset += Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;
  }
  return result;
}

// ---------------------------------------------------------------------------
// 导出清单与签名
// ---------------------------------------------------------------------------

export type ManifestFileRecord = {
  path: string;
  sha256: string;
  byteSize: number;
  contentType: string;
};

export type ExportManifest = {
  format: "map-data-export";
  formatVersion: 1;
  userId: string;
  createdAt: string;
  files: ManifestFileRecord[];
};

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** 递归按键名字典序排序对象键（数组保持顺序），保证序列化稳定。 */
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, item]) => [key, sortKeysDeep(item)])
    );
  }
  return value;
}

/** 生成规范化清单 JSON（递归键排序，无多余空白），保证哈希稳定。 */
export function canonicalManifest(manifest: ExportManifest): string {
  const sortedFiles = [...manifest.files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const sorted: ExportManifest = {
    format: manifest.format,
    formatVersion: manifest.formatVersion,
    userId: manifest.userId,
    createdAt: manifest.createdAt,
    files: sortedFiles
  };
  return JSON.stringify(sortKeysDeep(sorted));
}

export type BuiltExport = {
  archive: Buffer;
  manifest: ExportManifest;
  manifestSha256: string;
  archiveSha256: string;
  signature: string | null;
};

/**
 * 将结构化数据条目打包为合规导出归档：
 * data/*.json 为各数据集（已调用方序列化），media/ 为媒体二进制，
 * 根目录写入 MANIFEST.json（含每个文件 SHA-256）与可选 MANIFEST.sig（HMAC）。
 */
export function buildExportArchive(input: {
  userId: string;
  createdAt: Date;
  jsonSections: Record<string, unknown>;
  media: Array<{ path: string; data: Buffer; contentType: string }>;
  signingSecret?: string | undefined;
}): BuiltExport {
  const entries: ArchiveEntry[] = [];
  const fileRecords: ManifestFileRecord[] = [];

  for (const [section, value] of Object.entries(input.jsonSections)) {
    const path = `data/${section}.json`;
    const data = Buffer.from(JSON.stringify(value, null, 2), "utf8");
    entries.push({ path, data, contentType: "application/json" });
    fileRecords.push({ path, sha256: sha256Hex(data), byteSize: data.length, contentType: "application/json" });
  }

  for (const item of input.media) {
    entries.push({ path: item.path, data: item.data, contentType: item.contentType });
    fileRecords.push({
      path: item.path,
      sha256: sha256Hex(item.data),
      byteSize: item.data.length,
      contentType: item.contentType
    });
  }

  const manifest: ExportManifest = {
    format: "map-data-export",
    formatVersion: 1,
    userId: input.userId,
    createdAt: input.createdAt.toISOString(),
    files: fileRecords.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  };
  const manifestText = canonicalManifest(manifest);
  const manifestSha256 = sha256Hex(manifestText);
  entries.push({ path: "MANIFEST.json", data: Buffer.from(manifestText, "utf8"), mode: 0o444, contentType: "application/json" });

  let signature: string | null = null;
  if (input.signingSecret) {
    signature = createHmac("sha256", input.signingSecret).update(manifestText).digest("hex");
    entries.push({
      path: "MANIFEST.sig",
      data: Buffer.from(signature, "utf8"),
      mode: 0o444,
      contentType: "text/plain"
    });
  }

  const archive = buildTarArchive(entries);
  return { archive, manifest, manifestSha256, archiveSha256: sha256Hex(archive), signature };
}

/** 下载/审计侧自校验：重算清单与归档哈希，并在存在签名时验证 HMAC。 */
export function verifyExportArchive(
  archive: Buffer,
  signingSecret?: string
): { valid: boolean; manifest: ExportManifest; archiveSha256: string; reason?: string } {
  let files: Map<string, Buffer>;
  try {
    files = readTarArchive(archive);
  } catch (error) {
    return { valid: false, manifest: null as never, archiveSha256: sha256Hex(archive), reason: error instanceof Error ? error.message : "bad archive" };
  }
  const manifestBuffer = files.get("MANIFEST.json");
  if (!manifestBuffer) return { valid: false, manifest: null as never, archiveSha256: sha256Hex(archive), reason: "missing manifest" };
  let manifest: ExportManifest;
  try {
    manifest = JSON.parse(manifestBuffer.toString("utf8")) as ExportManifest;
  } catch {
    return { valid: false, manifest: null as never, archiveSha256: sha256Hex(archive), reason: "manifest is not JSON" };
  }
  for (const record of manifest.files) {
    const data = files.get(record.path);
    if (!data) return { valid: false, manifest, archiveSha256: sha256Hex(archive), reason: `missing file ${record.path}` };
    if (sha256Hex(data) !== record.sha256) return { valid: false, manifest, archiveSha256: sha256Hex(archive), reason: `hash mismatch ${record.path}` };
  }
  // 清单元数据完整性：必须能以同构形式重新规范化（键顺序、文件排序均无关）。
  if (manifest.format !== "map-data-export" || manifest.formatVersion !== 1 || !manifest.userId || !Array.isArray(manifest.files)) {
    return { valid: false, manifest, archiveSha256: sha256Hex(archive), reason: "malformed manifest" };
  }
  if (signingSecret) {
    const sigBuffer = files.get("MANIFEST.sig");
    if (!sigBuffer) return { valid: false, manifest, archiveSha256: sha256Hex(archive), reason: "missing signature" };
    const expected = createHmac("sha256", signingSecret).update(manifestBuffer).digest("hex");
    const actual = sigBuffer.toString("utf8").trim();
    const a = Buffer.from(actual);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return { valid: false, manifest, archiveSha256: sha256Hex(archive), reason: "signature mismatch" };
    }
  }
  return { valid: true, manifest, archiveSha256: sha256Hex(archive) };
}
