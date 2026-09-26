# 数据合规归档模块

统一编排三类数据生命周期操作：**数据导出（可携带归档）**、**法务保留（Legal Hold）** 与**到期删除**。
模块保证两条不变量：

1. **保留期内不得提前清除**——任何删除路径（用户自助、管理员、维护任务）都由数据库状态和调度器双重约束。
2. **到期后可证明完整删除并保留审计证据**——每个对象/记录删除后立即复验“不存在”，逐项写入 `deletion_verifications`，并生成带证据摘要的删除证明。

## 数据模型（迁移 `0003_compliance.sql`）

| 表 | 作用 |
| --- | --- |
| `retention_policies` | 各数据类别的最短保留天数（种子：账号冷静期 30 天、导出 30 天、原图 1 天、失败媒体 7 天、已删除内容 90 天、审计日志 2555 天、通知 180 天）。管理员可通过 API 调整。 |
| `legal_holds` | 法务保留令，目标为 `user/feature/comment/media`。`active` 且未到期的保留阻断对应资源的一切清除；挂在 `user` 上时覆盖其全部资源。释放需记录操作人与审计。 |
| `compliance_exports` | 异步导出任务及归档对象元数据（桶、键、字节数、文件数、归档 SHA-256、清单 SHA-256、HMAC 签名、到期时间）。 |
| `deletion_requests` | 删除请求与统一编排状态机：`scheduled → held ⇄ scheduled → processing → completed`（或 `cancelled`）。`purge_after` 为最早可清除时刻。 |
| `deletion_verifications` | 删除证明明细：对象/记录位置、删除后期望哈希、复验方法（`s3_head_object_after_delete` / `sql_residual_count_after_purge`）、复验结果与时间。每一行要么挂 `request_id`，要么挂 `export_id`。 |

另有既有 `audit_logs` 承载全部合规动作（导出申请、保留创建/释放、删除申请/撤销/挂起/完成、导出到期删除）。审计日志本身按 7 年策略保留，不随账号删除。

## 编排流程

### 1. 导出

1. `POST /api/v1/me/compliance/exports` 创建任务（同一用户仅允许一个进行中任务），入 BullMQ `compliance` 队列。
2. Worker `processExportJob` 原子认领（`pending/failed → processing`），采集资料、投稿（含修订）、评论、时效确认、举报、媒体索引。
3. 仅打包**服务端隐私处理后的 WebP 派生图**；原图永不离开隔离桶。超过 `EXPORT_MEDIA_MAX_BYTES` 时记录 `media_warnings`。
4. 生成确定性 tar（USTAR）：根目录 `MANIFEST.json` 列出每个文件的 SHA-256；配置 `EXPORT_SIGNING_SECRET` 时附 `MANIFEST.sig`（HMAC-SHA256）。
5. 上传私有 `map-exports` 桶（默认匿名不可读），回写哈希，站内通知 + 邮件。
6. 用户通过 `POST .../exports/:id/download` 获取 10 分钟签名 URL。
7. 到期（默认 30 天）由 `sweepExpiredExports` 删除对象 → HeadObject 复验不存在 → 写证明 → 状态置 `expired`。保留期内的对象不存在任何删除路径。

确定性保证：归档条目按路径排序、固定 uid/gid/mtime，因此同一份数据多次构建字节一致，归档 SHA-256 可作为内容完整性证据。校验工具见 `@map/shared/compliance` 的 `verifyExportArchive`。

### 2. 法务保留

- 管理员 `POST /api/v1/admin/legal-holds`（需目标存在、引用编号唯一、可设过期时间）。
- 用户级保留覆盖其名下 feature/comment/media；资源级保留直接生效。
- 阻断点（均返回 `409 LEGAL_HOLD_ACTIVE` 并记审计）：
  - API：删除 feature / comment / media、创建账号删除请求；
  - Worker：原图/失败/无引用媒体清理、已删除媒体对象清扫、账号到期清除。
- 到期删除时仍命中保留：请求转 `held`，不删除任何数据；保留释放后 `reevaluateHeldDeletions` 转回 `scheduled`，**清除时刻仍以原 `purge_after` 为准**——保留只延后、绝不缩短保留期。

### 3. 账号删除

1. `POST /api/v1/me/compliance/deletion-requests`：30 天冷静期（`ACCOUNT_DELETION_GRACE_DAYS`），记录删除前计数（`before_state`）、吊销会话。已命中有效保留时拒绝申请。
2. 冷静期内 `POST .../:id/cancel` 可撤销，账号恢复 `active`。
3. 到期后 `processDueDeletionRequests` 执行：
   - 原子认领（`scheduled → processing`），重查法务保留；
   - 删除隔离桶/公开桶全部媒体对象，逐个 HeadObject 复验；
   - 删除该用户全部导出归档（账号清除优先于导出自身保留期），逐项证明；
   - 数据库终态：媒体行清空对象键并标记 `deleted`、评论/投稿 `deleted`、用户匿名化（邮箱改写、密码哈希失效、状态 `deleted`）；
   - SQL 复验活动残留为 0；全部证据写入后才置 `completed`，并生成 `evidenceDigest`（所有对象证据 + 残留结果的 SHA-256）。
4. 任一对象无法确认删除时**绝不宣告完成**：状态回退 `scheduled` 下一 tick 幂等重试；`processing` 超 10 分钟由 `recoverStuckDeletions` 兜底。
5. 证明查询：用户 `GET /me/compliance/deletion-requests/:id/certificate`，管理员 `GET /admin/deletion-requests/:id/certificate`。

## HTTP 接口

用户侧（均需登录）：

- `POST/GET /me/compliance/exports`、`GET /me/compliance/exports/:id`、`POST /me/compliance/exports/:id/download`
- `POST/GET /me/compliance/deletion-requests`、`POST /me/compliance/deletion-requests/:id/cancel`、`GET /me/compliance/deletion-requests/:id/certificate`

管理员侧（`admin`）：

- `GET /admin/retention-policies`、`PATCH /admin/retention-policies/:key`
- `POST/GET /admin/legal-holds`、`POST /admin/legal-holds/:id/release`
- `GET /admin/deletion-requests`、`GET /admin/deletion-requests/:id/certificate`
- `GET /admin/exports`、`GET /admin/exports/:id/verifications`

## 配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `S3_EXPORT_BUCKET` | `map-exports` | 导出归档私有桶 |
| `EXPORT_RETENTION_DAYS` | `30` | 导出归档保留天数 |
| `EXPORT_SIGNING_SECRET` | 空 | 设置后对 MANIFEST 生成 HMAC-SHA256 签名（生产建议设置，≥16 字符） |
| `ACCOUNT_DELETION_GRACE_DAYS` | `30` | 账号删除冷静期 |
| `EXPORT_MEDIA_MAX_BYTES` | `83886080` | 单个导出包含媒体字节上限，超出部分只留索引 |

MinIO 初始化脚本会创建私有导出桶并配置 30 天生命周期规则作为对象层兜底；**应用侧调度 + 删除证明仍是合规事实来源**（生命周期删除不会生成证明，因此过期判定只信任应用时间）。

## 前端

设置页（`/me/settings`）提供：申请导出、导出列表与短期签名下载、删除申请/撤销/状态展示；删除完成后可在 `/compliance/deletion/:id` 查看逐项删除证明。

## 验证

```bash
pnpm --filter @map/shared test     # tar/manifest/签名、保留期窗口纯函数
pnpm --filter @map/worker test     # 删除编排决策（保留期/法务保留）
pnpm --filter @map/db test         # 迁移结构断言
```

生产部署注意：

- 对象存储版本控制 / 备份的过期策略必须与本表一致，否则“删除证明”只覆盖在线对象；
- 数据库软删除行（`deleted_at`）按 `deleted_content` 策略另行物理清理，清理同样必须检查法务保留；
- `EXPORT_SIGNING_SECRET` 应进入密钥管理，签名验证方可作为“归档由本系统生成且未篡改”的证据。
