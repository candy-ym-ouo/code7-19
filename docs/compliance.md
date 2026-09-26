# 数据合规归档

合规模块统一编排三类数据主体操作：**导出**、**法务保留**、**删除**。所有操作都建模为 `compliance_cases` 案件，由 Worker 的 `processComplianceCases()` 在每个维护周期推进，全部状态转移写入防篡改审计链。

## 核心保证

1. **保留期内不得提前清除**——两道数据库级防线，不依赖应用代码自觉：
   - `compliance_cases` 触发器：删除案件在 `retention_until` 届满前、或主体存在活跃法务保留时，禁止置为 `completed`。
   - `users` 触发器：存在活跃法务保留的账号禁止被匿名化为 `deleted`。
   - 应用层在创建删除案件、执行清除前也用同一判定口径（`gateDeletion`）先行拦截。
2. **到期后可证明完整删除**——删除执行完毕生成 `deletion_certificates`：各资源清除计数（`scope`）、已删除对象键清单及其聚合哈希、以及锚定审计链的事件哈希。证书与审计事件均为 append-only（触发器禁止 UPDATE/DELETE）。
3. **审计证据可独立验证**——`compliance_events` 是哈希链：`entry_hash = sha256([prev_hash, case_id, actor_id, action, subject, metadata, occurred_at])`，元数据以 canonical JSON 文本存储。`GET /compliance/audit/verify` 重放全链；任何篡改都会在第一个被改动的 `seq` 处断裂。

## 案件状态机

| 类型 | 流转 |
|---|---|
| `export` | `pending` → `processing` → `completed`（归档生成）→ 到期清除归档（`payload.purgedAt`） |
| `legal_hold` | `active`（保留生效中）→ `completed`（手动解除或 `release_after` 到期自动解除） |
| `deletion` | `waiting_retention` → `processing` → `completed`；保留冲突时 `blocked`，解除后回到 `waiting_retention`；多次失败转 `failed` |

同一主体同时只允许一个未完结的删除案件（部分唯一索引）。

## 保留策略

- 账号自助删除（`POST /me/delete`）与管理员删除（`POST /compliance/deletions`）默认保留 30 天宽限期，到期才执行清除。
- 法务保留可设 `release_after`，到期自动解除；未设则需管理员手动解除。解除后被阻塞的删除案件自动恢复排队。
- 导出归档含个人信息，生成后仅在私有桶保留 7 天供下载，随后由 Worker 清除并记录 `export.purged` 事件。

## 删除执行范围

执行清除时（`apps/worker/src/compliance-job.ts`）：

- 对象存储：删除主体全部媒体对象（隔离原图、处理图、缩略图、公开派生图），键清单写入证书。
- 数据库（单事务）：删除会话、认证令牌、通知、时效确认；评论、地图要素、媒体记录软删除；账号匿名化（邮箱替换为 `deleted+<id>@invalid.local`、昵称重置、口令置为不可用）。
- 合规与审核记录（`reports`、`moderation_actions`、`audit_logs`、`compliance_events`）按审计合法利益保留，但关联的账号行已匿名化，不再可识别个人。证书的 `scope.retainedForAudit` 字段明示该范围。

## API 一览

均需管理员角色，除下载端点允许数据主体本人访问。

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/compliance/cases` | 案件列表（按类型/状态/主体过滤） |
| `POST` | `/compliance/exports` | 创建导出案件 |
| `GET` | `/compliance/exports/:id/download` | 获取归档短期签名下载地址（10 分钟） |
| `POST` | `/compliance/legal-holds` | 建立法务保留 |
| `POST` | `/compliance/legal-holds/:id/release` | 解除法务保留 |
| `POST` | `/compliance/deletions` | 创建删除案件（可指定保留天数） |
| `GET` | `/compliance/deletions/:id/certificate` | 获取删除证明 |
| `GET` | `/compliance/audit` | 审计链事件查询 |
| `GET` | `/compliance/audit/verify` | 重放验证审计链完整性 |

## 验证

- 单元测试：`packages/shared/src/compliance.test.ts`（canonical JSON、哈希链、篡改检测、删除闸门）。
- 迁移断言：`packages/db/src/migrations.test.ts`。
- 数据库不变量（在真实 PostgreSQL 上验证过）：保留期内完成删除、法务保留期间匿名化、重复开放删除案件、篡改审计事件/证书均被触发器或唯一索引拒绝；解除保留后删除可正常完成。
