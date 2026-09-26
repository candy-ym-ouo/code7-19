-- 数据合规归档模块：保留策略、法务保留、合规导出、删除请求与删除证明
-- 所有时间均为 timestamptz；“有效法务保留”统一判定为
-- status = 'active' AND (expires_at IS NULL OR expires_at > now())。

CREATE TYPE legal_hold_target_type AS ENUM ('user', 'feature', 'comment', 'media');
CREATE TYPE legal_hold_status AS ENUM ('active', 'released');
CREATE TYPE compliance_export_status AS ENUM ('pending', 'processing', 'ready', 'failed', 'expired');
CREATE TYPE deletion_request_status AS ENUM ('scheduled', 'held', 'processing', 'completed', 'cancelled');

-- 保留策略：每类数据的最短/最长保留天数（0 表示永久保留、不自动清除）。
-- 调度器在 retain_for_days 到期前不得清除对应数据。
CREATE TABLE retention_policies (
  policy_key text PRIMARY KEY,
  display_name text NOT NULL,
  description text NOT NULL DEFAULT '',
  scope text NOT NULL DEFAULT '',
  retain_for_days integer NOT NULL CHECK (retain_for_days >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO retention_policies(policy_key, display_name, scope, retain_for_days, description) VALUES
  ('account_pending_deletion', '账号删除冷静期', 'user', 30, '账号删除申请后最短保留 30 天，期间可撤销；到期前调度器不得清除。'),
  ('export_archive', '合规导出归档', 'compliance_export', 30, '导出包包含个人数据，到期后必须删除对象并保留删除证明。'),
  ('media_original', '原始上传媒体', 'media', 1, '隔离桶原图在处理完成后最短保留 1 天再清除。'),
  ('media_failed', '处理失败媒体', 'media', 7, '失败媒体对象最多保留 7 天供排查。'),
  ('deleted_content', '已删除内容行', 'feature,comment', 90, '软删除内容在物理清除前保留 90 天，法务保留优先。'),
  ('audit_log', '审计日志', 'audit_log', 2555, '审计与合规证据保留 7 年（2555 天），不随账号删除而清除。'),
  ('notification', '通知', 'notification', 180, '站内通知保留 180 天后清除。');

-- 法务保留（Legal Hold / Litigation Hold）。
-- 命中有效保留的对象（以及 user 级别保留下该用户的全部资源）禁止任何清除路径。
CREATE TABLE legal_holds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  hold_reference text NOT NULL UNIQUE,
  target_type legal_hold_target_type NOT NULL,
  target_id uuid NOT NULL,
  reason text NOT NULL,
  status legal_hold_status NOT NULL DEFAULT 'active',
  created_by uuid NOT NULL REFERENCES users(id),
  released_by uuid REFERENCES users(id),
  expires_at timestamptz,
  released_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX legal_holds_target_idx
  ON legal_holds(target_type, target_id, status)
  WHERE status = 'active';
CREATE INDEX legal_holds_status_idx ON legal_holds(status, created_at DESC);

-- 合规导出（GDPR 式可携带包）。异步生成，对象存放在私有导出桶，短期签名 URL 下载。
CREATE TABLE compliance_exports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  requested_by uuid NOT NULL REFERENCES users(id),
  status compliance_export_status NOT NULL DEFAULT 'pending',
  object_bucket text,
  object_key text,
  byte_size bigint,
  file_count integer,
  sha256 text,
  manifest_sha256 text,
  signature text,
  failure_code text,
  last_error text,
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX compliance_exports_user_idx ON compliance_exports(user_id, created_at DESC);
CREATE INDEX compliance_exports_queue_idx ON compliance_exports(status, created_at)
  WHERE status IN ('pending', 'processing');

-- 删除请求：统一编排“到期清除”。purge_after 之前任何作业不得物理清除。
CREATE TABLE deletion_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  requested_by uuid NOT NULL REFERENCES users(id),
  reason_code text NOT NULL DEFAULT 'user_request',
  status deletion_request_status NOT NULL DEFAULT 'scheduled',
  purge_after timestamptz NOT NULL,
  export_id uuid REFERENCES compliance_exports(id),
  held_at timestamptz,
  completed_at timestamptz,
  cancelled_at timestamptz,
  cancel_reason text,
  before_state jsonb NOT NULL DEFAULT '{}'::jsonb,
  purge_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX deletion_requests_one_open_idx
  ON deletion_requests(user_id)
  WHERE status IN ('scheduled', 'held', 'processing');
CREATE INDEX deletion_requests_due_idx ON deletion_requests(status, purge_after)
  WHERE status = 'scheduled';

-- 删除证明：每次物理清除都逐项记录“期望删除 → 已验证不存在”。
-- request_id 与 export_id 二选一（账号清除证明 / 导出包到期删除证明）。
CREATE TABLE deletion_verifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id uuid REFERENCES deletion_requests(id) ON DELETE CASCADE,
  export_id uuid REFERENCES compliance_exports(id) ON DELETE CASCADE,
  object_kind text NOT NULL CHECK (object_kind IN ('s3_object', 'database_record', 'export_archive')),
  location text NOT NULL,
  bucket text,
  object_key text,
  expected_sha256 text,
  verified boolean NOT NULL,
  check_method text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  checked_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT deletion_verifications_subject_check
    CHECK (num_nonnulls(request_id, export_id) = 1)
);
CREATE INDEX deletion_verifications_request_idx ON deletion_verifications(request_id, checked_at);
CREATE INDEX deletion_verifications_export_idx ON deletion_verifications(export_id, checked_at);
