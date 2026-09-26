-- 数据合规归档：统一编排导出、法务保留与删除。
-- 两道数据库级防线保证“保留期内不得提前清除”：
--   1. compliance_cases 触发器：删除案件在 retention_until 届满前、或主体存在活跃法务保留时，禁止置为 completed。
--   2. users 触发器：存在活跃法务保留的账号禁止被匿名化为 deleted。
-- compliance_events 与 deletion_certificates 为 append-only，审计链可独立重放验证。

CREATE TYPE compliance_case_type AS ENUM ('export', 'legal_hold', 'deletion');
CREATE TYPE compliance_case_status AS ENUM (
  'pending', 'active', 'waiting_retention', 'processing', 'blocked', 'completed', 'failed', 'cancelled'
);

CREATE TABLE compliance_cases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_type compliance_case_type NOT NULL,
  subject_user_id uuid NOT NULL REFERENCES users(id),
  status compliance_case_status NOT NULL DEFAULT 'pending',
  reason text NOT NULL,
  requested_by uuid REFERENCES users(id),
  retention_until timestamptz,
  legal_hold_id uuid,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  attempts integer NOT NULL DEFAULT 0,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX compliance_cases_subject_idx ON compliance_cases(subject_user_id, created_at DESC);
CREATE INDEX compliance_cases_queue_idx ON compliance_cases(case_type, status, retention_until)
  WHERE status IN ('pending', 'waiting_retention', 'blocked', 'failed');
-- 同一主体同时只允许一个未完结的删除案件，防止重复编排。
CREATE UNIQUE INDEX compliance_one_open_deletion_idx ON compliance_cases(subject_user_id)
  WHERE case_type = 'deletion' AND status IN ('pending', 'waiting_retention', 'processing', 'blocked', 'failed');

CREATE TABLE legal_holds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  case_id uuid NOT NULL REFERENCES compliance_cases(id),
  reason text NOT NULL,
  placed_by uuid REFERENCES users(id),
  release_after timestamptz,
  released_at timestamptz,
  released_by uuid REFERENCES users(id),
  release_reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX legal_holds_active_idx ON legal_holds(user_id) WHERE released_at IS NULL;

ALTER TABLE compliance_cases
  ADD CONSTRAINT compliance_cases_legal_hold_fk
  FOREIGN KEY (legal_hold_id) REFERENCES legal_holds(id);

CREATE TABLE deletion_certificates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL UNIQUE REFERENCES compliance_cases(id),
  user_id uuid NOT NULL REFERENCES users(id),
  scope jsonb NOT NULL,
  object_keys text[] NOT NULL DEFAULT '{}',
  object_keys_hash text NOT NULL,
  entry_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX deletion_certificates_user_idx ON deletion_certificates(user_id, created_at DESC);

-- metadata 存 canonical JSON 文本而非 jsonb，保证链上哈希可被原样重放。
CREATE TABLE compliance_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  seq bigint GENERATED ALWAYS AS IDENTITY,
  case_id uuid REFERENCES compliance_cases(id),
  actor_id uuid,
  action text NOT NULL,
  subject_user_id uuid,
  metadata text NOT NULL DEFAULT '{}',
  prev_hash text NOT NULL,
  entry_hash text NOT NULL,
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX compliance_events_seq_idx ON compliance_events(seq);
CREATE INDEX compliance_events_case_idx ON compliance_events(case_id, seq);
CREATE INDEX compliance_events_subject_idx ON compliance_events(subject_user_id, seq);

CREATE FUNCTION refuse_compliance_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'compliance evidence is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER compliance_events_append_only
  BEFORE UPDATE OR DELETE ON compliance_events
  FOR EACH ROW EXECUTE FUNCTION refuse_compliance_mutation();

CREATE TRIGGER deletion_certificates_append_only
  BEFORE UPDATE OR DELETE ON deletion_certificates
  FOR EACH ROW EXECUTE FUNCTION refuse_compliance_mutation();

CREATE FUNCTION enforce_deletion_retention() RETURNS trigger AS $$
BEGIN
  IF NEW.case_type = 'deletion' AND NEW.status = 'completed' AND OLD.status IS DISTINCT FROM 'completed' THEN
    IF NEW.retention_until IS NOT NULL AND NEW.retention_until > now() THEN
      RAISE EXCEPTION 'deletion case % cannot complete before retention expires', NEW.id;
    END IF;
    IF EXISTS (SELECT 1 FROM legal_holds h WHERE h.user_id = NEW.subject_user_id AND h.released_at IS NULL) THEN
      RAISE EXCEPTION 'deletion case % is blocked by an active legal hold', NEW.id;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER compliance_cases_enforce_retention
  BEFORE UPDATE ON compliance_cases
  FOR EACH ROW EXECUTE FUNCTION enforce_deletion_retention();

CREATE FUNCTION enforce_legal_hold_on_user_delete() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'deleted' AND OLD.status IS DISTINCT FROM 'deleted'
     AND EXISTS (SELECT 1 FROM legal_holds h WHERE h.user_id = NEW.id AND h.released_at IS NULL) THEN
    RAISE EXCEPTION 'user % is under an active legal hold and cannot be deleted', NEW.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_enforce_legal_hold
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION enforce_legal_hold_on_user_delete();
