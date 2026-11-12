ALTER TABLE approval_drafts DROP CONSTRAINT approval_drafts_kind_check;
ALTER TABLE approval_drafts ADD CONSTRAINT approval_drafts_kind_check
CHECK (kind IN ('send','archive','move','mark'));

CREATE UNIQUE INDEX approvals_one_per_draft ON approvals(draft_id);

CREATE TABLE mail_action_ledger (
    action_id UUID PRIMARY KEY,
    approval_id UUID NOT NULL UNIQUE REFERENCES approvals(approval_id),
    draft_id UUID NOT NULL REFERENCES approval_drafts(draft_id),
    kind TEXT NOT NULL CHECK (kind IN ('send','archive','move','mark')),
    payload_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('ATTEMPTING','CONFIRMED','UNKNOWN','FAILED')),
    attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt > 0),
    provider_object_id TEXT,
    provider_result JSONB,
    error_class TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER mail_action_ledger_no_delete BEFORE DELETE ON mail_action_ledger
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();
