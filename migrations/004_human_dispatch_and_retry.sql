-- Human approvals run on the server dispatcher; policy approvals run in their client.
ALTER TABLE approvals ADD COLUMN approval_source TEXT NOT NULL DEFAULT 'policy'
    CHECK (approval_source IN ('human','policy'));
UPDATE approvals a SET approval_source='human'
FROM approval_drafts d
WHERE d.draft_id=a.draft_id AND (a.approved_client IN ('approval-ui','admin-cli') OR d.kind='trash');
-- A provider failure before any mailbox command keeps the approval retryable.
ALTER TABLE mail_action_ledger DROP CONSTRAINT mail_action_ledger_state_check;
ALTER TABLE mail_action_ledger ADD CONSTRAINT mail_action_ledger_state_check
CHECK (state IN ('ATTEMPTING','RETRYABLE','CONFIRMED','UNKNOWN','FAILED'));
CREATE INDEX approvals_human_expiry ON approvals(expires_at) WHERE approval_source='human';
CREATE INDEX mail_action_ledger_open_states ON mail_action_ledger(state, updated_at)
WHERE state IN ('ATTEMPTING','RETRYABLE','UNKNOWN');
CREATE TABLE approval_dispatcher_status (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    host TEXT NOT NULL,
    kinds TEXT[] NOT NULL,
    last_scan_at TIMESTAMPTZ NOT NULL,
    last_error_class TEXT,
    last_item_error_class TEXT,
    last_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
