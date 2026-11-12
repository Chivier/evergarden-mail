-- A human approval is a durable work order: it never expires (expires_at NULL)
-- and can only be executed or revoked. Policy approvals keep their expiry.
ALTER TABLE approvals ALTER COLUMN expires_at DROP NOT NULL;
ALTER TABLE approvals ADD COLUMN revoked_at TIMESTAMPTZ;

-- Human approvals that lapsed unclaimed were dead under the expiring model.
-- Record them as revoked instead of silently resurrecting the old backlog.
UPDATE approvals SET revoked_at=now()
WHERE approval_source='human' AND consumed_at IS NULL AND expires_at<=now();

-- RETRYABLE rows whose human approval lapsed could only continue through the
-- removed re-approval flow; close them out as final failures.
UPDATE mail_action_ledger l
SET state='FAILED',error_class='ApprovalLapsedBeforeRetry',updated_at=now()
FROM approvals a
WHERE a.approval_id=l.approval_id AND l.state='RETRYABLE'
  AND a.approval_source='human' AND a.expires_at<=now();

-- Waiting (never claimed) and still-retryable human approvals become durable.
-- Finished rows keep their historical expiry for the audit trail.
UPDATE approvals a SET expires_at=NULL
WHERE a.approval_source='human' AND a.revoked_at IS NULL
  AND (
    (a.consumed_at IS NULL
     AND NOT EXISTS (SELECT 1 FROM mail_action_ledger l WHERE l.approval_id=a.approval_id))
    OR EXISTS (SELECT 1 FROM mail_action_ledger l
               WHERE l.approval_id=a.approval_id AND l.state='RETRYABLE')
  );

-- The dispatcher orders by approval time now, not by expiry.
DROP INDEX IF EXISTS approvals_human_expiry;
CREATE INDEX approvals_human_ready ON approvals(approved_at)
WHERE approval_source='human' AND revoked_at IS NULL;
