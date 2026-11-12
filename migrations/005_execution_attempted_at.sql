-- When the current provider attempt started. created_at keeps the first
-- attempt; a retry or human renewal starts a new attempt, and the unknown
-- outcome give-up window is measured from it.
ALTER TABLE mail_action_ledger ADD COLUMN attempted_at TIMESTAMPTZ NOT NULL DEFAULT now();
-- Retried rows do not record when the retry began; updated_at is the latest
-- possible start, which only delays giving up.
UPDATE mail_action_ledger SET attempted_at=CASE WHEN attempt>1 THEN updated_at ELSE created_at END;
