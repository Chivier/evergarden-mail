-- Reversible deletion is modeled as a separately approved native IMAP MOVE
-- into the account's configured Trash folder. No EXPUNGE primitive exists.
ALTER TABLE approval_drafts DROP CONSTRAINT approval_drafts_kind_check;
ALTER TABLE approval_drafts ADD CONSTRAINT approval_drafts_kind_check
CHECK (kind IN ('send','archive','move','mark','trash'));

ALTER TABLE mail_action_ledger DROP CONSTRAINT mail_action_ledger_kind_check;
ALTER TABLE mail_action_ledger ADD CONSTRAINT mail_action_ledger_kind_check
CHECK (kind IN ('send','archive','move','mark','trash'));
