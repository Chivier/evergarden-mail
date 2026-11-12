-- Writer identities are free host identifiers instead of a closed list of
-- names. Existing rows keep their value; the new constraint only bounds the
-- format and length (the same pattern EVERGARDEN_HOST_ID accepts), and the
-- reserved value 'none' still means that no host may write.
ALTER TABLE runtime_control DROP CONSTRAINT IF EXISTS runtime_control_active_writer_check;
ALTER TABLE runtime_control ADD CONSTRAINT runtime_control_active_writer_check
    CHECK (active_writer ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$');
