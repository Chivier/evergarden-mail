CREATE TABLE runtime_control (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    active_writer TEXT NOT NULL CHECK (active_writer ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'),
    writer_epoch BIGINT NOT NULL CHECK (writer_epoch > 0),
    side_effects_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO runtime_control(singleton,active_writer,writer_epoch,side_effects_enabled)
VALUES (TRUE,'none',1,FALSE);

CREATE TABLE job_runs (
    run_id UUID PRIMARY KEY,
    job_id TEXT NOT NULL,
    scheduled_slot TEXT NOT NULL,
    host TEXT NOT NULL,
    owner_epoch BIGINT NOT NULL,
    input_watermark TEXT,
    idempotency_key TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    outcome TEXT NOT NULL CHECK (outcome IN ('RUNNING','SUCCESS','PARTIAL','FAILED','UNKNOWN','FENCE_REJECTED')),
    duration_ms BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(job_id,scheduled_slot)
);

CREATE TABLE notification_outbox (
    outbox_id UUID PRIMARY KEY,
    source_job TEXT NOT NULL,
    scheduled_slot TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    encrypted_payload BYTEA,
    status TEXT NOT NULL CHECK (status IN ('SHADOW','PENDING','SUCCESS','PARTIAL','FAILED','UNKNOWN','EXPIRED')),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(source_job,scheduled_slot)
);

CREATE TABLE notification_delivery_ledger (
    outbox_id UUID NOT NULL REFERENCES notification_outbox(outbox_id),
    channel TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('SHADOW','PENDING','ATTEMPTING','CONFIRMED','RETRYABLE_FAILED','FAILED','UNKNOWN','EXPIRED')),
    idempotency_key TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    provider_object_id TEXT,
    provider_result JSONB,
    confirmed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(outbox_id,channel)
);

CREATE TABLE approval_drafts (
    draft_id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('send','archive','move')),
    payload_hash TEXT NOT NULL,
    encrypted_payload BYTEA NOT NULL,
    created_by TEXT NOT NULL,
    client_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE approvals (
    approval_id UUID PRIMARY KEY,
    draft_id UUID NOT NULL REFERENCES approval_drafts(draft_id),
    payload_hash TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_client TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    provider_object_id TEXT
);

CREATE TABLE audit_events (
    event_id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    client_id TEXT,
    outcome TEXT NOT NULL,
    metadata JSONB NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION evergarden_forbid_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Evergarden append-only table: DELETE is forbidden';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();
CREATE TRIGGER approval_drafts_no_delete BEFORE DELETE ON approval_drafts
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();
CREATE TRIGGER job_runs_no_delete BEFORE DELETE ON job_runs
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();
CREATE TRIGGER notification_outbox_no_delete BEFORE DELETE ON notification_outbox
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();
CREATE TRIGGER notification_ledger_no_delete BEFORE DELETE ON notification_delivery_ledger
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();

CREATE OR REPLACE FUNCTION evergarden_forbid_audit_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Evergarden audit table is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_audit_update();
