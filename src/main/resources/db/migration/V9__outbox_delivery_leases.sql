ALTER TABLE outbox_event
    ADD COLUMN claim_token BINARY(16) NULL,
    ADD COLUMN lease_until DATETIME(6) NULL,
    ADD COLUMN last_error VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD CONSTRAINT chk_outbox_claim CHECK (
        (claim_token IS NULL AND lease_until IS NULL) OR
        (status = 'PENDING' AND claim_token IS NOT NULL AND lease_until IS NOT NULL)),
    ADD INDEX ix_outbox_pending_age (status, created_at, id);
