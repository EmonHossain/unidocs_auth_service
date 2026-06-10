-- Historical audit rows remain valid without an envelope. New login audits use schema v1.
ALTER TABLE security_audit_event
    ADD COLUMN envelope JSON NULL,
    ADD CONSTRAINT chk_login_audit_envelope CHECK (
        envelope IS NULL OR (
            event_type IN ('LOGIN_SUCCEEDED','LOGIN_FAILED')
            AND JSON_CONTAINS_PATH(envelope,'all','$.eventId','$.schemaVersion','$.sourceService','$.eventType') = 1
            AND JSON_EXTRACT(envelope,'$.schemaVersion') = 1
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.eventId')) = LOWER(BIN_TO_UUID(id))
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.sourceService')) = 'auth-service'
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.eventType')) =
                CASE event_type WHEN 'LOGIN_SUCCEEDED' THEN 'auth.login.succeeded' ELSE 'auth.login.failed' END
        )
    );