-- Preserve historical null envelopes and existing login facts; version explicit logout facts.
ALTER TABLE security_audit_event
    DROP CHECK chk_login_audit_envelope,
    ADD CONSTRAINT chk_security_audit_envelope CHECK (
        envelope IS NULL OR (
            event_type IN ('LOGIN_SUCCEEDED','LOGIN_FAILED','SESSION_REVOKED')
            AND JSON_CONTAINS_PATH(envelope,'all','$.eventId','$.schemaVersion','$.sourceService','$.eventType') = 1
            AND JSON_EXTRACT(envelope,'$.schemaVersion') = 1
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.eventId')) = LOWER(BIN_TO_UUID(id))
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.sourceService')) = 'auth-service'
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.eventType')) =
                CASE event_type
                    WHEN 'LOGIN_SUCCEEDED' THEN 'auth.login.succeeded'
                    WHEN 'LOGIN_FAILED' THEN 'auth.login.failed'
                    ELSE 'auth.logout.completed'
                END
            AND (event_type <> 'SESSION_REVOKED' OR (
                JSON_CONTAINS_PATH(envelope,'all','$.actorId','$.actorType','$.targetId',
                    '$.targetType','$.sessionId','$.outcome','$.reasonCode') = 1
                AND account_id IS NOT NULL AND session_id IS NOT NULL
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.actorId')) = LOWER(BIN_TO_UUID(account_id))
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.sessionId')) = LOWER(BIN_TO_UUID(session_id))
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetId')) = LOWER(BIN_TO_UUID(session_id))
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.actorType')) = 'ACCOUNT'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetType')) = 'SESSION'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.outcome')) = 'SUCCESS'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.reasonCode')) = 'LOGOUT'
            ))
        )
    );
