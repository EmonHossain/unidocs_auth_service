-- Version email password-reset completion while preserving prior and legacy facts.
ALTER TABLE security_audit_event
    DROP CHECK chk_security_audit_envelope,
    ADD CONSTRAINT chk_security_audit_envelope CHECK (
        envelope IS NULL OR (
            event_type IN ('LOGIN_SUCCEEDED','LOGIN_FAILED','SESSION_REVOKED','REFRESH_REPLAY','ALL_SESSIONS_REVOKED','REFRESH_FAILED','PASSWORD_RESET_COMPLETED')
            AND JSON_CONTAINS_PATH(envelope,'all','$.eventId','$.schemaVersion','$.sourceService','$.eventType') = 1
            AND JSON_EXTRACT(envelope,'$.schemaVersion') = 1
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.eventId')) = LOWER(BIN_TO_UUID(id))
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.sourceService')) = 'auth-service'
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.eventType')) =
                CASE event_type
                    WHEN 'PASSWORD_RESET_COMPLETED' THEN 'auth.password.reset.completed'
                    WHEN 'LOGIN_SUCCEEDED' THEN 'auth.login.succeeded'
                    WHEN 'LOGIN_FAILED' THEN 'auth.login.failed'
                    WHEN 'SESSION_REVOKED' THEN 'auth.logout.completed'
                    WHEN 'ALL_SESSIONS_REVOKED' THEN 'auth.logout.completed'
                    ELSE 'auth.token.refresh.failed'
                END
            AND (event_type <> 'PASSWORD_RESET_COMPLETED' OR COALESCE((
                JSON_CONTAINS_PATH(envelope,'all','$.actorId','$.actorType','$.targetId',
                    '$.targetType','$.sessionId','$.outcome','$.reasonCode') = 1
                AND user_id IS NOT NULL AND account_id IS NOT NULL AND session_id IS NULL
                AND JSON_TYPE(JSON_EXTRACT(envelope,'$.actorId')) = 'NULL'
                AND JSON_TYPE(JSON_EXTRACT(envelope,'$.sessionId')) = 'NULL'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.actorType')) = 'UNKNOWN'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetType')) = 'ACCOUNT'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetId')) = LOWER(BIN_TO_UUID(account_id))
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.outcome')) = 'SUCCESS'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.reasonCode')) = 'EMAIL_RECOVERY_VERIFIED'
            ), FALSE))
            AND (event_type <> 'REFRESH_FAILED' OR COALESCE((
                user_id IS NULL AND account_id IS NULL AND session_id IS NULL
                AND JSON_CONTAINS_PATH(envelope,'all','$.actorId','$.actorType','$.targetId','$.targetType','$.sessionId','$.outcome','$.reasonCode') = 1
                AND JSON_TYPE(JSON_EXTRACT(envelope,'$.actorId')) = 'NULL'
                AND JSON_TYPE(JSON_EXTRACT(envelope,'$.targetId')) = 'NULL'
                AND JSON_TYPE(JSON_EXTRACT(envelope,'$.sessionId')) = 'NULL'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.actorType')) = 'UNKNOWN'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetType')) = 'AUTHENTICATION'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.outcome')) = 'FAILURE'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.reasonCode')) = 'INVALID_REFRESH'
            ), FALSE))
            AND (event_type <> 'ALL_SESSIONS_REVOKED' OR COALESCE((
                JSON_CONTAINS_PATH(envelope,'all','$.actorId','$.actorType','$.targetId',
                    '$.targetType','$.sessionId','$.outcome','$.reasonCode','$.accountGroupId') = 1
                AND account_id IS NOT NULL AND session_id IS NOT NULL
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.actorId')) = LOWER(BIN_TO_UUID(account_id))
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.sessionId')) = LOWER(BIN_TO_UUID(session_id))
                AND JSON_TYPE(JSON_EXTRACT(envelope,'$.accountGroupId')) = 'STRING'
                AND REGEXP_LIKE(JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.accountGroupId')),
                    '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$','c')
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetId')) = JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.accountGroupId'))
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.actorType')) = 'ACCOUNT'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetType')) = 'ACCOUNT_GROUP'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.outcome')) = 'SUCCESS'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.reasonCode')) = 'LOGOUT_ALL'
            ), FALSE))
            AND (event_type <> 'REFRESH_REPLAY' OR COALESCE((
                JSON_CONTAINS_PATH(envelope,'all','$.actorId','$.actorType','$.targetId',
                    '$.targetType','$.sessionId','$.outcome','$.reasonCode') = 1
                AND session_id IS NOT NULL
                AND JSON_TYPE(JSON_EXTRACT(envelope,'$.actorId')) = 'NULL'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.actorType')) = 'UNKNOWN'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.sessionId')) = LOWER(BIN_TO_UUID(session_id))
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetId')) = LOWER(BIN_TO_UUID(session_id))
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.targetType')) = 'SESSION'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.outcome')) = 'FAILURE'
                AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.reasonCode')) = 'REFRESH_REPLAY'
            ), FALSE))
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


