ALTER TABLE security_audit_event DROP CHECK chk_security_audit_type,
 ADD CONSTRAINT chk_security_audit_type CHECK(event_type IN(
 'REGISTRATION_COMPLETED','ACCOUNT_LINKED','LOGIN_SUCCEEDED','LOGIN_FAILED','SESSION_REVOKED','REFRESH_REPLAY','REFRESH_FAILED','ALL_SESSIONS_REVOKED',
 'ACCOUNT_UNLOCKED','ACCOUNT_UNLOCK_FAILED','ACCOUNT_UNLINKED','PIN_CHANGED','PREFERENCE_CHANGED',
 'ORGANIZATION_CREATED','ORGANIZATION_MEMBERSHIP_ACTIVATED','ORGANIZATION_INVITATION_CREATED',
 'ORGANIZATION_INVITATION_SUPERSEDED','ORGANIZATION_INVITATION_FAILED','ORGANIZATION_ACCOUNT_PROVISIONED','GROUP_CREATED',
 'ACCOUNT_REMOVAL_REQUESTED','ACCOUNT_REMOVAL_REJECTED','ACCOUNT_SOFT_DELETED','ACCOUNT_RESTORED','ACCOUNT_PURGED',
 'ORGANIZATION_MEMBER_REMOVED','ORGANIZATION_MEMBER_BLACKLISTED','ORGANIZATION_MEMBER_RESTORED','ACCOUNT_RECOVERY_FAILED',
 'GROUP_MEMBER_ASSIGNED','GROUP_MEMBER_REVOKED','GROUP_JOIN_REQUESTED','GROUP_JOIN_APPROVED','GROUP_JOIN_REJECTED','GROUP_JOIN_CANCELLED',
 'GROUP_RULE_CHANGED','GROUP_MEMBER_ADMIN_CHANGED','ACADEMIC_SEMESTER_CREATED','COURSE_ENROLLMENT_REPLACED',
 'GROUP_INVITATION_CREATED','GROUP_INVITATION_ACCEPTED','GROUP_INVITATION_REVOKED','EMPLOYEE_PROVISIONED','EMPLOYEE_ACTIVATED','EMPLOYEE_CREDENTIAL_RESET','STUDENT_ADMISSION_CREATED','STUDENT_ADMISSION_VERIFIED','STUDENT_ADMISSION_APPROVED','STUDENT_ADMISSION_REJECTED','INSTITUTE_CURATOR_CHANGED','INSTITUTE_DOMAIN_CHANGED','PASSWORD_RECOVERY_REQUESTED','PASSWORD_RESET_COMPLETED','EMPLOYEE_PASSWORD_RECOVERY_REQUESTED','EMPLOYEE_RECOVERY_PIN_ISSUED','EMPLOYEE_PASSWORD_RESET_COMPLETED'));

-- Preserve previous audit facts and version the all-device logout action.
ALTER TABLE security_audit_event
    DROP CHECK chk_security_audit_envelope,
    ADD CONSTRAINT chk_security_audit_envelope CHECK (
        envelope IS NULL OR (
            event_type IN ('LOGIN_SUCCEEDED','LOGIN_FAILED','SESSION_REVOKED','REFRESH_REPLAY','ALL_SESSIONS_REVOKED','REFRESH_FAILED')
            AND JSON_CONTAINS_PATH(envelope,'all','$.eventId','$.schemaVersion','$.sourceService','$.eventType') = 1
            AND JSON_EXTRACT(envelope,'$.schemaVersion') = 1
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.eventId')) = LOWER(BIN_TO_UUID(id))
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.sourceService')) = 'auth-service'
            AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.eventType')) =
                CASE event_type
                    WHEN 'LOGIN_SUCCEEDED' THEN 'auth.login.succeeded'
                    WHEN 'LOGIN_FAILED' THEN 'auth.login.failed'
                    WHEN 'SESSION_REVOKED' THEN 'auth.logout.completed'
                    WHEN 'ALL_SESSIONS_REVOKED' THEN 'auth.logout.completed'
                    ELSE 'auth.token.refresh.failed'
                END
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

