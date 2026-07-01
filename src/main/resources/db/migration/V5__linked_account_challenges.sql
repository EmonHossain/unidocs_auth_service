CREATE TABLE account_credential (
    id BINARY(16) NOT NULL PRIMARY KEY,
    account_id BINARY(16) NOT NULL,
    type VARCHAR(32) NOT NULL,
    credential_hash VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL,
    version BIGINT NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_credential_account FOREIGN KEY (account_id) REFERENCES user_account(id),
    CONSTRAINT uq_account_credential UNIQUE (account_id, type),
    CONSTRAINT chk_account_credential_type CHECK (type = 'PIN'),
    CONSTRAINT chk_account_credential_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_account_credential_version CHECK (version >= 1),
    CONSTRAINT chk_account_credential_attempts CHECK (failed_attempts BETWEEN 0 AND 5)
);

CREATE TABLE session_grant_policy (
    id BINARY(16) NOT NULL PRIMARY KEY,
    scope_type VARCHAR(32) NOT NULL UNIQUE,
    scope_id BINARY(16) NULL,
    idle_timeout_seconds INT NOT NULL,
    absolute_timeout_seconds INT NOT NULL,
    allow_multi_account BOOLEAN NOT NULL,
    require_reauthentication BOOLEAN NOT NULL,
    version BIGINT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT chk_grant_policy_scope CHECK (scope_type = 'GLOBAL' AND scope_id IS NULL),
    CONSTRAINT chk_grant_policy_limits CHECK (idle_timeout_seconds > 0 AND absolute_timeout_seconds >= idle_timeout_seconds AND absolute_timeout_seconds <= 43200),
    CONSTRAINT chk_grant_policy_invariants CHECK (allow_multi_account = TRUE AND require_reauthentication = TRUE AND version >= 1)
);
INSERT INTO session_grant_policy VALUES (UNHEX('00000000000000000000000000000001'), 'GLOBAL', NULL, 1800, 43200, TRUE, TRUE, 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));

ALTER TABLE session_account_grant
    DROP CHECK chk_grant_method,
    DROP CHECK chk_grant_revocation,
    ADD credential_source VARCHAR(32) NOT NULL DEFAULT 'LOGIN_IDENTITY',
    ADD credential_id BINARY(16) NULL,
    ADD policy_version BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT chk_grant_method CHECK (auth_method IN ('LOGIN', 'PASSWORD', 'PIN')),
    ADD CONSTRAINT chk_grant_source CHECK (
        (credential_source = 'LOGIN_IDENTITY' AND auth_method IN ('LOGIN', 'PASSWORD')) OR
        (credential_source = 'ACCOUNT_CREDENTIAL' AND auth_method = 'PIN')),
    ADD CONSTRAINT chk_grant_policy_version CHECK (policy_version >= 1),
    ADD CONSTRAINT chk_grant_revocation CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revocation_reason IS NULL) OR
        (status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason IN
            ('LOGOUT', 'REFRESH_REPLAY', 'ACCOUNT_UNLINKED', 'CREDENTIAL_CHANGED', 'NO_USABLE_ACCOUNT')));
UPDATE session_account_grant sg JOIN login_identity li ON li.account_id = sg.account_id AND li.type = 'EMAIL'
    SET sg.credential_id = li.id;
ALTER TABLE session_account_grant MODIFY credential_id BINARY(16) NOT NULL;

CREATE TABLE account_challenge (
    id BINARY(16) NOT NULL PRIMARY KEY,
    session_id BINARY(16) NOT NULL,
    account_id BINARY(16) NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    method VARCHAR(32) NOT NULL,
    credential_source VARCHAR(32) NOT NULL,
    credential_id BINARY(16) NOT NULL,
    credential_version BIGINT NOT NULL,
    policy_version BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    consumed_at DATETIME(6) NULL,
    CONSTRAINT fk_challenge_session FOREIGN KEY (session_id) REFERENCES user_session(id),
    CONSTRAINT fk_challenge_account FOREIGN KEY (account_id) REFERENCES user_account(id),
    CONSTRAINT chk_challenge_purpose CHECK (purpose IN ('UNLOCK', 'LINK', 'UNLINK', 'SET_PIN')),
    CONSTRAINT chk_challenge_method CHECK (method IN ('PASSWORD', 'PIN')),
    CONSTRAINT chk_challenge_source CHECK (
        (credential_source = 'LOGIN_IDENTITY' AND method = 'PASSWORD') OR
        (credential_source = 'ACCOUNT_CREDENTIAL' AND method = 'PIN')),
    CONSTRAINT chk_challenge_version CHECK (credential_version >= 1 AND policy_version >= 1),
    CONSTRAINT chk_challenge_attempts CHECK (attempts BETWEEN 0 AND 5),
    CONSTRAINT chk_challenge_state CHECK (status IN ('PENDING', 'CONSUMED', 'FAILED', 'EXPIRED')),
    CONSTRAINT chk_challenge_consumed CHECK ((status = 'CONSUMED' AND consumed_at IS NOT NULL) OR (status <> 'CONSUMED' AND consumed_at IS NULL)),
    CONSTRAINT chk_challenge_expiry CHECK (expires_at > created_at),
    INDEX ix_challenge_session_expiry (session_id, expires_at),
    INDEX ix_challenge_account_expiry (account_id, expires_at)
);

ALTER TABLE user_preference MODIFY preferred_account_id BINARY(16) NULL;
ALTER TABLE account_group_member DROP CHECK chk_account_link_method,
    ADD CONSTRAINT chk_account_link_method CHECK (link_method IN ('REGISTRATION', 'PASSWORD', 'PIN'));
ALTER TABLE security_audit_event DROP CHECK chk_security_audit_type,
    ADD CONSTRAINT chk_security_audit_type CHECK (event_type IN (
        'REGISTRATION_COMPLETED', 'ACCOUNT_LINKED', 'LOGIN_SUCCEEDED', 'LOGIN_FAILED', 'SESSION_REVOKED', 'REFRESH_REPLAY',
        'ACCOUNT_UNLOCKED', 'ACCOUNT_UNLOCK_FAILED', 'ACCOUNT_UNLINKED', 'PIN_CHANGED', 'PREFERENCE_CHANGED'));
