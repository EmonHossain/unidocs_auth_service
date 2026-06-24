CREATE TABLE user_session (
    id BINARY(16) NOT NULL PRIMARY KEY,
    account_group_id BINARY(16) NOT NULL,
    login_account_id BINARY(16) NOT NULL,
    status VARCHAR(32) NOT NULL,
    authenticated_at DATETIME(6) NOT NULL,
    last_activity_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    CONSTRAINT fk_session_group FOREIGN KEY (account_group_id) REFERENCES account_group(id),
    CONSTRAINT fk_session_account FOREIGN KEY (login_account_id) REFERENCES user_account(id),
    CONSTRAINT chk_session_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT chk_session_revocation CHECK ((status = 'ACTIVE' AND revoked_at IS NULL) OR (status = 'REVOKED' AND revoked_at IS NOT NULL)),
    CONSTRAINT chk_session_expiry CHECK (expires_at > authenticated_at),
    INDEX ix_session_group (account_group_id, status, expires_at)
);

CREATE TABLE session_account_grant (
    id BINARY(16) NOT NULL PRIMARY KEY,
    session_id BINARY(16) NOT NULL,
    account_id BINARY(16) NOT NULL,
    status VARCHAR(32) NOT NULL,
    auth_method VARCHAR(32) NOT NULL,
    credential_version BIGINT NOT NULL,
    authenticated_at DATETIME(6) NOT NULL,
    last_activity_at DATETIME(6) NOT NULL,
    idle_expires_at DATETIME(6) NOT NULL,
    absolute_expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    revocation_reason VARCHAR(64) NULL,
    CONSTRAINT fk_grant_session FOREIGN KEY (session_id) REFERENCES user_session(id),
    CONSTRAINT fk_grant_account FOREIGN KEY (account_id) REFERENCES user_account(id),
    CONSTRAINT uq_session_account_grant UNIQUE (session_id, account_id),
    CONSTRAINT chk_grant_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT chk_grant_method CHECK (auth_method = 'LOGIN'),
    CONSTRAINT chk_grant_version CHECK (credential_version >= 1),
    CONSTRAINT chk_grant_expiry CHECK (idle_expires_at <= absolute_expires_at AND absolute_expires_at > authenticated_at),
    CONSTRAINT chk_grant_revocation CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason IN ('LOGOUT', 'REFRESH_REPLAY'))),
    INDEX ix_grant_account (account_id, status)
);

CREATE TABLE session_refresh_token (
    id BINARY(16) NOT NULL PRIMARY KEY,
    session_id BINARY(16) NOT NULL,
    secret_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6) NULL,
    replaced_by_id BINARY(16) NULL,
    revoked_at DATETIME(6) NULL,
    CONSTRAINT fk_refresh_session FOREIGN KEY (session_id) REFERENCES user_session(id),
    CONSTRAINT chk_refresh_rotation CHECK ((used_at IS NULL AND replaced_by_id IS NULL) OR (used_at IS NOT NULL AND replaced_by_id IS NOT NULL)),
    CONSTRAINT chk_refresh_expiry CHECK (expires_at > created_at),
    INDEX ix_refresh_session (session_id),
    INDEX ix_refresh_expiry (expires_at)
);

ALTER TABLE security_audit_event
    DROP CHECK chk_provisioning_audit_type,
    MODIFY user_id BINARY(16) NULL,
    MODIFY account_id BINARY(16) NULL,
    ADD COLUMN session_id BINARY(16) NULL,
    ADD CONSTRAINT chk_security_audit_type CHECK (event_type IN (
        'REGISTRATION_COMPLETED', 'ACCOUNT_LINKED', 'LOGIN_SUCCEEDED', 'LOGIN_FAILED', 'SESSION_REVOKED', 'REFRESH_REPLAY')),
    ADD INDEX ix_audit_session_time (session_id, occurred_at, id);
