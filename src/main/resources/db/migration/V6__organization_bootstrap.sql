CREATE TABLE organization (
    id BINARY(16) NOT NULL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(63) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    authorization_version BIGINT NOT NULL,
    created_by_account_id BINARY(16) NOT NULL,
    creation_request_id BINARY(16) NOT NULL,
    creation_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT uq_organization_slug UNIQUE (slug),
    CONSTRAINT uq_organization_creation UNIQUE (created_by_account_id, creation_request_id),
    CONSTRAINT fk_organization_creator FOREIGN KEY (created_by_account_id) REFERENCES user_account(id),
    CONSTRAINT chk_organization_type CHECK (type IN ('COMPANY', 'UNIVERSITY', 'CUSTOM')),
    CONSTRAINT chk_organization_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_organization_version CHECK (authorization_version >= 1)
);
CREATE TABLE organization_auth_policy (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL UNIQUE,
    auth_method VARCHAR(32) NOT NULL,
    email_domain VARCHAR(253) NULL,
    enabled BOOLEAN NOT NULL,
    allow_pin_unlock BOOLEAN NOT NULL,
    require_mfa BOOLEAN NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_org_policy_organization FOREIGN KEY (organization_id) REFERENCES organization(id),
    CONSTRAINT chk_org_auth_method CHECK (auth_method = 'PASSWORD')
);
CREATE TABLE organization_membership (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    account_id BINARY(16) NOT NULL,
    role VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    official_email VARCHAR(254) NOT NULL,
    member_code VARCHAR(100) NULL,
    external_identity VARCHAR(255) NULL,
    version BIGINT NOT NULL,
    joined_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    revoked_by BINARY(16) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_org_member_organization FOREIGN KEY (organization_id) REFERENCES organization(id),
    CONSTRAINT fk_org_member_account FOREIGN KEY (account_id) REFERENCES user_account(id),
    CONSTRAINT uq_org_membership UNIQUE (organization_id, account_id),
    CONSTRAINT chk_org_member_role CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER')),
    CONSTRAINT chk_org_member_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT chk_org_member_version CHECK (version >= 1),
    CONSTRAINT chk_org_member_revocation CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revoked_by IS NULL) OR
        (status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)),
    INDEX ix_org_member_account (account_id, status, organization_id)
);
CREATE TABLE outbox_event (
    id BINARY(16) NOT NULL PRIMARY KEY,
    aggregate_type VARCHAR(32) NOT NULL,
    aggregate_id BINARY(16) NOT NULL,
    aggregate_version BIGINT NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload JSON NOT NULL,
    status VARCHAR(32) NOT NULL,
    attempts INT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    available_at DATETIME(6) NOT NULL,
    published_at DATETIME(6) NULL,
    CONSTRAINT chk_outbox_version CHECK (aggregate_version >= 1),
    CONSTRAINT chk_outbox_status CHECK (status IN ('PENDING', 'PUBLISHED')),
    CONSTRAINT chk_outbox_attempts CHECK (attempts >= 0),
    CONSTRAINT chk_outbox_publication CHECK ((status = 'PENDING' AND published_at IS NULL) OR (status = 'PUBLISHED' AND published_at IS NOT NULL)),
    INDEX ix_outbox_pending (status, available_at, created_at, id),
    INDEX ix_outbox_aggregate (aggregate_type, aggregate_id, aggregate_version)
);
ALTER TABLE security_audit_event DROP CHECK chk_security_audit_type,
    ADD CONSTRAINT chk_security_audit_type CHECK (event_type IN (
        'REGISTRATION_COMPLETED', 'ACCOUNT_LINKED', 'LOGIN_SUCCEEDED', 'LOGIN_FAILED', 'SESSION_REVOKED', 'REFRESH_REPLAY',
        'ACCOUNT_UNLOCKED', 'ACCOUNT_UNLOCK_FAILED', 'ACCOUNT_UNLINKED', 'PIN_CHANGED', 'PREFERENCE_CHANGED',
        'ORGANIZATION_CREATED', 'ORGANIZATION_MEMBERSHIP_ACTIVATED'));
