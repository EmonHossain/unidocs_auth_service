CREATE TABLE organization_invitation (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    created_by_account_id BINARY(16) NOT NULL,
    issuer_membership_id BINARY(16) NOT NULL,
    issuer_membership_version BIGINT NOT NULL,
    official_email VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(32) NOT NULL,
    attempt_count INT NOT NULL,
    version BIGINT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    accepted_at DATETIME(6) NULL,
    accepted_account_id BINARY(16) NULL,
    membership_id BINARY(16) NULL,
    pending_email VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin GENERATED ALWAYS AS (CASE WHEN status = 'PENDING' THEN official_email ELSE NULL END) STORED,
    CONSTRAINT fk_org_invitation_org FOREIGN KEY (organization_id) REFERENCES organization(id),
    CONSTRAINT fk_org_invitation_issuer FOREIGN KEY (issuer_membership_id) REFERENCES organization_membership(id),
    CONSTRAINT fk_org_invitation_creator FOREIGN KEY (created_by_account_id) REFERENCES user_account(id),
    CONSTRAINT fk_org_invitation_account FOREIGN KEY (accepted_account_id) REFERENCES user_account(id),
    CONSTRAINT fk_org_invitation_member FOREIGN KEY (membership_id) REFERENCES organization_membership(id),
    CONSTRAINT uq_org_pending_invitation UNIQUE (organization_id, pending_email),
    CONSTRAINT chk_org_invitation_status CHECK (status IN ('PENDING','ACCEPTED','EXPIRED','FAILED','SUPERSEDED')),
    CONSTRAINT chk_org_invitation_attempt CHECK (attempt_count BETWEEN 0 AND 5),
    CONSTRAINT chk_org_invitation_version CHECK (version >= 1 AND issuer_membership_version >= 1),
    CONSTRAINT chk_org_invitation_expiry CHECK (expires_at > created_at),
    CONSTRAINT chk_org_invitation_acceptance CHECK (
        (status = 'ACCEPTED' AND accepted_at IS NOT NULL AND accepted_account_id IS NOT NULL AND membership_id IS NOT NULL)
        OR (status <> 'ACCEPTED' AND accepted_at IS NULL AND accepted_account_id IS NULL AND membership_id IS NULL)),
    INDEX ix_org_invitation_expiry (status, expires_at, id)
);
ALTER TABLE security_audit_event DROP CHECK chk_security_audit_type,
    ADD CONSTRAINT chk_security_audit_type CHECK (event_type IN (
        'REGISTRATION_COMPLETED', 'ACCOUNT_LINKED', 'LOGIN_SUCCEEDED', 'LOGIN_FAILED', 'SESSION_REVOKED', 'REFRESH_REPLAY',
        'ACCOUNT_UNLOCKED', 'ACCOUNT_UNLOCK_FAILED', 'ACCOUNT_UNLINKED', 'PIN_CHANGED', 'PREFERENCE_CHANGED',
        'ORGANIZATION_CREATED', 'ORGANIZATION_MEMBERSHIP_ACTIVATED',
        'ORGANIZATION_INVITATION_CREATED', 'ORGANIZATION_INVITATION_SUPERSEDED', 'ORGANIZATION_INVITATION_FAILED'));
