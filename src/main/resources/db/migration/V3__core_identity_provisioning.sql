CREATE TABLE users (
    id BINARY(16) NOT NULL PRIMARY KEY,
    display_name VARCHAR(100) NOT NULL,
    status VARCHAR(32) NOT NULL,
    last_login_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT chk_user_status CHECK (status IN ('ACTIVE', 'DISABLED'))
);

CREATE TABLE user_profile (
    user_id BINARY(16) NOT NULL PRIMARY KEY,
    first_name VARCHAR(100) NULL,
    middle_name VARCHAR(100) NULL,
    last_name VARCHAR(100) NULL,
    date_of_birth DATE NULL,
    profile_image_key VARCHAR(512) NULL,
    locale VARCHAR(35) NULL,
    time_zone VARCHAR(64) NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_profile_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE user_contact (
    id BINARY(16) NOT NULL PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    type VARCHAR(32) NOT NULL,
    value VARCHAR(254) NOT NULL,
    is_primary BOOLEAN NOT NULL,
    verified BOOLEAN NOT NULL,
    verified_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_contact_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT uq_user_contact UNIQUE (user_id, type, value),
    CONSTRAINT chk_contact_type CHECK (type = 'EMAIL')
);

CREATE TABLE user_account (
    id BINARY(16) NOT NULL PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    type VARCHAR(32) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_account_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT uq_account_owner UNIQUE (user_id, id),
    CONSTRAINT chk_account_type CHECK (type = 'PERSONAL'),
    CONSTRAINT chk_account_status CHECK (status IN ('ACTIVE', 'DISABLED'))
);

CREATE TABLE user_preference (
    user_id BINARY(16) NOT NULL PRIMARY KEY,
    preferred_account_id BINARY(16) NOT NULL,
    theme VARCHAR(32) NOT NULL,
    locale VARCHAR(35) NULL,
    time_zone VARCHAR(64) NOT NULL,
    email_notifications BOOLEAN NOT NULL,
    push_notifications BOOLEAN NOT NULL,
    security_notifications BOOLEAN NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_preference_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT fk_preference_owned_account FOREIGN KEY (user_id, preferred_account_id)
        REFERENCES user_account (user_id, id),
    CONSTRAINT chk_preference_theme CHECK (theme IN ('SYSTEM', 'LIGHT', 'DARK'))
);

CREATE TABLE login_identity (
    id BINARY(16) NOT NULL PRIMARY KEY,
    account_id BINARY(16) NOT NULL,
    type VARCHAR(32) NOT NULL,
    identifier VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    external_subject VARCHAR(255) NULL,
    status VARCHAR(32) NOT NULL,
    credential_version BIGINT NOT NULL,
    last_authenticated_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_identity_account FOREIGN KEY (account_id) REFERENCES user_account (id),
    CONSTRAINT uq_login_identity_identifier UNIQUE (type, identifier),
    CONSTRAINT chk_login_identity_type CHECK (type = 'EMAIL'),
    CONSTRAINT chk_login_identity_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_credential_version CHECK (credential_version >= 1),
    INDEX ix_login_identity_account (account_id)
);

CREATE TABLE account_group (
    id BINARY(16) NOT NULL PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_account_group_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT uq_account_group_user UNIQUE (user_id),
    CONSTRAINT chk_account_group_status CHECK (status IN ('ACTIVE', 'DISABLED'))
);

CREATE TABLE account_group_member (
    account_id BINARY(16) NOT NULL PRIMARY KEY,
    account_group_id BINARY(16) NOT NULL,
    status VARCHAR(32) NOT NULL,
    link_method VARCHAR(32) NOT NULL,
    linked_by_account_id BINARY(16) NOT NULL,
    linked_at DATETIME(6) NOT NULL,
    disconnected_at DATETIME(6) NULL,
    CONSTRAINT fk_group_member_account FOREIGN KEY (account_id) REFERENCES user_account (id),
    CONSTRAINT fk_group_member_group FOREIGN KEY (account_group_id) REFERENCES account_group (id),
    CONSTRAINT fk_group_member_linked_by FOREIGN KEY (linked_by_account_id) REFERENCES user_account (id),
    CONSTRAINT chk_account_link_status CHECK (status IN ('LINKED', 'DISCONNECTED')),
    CONSTRAINT chk_account_link_method CHECK (link_method = 'REGISTRATION'),
    INDEX ix_account_group_members (account_group_id, status, account_id)
);

CREATE TABLE security_audit_event (
    id BINARY(16) NOT NULL PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    account_id BINARY(16) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    CONSTRAINT chk_provisioning_audit_type CHECK (event_type IN ('REGISTRATION_COMPLETED', 'ACCOUNT_LINKED')),
    INDEX ix_audit_account_time (account_id, occurred_at, id),
    INDEX ix_audit_user_time (user_id, occurred_at, id)
);

ALTER TABLE pending_registration
    ADD COLUMN provisioned_user_id BINARY(16) NULL,
    ADD COLUMN provisioned_account_id BINARY(16) NULL,
    ADD COLUMN provisioned_account_group_id BINARY(16) NULL,
    ADD CONSTRAINT fk_registration_user FOREIGN KEY (provisioned_user_id) REFERENCES users (id),
    ADD CONSTRAINT fk_registration_account FOREIGN KEY (provisioned_account_id) REFERENCES user_account (id),
    ADD CONSTRAINT fk_registration_account_group FOREIGN KEY (provisioned_account_group_id) REFERENCES account_group (id),
    ADD CONSTRAINT chk_registration_completion CHECK (
        (status = 'COMPLETED' AND completed_at IS NOT NULL AND verified_at IS NOT NULL
            AND provisioned_user_id IS NOT NULL AND provisioned_account_id IS NOT NULL
            AND provisioned_account_group_id IS NOT NULL)
        OR (status <> 'COMPLETED' AND completed_at IS NULL AND provisioned_user_id IS NULL
            AND provisioned_account_id IS NULL AND provisioned_account_group_id IS NULL)
    );
