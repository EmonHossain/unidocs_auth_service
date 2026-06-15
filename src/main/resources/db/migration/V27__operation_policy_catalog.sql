-- Definitions only: no default grants or developer identities are provisioned here.
CREATE TABLE iam_authority (
    id BINARY(16) NOT NULL PRIMARY KEY,
    service_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(16) NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    UNIQUE KEY uq_authority_key (service_id, authority_key),
    UNIQUE KEY uq_authority_service_id (service_id, id),
    CONSTRAINT chk_authority_key CHECK (CHAR_LENGTH(TRIM(service_id)) > 0 AND CHAR_LENGTH(TRIM(authority_key)) > 0),
    CONSTRAINT chk_authority_status CHECK (status IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT chk_authority_version CHECK (version >= 1)
);

CREATE TABLE iam_operation (
    id BINARY(16) NOT NULL PRIMARY KEY,
    service_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(16) NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    UNIQUE KEY uq_operation_key (service_id, operation_key),
    UNIQUE KEY uq_operation_service_id (service_id, id),
    CONSTRAINT chk_operation_key CHECK (CHAR_LENGTH(TRIM(service_id)) > 0 AND CHAR_LENGTH(TRIM(operation_key)) > 0),
    CONSTRAINT chk_operation_status CHECK (status IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT chk_operation_version CHECK (version >= 1)
);

CREATE TABLE iam_role (
    id BINARY(16) NOT NULL PRIMARY KEY,
    role_key VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(16) NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    UNIQUE KEY uq_role_key (role_key),
    CONSTRAINT chk_role_key CHECK (CHAR_LENGTH(TRIM(role_key)) > 0),
    CONSTRAINT chk_role_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_role_version CHECK (version >= 1)
);

CREATE TABLE iam_role_authority (
    role_id BINARY(16) NOT NULL,
    authority_id BINARY(16) NOT NULL,
    PRIMARY KEY (role_id, authority_id),
    CONSTRAINT fk_role_authority_role FOREIGN KEY (role_id) REFERENCES iam_role(id),
    CONSTRAINT fk_role_authority_authority FOREIGN KEY (authority_id) REFERENCES iam_authority(id)
);

CREATE TABLE iam_stakeholder_role_binding (
    category_key VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    role_id BINARY(16) NOT NULL,
    status VARCHAR(16) NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT fk_stakeholder_role FOREIGN KEY (role_id) REFERENCES iam_role(id),
    CONSTRAINT chk_stakeholder_category CHECK (category_key IN ('INDIVIDUAL', 'ORGANIZATION', 'STUDENT')),
    CONSTRAINT chk_stakeholder_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_stakeholder_version CHECK (version >= 1)
);

CREATE TABLE iam_operation_policy (
    id BINARY(16) NOT NULL PRIMARY KEY,
    operation_id BINARY(16) NOT NULL,
    service_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    match_mode VARCHAR(16) NOT NULL,
    requires_scoped_authorities BOOLEAN NOT NULL,
    status VARCHAR(16) NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    UNIQUE KEY uq_policy_operation (operation_id),
    UNIQUE KEY uq_policy_service_id (service_id, id),
    CONSTRAINT fk_policy_operation FOREIGN KEY (service_id, operation_id) REFERENCES iam_operation(service_id, id),
    CONSTRAINT chk_policy_match_mode CHECK (match_mode IN ('ALL_OF', 'ANY_OF')),
    CONSTRAINT chk_policy_scoped CHECK (requires_scoped_authorities IN (0, 1)),
    CONSTRAINT chk_policy_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT chk_policy_version CHECK (version >= 1)
);

CREATE TABLE iam_policy_authority (
    policy_id BINARY(16) NOT NULL,
    service_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_id BINARY(16) NOT NULL,
    authority_slot TINYINT UNSIGNED NOT NULL,
    PRIMARY KEY (policy_id, authority_id),
    UNIQUE KEY uq_policy_authority_slot (policy_id, authority_slot),
    CONSTRAINT fk_policy_authority_policy FOREIGN KEY (service_id, policy_id) REFERENCES iam_operation_policy(service_id, id),
    CONSTRAINT fk_policy_authority_authority FOREIGN KEY (service_id, authority_id) REFERENCES iam_authority(service_id, id),
    CONSTRAINT chk_policy_authority_slot CHECK (authority_slot BETWEEN 1 AND 64)
);
