-- Durable organization projection fences and the exact tuple ledger used for reconciliation.
CREATE TABLE spicedb_projection_state (
    organization_id BINARY(16) NOT NULL PRIMARY KEY,
    required_revision BIGINT NOT NULL,
    applied_revision BIGINT NOT NULL DEFAULT 0,
    required_source_version BIGINT NOT NULL,
    applied_source_version BIGINT NOT NULL DEFAULT 0,
    projection_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    zed_token VARCHAR(512) NULL,
    next_boundary_at DATETIME(6) NULL,
    lease_owner BINARY(16) NULL,
    lease_until DATETIME(6) NULL,
    attempts INT NOT NULL DEFAULT 0,
    available_at DATETIME(6) NOT NULL,
    last_error_code VARCHAR(64) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT chk_spicedb_projection_revision CHECK (
        required_revision >= 1 AND applied_revision >= 0 AND applied_revision <= required_revision
        AND required_source_version >= 1 AND applied_source_version >= 0
    ),
    CONSTRAINT chk_spicedb_projection_status CHECK (projection_status IN ('PENDING','APPLIED','FAILED')),
    INDEX ix_spicedb_projection_pending (projection_status, available_at, lease_until, organization_id),
    INDEX ix_spicedb_projection_boundary (next_boundary_at, organization_id)
);

CREATE TABLE spicedb_projection_tuple (
    organization_id BINARY(16) NOT NULL,
    tuple_hash BINARY(32) NOT NULL,
    resource_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    resource_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    relation_name VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject_type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (organization_id, tuple_hash),
    INDEX ix_spicedb_projection_tuple_resource (organization_id, resource_type, resource_id)
);

