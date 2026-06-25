-- Name the durable work queue and tuple ledger for what they do: sync Auth-owned
-- organization authorization data to SpiceDB. RENAME TABLE preserves existing rows.
RENAME TABLE
    spicedb_projection_state TO spicedb_organization_sync_state,
    spicedb_projection_tuple TO spicedb_organization_sync_tuple;

-- MySQL rejects a column rename while a CHECK still references the old name.
ALTER TABLE spicedb_organization_sync_state
    DROP CHECK chk_spicedb_projection_status;

ALTER TABLE spicedb_organization_sync_state
    CHANGE COLUMN projection_status sync_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    ADD CONSTRAINT chk_spicedb_org_sync_status CHECK (sync_status IN ('PENDING','APPLIED','FAILED')),
    RENAME INDEX ix_spicedb_projection_pending TO ix_spicedb_org_sync_pending;

ALTER TABLE spicedb_organization_sync_tuple
    RENAME INDEX ix_spicedb_projection_tuple_resource TO ix_spicedb_org_sync_tuple_resource;
