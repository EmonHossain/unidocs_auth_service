-- V2 separates category and scoped authority witnesses. Existing applied V1
-- projections must be regenerated before a canary may consume their tuples.
UPDATE spicedb_organization_sync_state
SET required_revision=required_revision+1,
    sync_status='PENDING',
    available_at=UTC_TIMESTAMP(6),
    updated_at=UTC_TIMESTAMP(6);
