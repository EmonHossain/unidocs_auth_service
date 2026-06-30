-- Queue reconciliation after deploying the additive direct-responsibility graph relation.
-- Stop old workers first; retain monotonic source/applied evidence, leases and intent for upgraded cleanup.
UPDATE spicedb_organization_sync_state
SET required_revision=required_revision+1,
    sync_status='PENDING',
    available_at=UTC_TIMESTAMP(6),
    last_error_code=NULL,
    updated_at=UTC_TIMESTAMP(6);
