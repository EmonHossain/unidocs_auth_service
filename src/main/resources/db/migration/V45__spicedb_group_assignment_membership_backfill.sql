-- Group-scoped responsibility tuples now require a current group membership.
-- Reconcile all prior organization projections before any wider graph checks.
UPDATE spicedb_organization_sync_state
SET required_revision=required_revision+1,
    sync_status='PENDING',
    available_at=UTC_TIMESTAMP(6),
    updated_at=UTC_TIMESTAMP(6);
