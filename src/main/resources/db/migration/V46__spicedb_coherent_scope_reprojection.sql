-- Reconcile existing tuple ledgers after tightening account, membership and responsibility-scope eligibility.
-- Keep source versions, applied tokens, leases and tuple intent intact for the serialized worker's cleanup.
UPDATE spicedb_organization_sync_state
SET required_revision=required_revision+1,
    sync_status='PENDING',
    available_at=UTC_TIMESTAMP(6),
    last_error_code=NULL,
    updated_at=UTC_TIMESTAMP(6);
