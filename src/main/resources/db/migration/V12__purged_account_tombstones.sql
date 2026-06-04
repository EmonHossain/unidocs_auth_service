-- Retain historical identifiers without reserving a current organization account slot.
ALTER TABLE user_account
 ADD retained_organization_id BINARY(16) GENERATED ALWAYS AS(IF(status='PURGED',NULL,organization_id)) STORED,
 ADD CONSTRAINT uq_retained_human_org_account UNIQUE(user_id,retained_organization_id),
 DROP INDEX uq_human_organization_account;
ALTER TABLE organization_membership
 DROP CHECK chk_org_member_status,
 ADD CONSTRAINT chk_org_member_status CHECK(status IN('ACTIVE','REVOKED','PURGED')),
 DROP CHECK chk_org_member_revocation,
 ADD CONSTRAINT chk_org_member_revocation CHECK(
   (status='ACTIVE' AND revoked_at IS NULL AND revoked_by IS NULL) OR
   (status IN('REVOKED','PURGED') AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)),
 ADD retained_account_id BINARY(16) GENERATED ALWAYS AS(IF(status='PURGED',NULL,account_id)) STORED,
 ADD CONSTRAINT uq_retained_org_membership UNIQUE(organization_id,retained_account_id),
 DROP INDEX uq_org_membership;
