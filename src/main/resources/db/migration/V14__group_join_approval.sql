CREATE TABLE group_join_request (
 id BINARY(16) NOT NULL PRIMARY KEY,
 organization_id BINARY(16) NOT NULL,
 group_id BINARY(16) NOT NULL,
 account_id BINARY(16) NOT NULL,
 organization_membership_id BINARY(16) NOT NULL,
 creation_request_id BINARY(16) NOT NULL,
 creation_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 requested_role VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 reason VARCHAR(500) NOT NULL,
 status VARCHAR(32) NOT NULL,
 version BIGINT NOT NULL,
 reviewed_by_account_id BINARY(16) NULL,
 reviewed_at DATETIME(6) NULL,
 review_reason VARCHAR(500) NULL,
 review_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 approved_membership_id BINARY(16) NULL,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 pending_anchor_id BINARY(16) GENERATED ALWAYS AS(IF(status='PENDING',organization_membership_id,NULL)) STORED,
 CONSTRAINT fk_join_request_group FOREIGN KEY(organization_id,group_id) REFERENCES iam_group(organization_id,id),
 CONSTRAINT fk_join_request_anchor FOREIGN KEY(organization_id,organization_membership_id,account_id) REFERENCES organization_membership(organization_id,id,account_id),
 CONSTRAINT uq_join_request_retry UNIQUE(organization_id,account_id,creation_request_id),
 CONSTRAINT uq_join_request_pending UNIQUE(group_id,pending_anchor_id),
 CONSTRAINT uq_join_request_source UNIQUE(organization_id,group_id,account_id,organization_membership_id,id),
 CONSTRAINT chk_join_request_status CHECK(status IN('PENDING','APPROVED','REJECTED','CANCELLED')),
 CONSTRAINT chk_join_request_version CHECK(version>=1),
 CONSTRAINT chk_join_request_review CHECK(
   (status IN('PENDING','CANCELLED') AND reviewed_by_account_id IS NULL AND reviewed_at IS NULL AND review_reason IS NULL AND review_fingerprint IS NULL AND approved_membership_id IS NULL) OR
   (status IN('APPROVED','REJECTED') AND reviewed_by_account_id IS NOT NULL AND reviewed_at IS NOT NULL AND review_reason IS NOT NULL AND review_fingerprint IS NOT NULL
     AND ((status='APPROVED' AND approved_membership_id IS NOT NULL) OR (status='REJECTED' AND approved_membership_id IS NULL)))),
 INDEX ix_join_request_owner(organization_id,account_id,id),
 INDEX ix_join_request_review(organization_id,group_id,id)
);
ALTER TABLE group_membership
 ADD source_request_id BINARY(16) NULL,
 DROP CHECK chk_group_member_source,
 ADD CONSTRAINT chk_group_member_source CHECK(
   (source='ORGANIZATION_ASSIGNMENT' AND source_request_id IS NULL) OR
   (source='ADMIN_APPROVAL' AND source_request_id IS NOT NULL)),
 ADD CONSTRAINT fk_approved_group_member_request FOREIGN KEY(organization_id,group_id,account_id,organization_membership_id,source_request_id)
   REFERENCES group_join_request(organization_id,group_id,account_id,organization_membership_id,id);
ALTER TABLE security_audit_event DROP CHECK chk_security_audit_type,
 ADD CONSTRAINT chk_security_audit_type CHECK(event_type IN(
 'REGISTRATION_COMPLETED','ACCOUNT_LINKED','LOGIN_SUCCEEDED','LOGIN_FAILED','SESSION_REVOKED','REFRESH_REPLAY',
 'ACCOUNT_UNLOCKED','ACCOUNT_UNLOCK_FAILED','ACCOUNT_UNLINKED','PIN_CHANGED','PREFERENCE_CHANGED',
 'ORGANIZATION_CREATED','ORGANIZATION_MEMBERSHIP_ACTIVATED','ORGANIZATION_INVITATION_CREATED',
 'ORGANIZATION_INVITATION_SUPERSEDED','ORGANIZATION_INVITATION_FAILED','ORGANIZATION_ACCOUNT_PROVISIONED','GROUP_CREATED',
 'ACCOUNT_REMOVAL_REQUESTED','ACCOUNT_REMOVAL_REJECTED','ACCOUNT_SOFT_DELETED','ACCOUNT_RESTORED','ACCOUNT_PURGED',
 'ORGANIZATION_MEMBER_REMOVED','ORGANIZATION_MEMBER_BLACKLISTED','ORGANIZATION_MEMBER_RESTORED','ACCOUNT_RECOVERY_FAILED',
 'GROUP_MEMBER_ASSIGNED','GROUP_MEMBER_REVOKED','GROUP_JOIN_REQUESTED','GROUP_JOIN_APPROVED','GROUP_JOIN_REJECTED','GROUP_JOIN_CANCELLED'));
