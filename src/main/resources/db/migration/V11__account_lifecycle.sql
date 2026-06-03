ALTER TABLE user_account DROP CHECK chk_account_status,
 ADD CONSTRAINT chk_account_status CHECK(status IN('ACTIVE','DISABLED','SOFT_DELETED','BLACKLISTED','PURGED')),
 ADD lifecycle_version BIGINT NOT NULL DEFAULT 1,
 ADD removed_at DATETIME(6) NULL, ADD retain_until DATETIME(6) NULL,
 ADD purged_at DATETIME(6) NULL, ADD blacklist_until DATETIME(6) NULL,
 ADD restriction_id BINARY(16) NULL,
 ADD CONSTRAINT chk_account_lifecycle_version CHECK(lifecycle_version>=1),
 ADD INDEX ix_account_retention(status,retain_until,id);
ALTER TABLE login_identity ADD lifecycle_attempts INT NOT NULL DEFAULT 0,
 ADD lifecycle_locked_until DATETIME(6) NULL,
 ADD CONSTRAINT chk_lifecycle_attempts CHECK(lifecycle_attempts BETWEEN 0 AND 5);
ALTER TABLE organization_membership ADD restriction_id BINARY(16) NULL;
CREATE TABLE organization_account_restriction (
 id BINARY(16) NOT NULL PRIMARY KEY, organization_id BINARY(16) NOT NULL,
 user_id BINARY(16) NOT NULL, status VARCHAR(32) NOT NULL,
 version BIGINT NOT NULL, retain_until DATETIME(6) NULL, blacklist_until DATETIME(6) NULL,
 updated_at DATETIME(6) NOT NULL,
 CONSTRAINT uq_org_human_restriction UNIQUE(organization_id,user_id),
 CONSTRAINT fk_restriction_org FOREIGN KEY(organization_id) REFERENCES organization(id),
 CONSTRAINT fk_restriction_user FOREIGN KEY(user_id) REFERENCES users(id),
 CONSTRAINT chk_restriction_status CHECK(status IN('ACTIVE','REMOVED','BLACKLISTED','PURGED')),
 CONSTRAINT chk_restriction_version CHECK(version>=1),
 INDEX ix_restriction_retention(status,retain_until,id),
 INDEX ix_restriction_blacklist(status,blacklist_until,id)
);
CREATE TABLE account_removal_request (
 id BINARY(16) NOT NULL PRIMARY KEY, account_id BINARY(16) NOT NULL,
 user_id BINARY(16) NOT NULL, organization_id BINARY(16) NOT NULL,
 status VARCHAR(32) NOT NULL, created_at DATETIME(6) NOT NULL, reviewed_at DATETIME(6) NULL,
 reviewed_by BINARY(16) NULL,
 pending_account_id BINARY(16) GENERATED ALWAYS AS(IF(status='PENDING',account_id,NULL)) STORED,
 CONSTRAINT uq_pending_removal UNIQUE(pending_account_id),
 CONSTRAINT fk_removal_account FOREIGN KEY(account_id) REFERENCES user_account(id),
 CONSTRAINT fk_removal_org FOREIGN KEY(organization_id) REFERENCES organization(id),
 CONSTRAINT chk_removal_status CHECK(status IN('PENDING','APPROVED','REJECTED','CANCELLED')),
 INDEX ix_removal_org(organization_id,status,id), INDEX ix_removal_user(user_id,id)
);
CREATE TABLE account_security_notice (
 id BINARY(16) NOT NULL PRIMARY KEY, user_id BINARY(16) NOT NULL,
 account_id BINARY(16) NOT NULL, organization_id BINARY(16) NULL,
 code VARCHAR(64) NOT NULL, reason VARCHAR(500) NOT NULL,
 deadline DATETIME(6) NULL, created_at DATETIME(6) NOT NULL,
 status VARCHAR(32) NOT NULL DEFAULT 'PENDING', attempts INT NOT NULL DEFAULT 0,
 available_at DATETIME(6) NOT NULL, claim_token BINARY(16) NULL, lease_until DATETIME(6) NULL,
 CONSTRAINT fk_notice_account FOREIGN KEY(account_id) REFERENCES user_account(id),
 CONSTRAINT chk_notice_status CHECK(status IN('PENDING','SENT')),
 CONSTRAINT chk_notice_attempts CHECK(attempts>=0),
 INDEX ix_notice_user(user_id,id), INDEX ix_notice_delivery(status,available_at,lease_until,id)
);
ALTER TABLE security_audit_event DROP CHECK chk_security_audit_type,
 ADD CONSTRAINT chk_security_audit_type CHECK(event_type IN(
 'REGISTRATION_COMPLETED','ACCOUNT_LINKED','LOGIN_SUCCEEDED','LOGIN_FAILED','SESSION_REVOKED','REFRESH_REPLAY',
 'ACCOUNT_UNLOCKED','ACCOUNT_UNLOCK_FAILED','ACCOUNT_UNLINKED','PIN_CHANGED','PREFERENCE_CHANGED',
 'ORGANIZATION_CREATED','ORGANIZATION_MEMBERSHIP_ACTIVATED','ORGANIZATION_INVITATION_CREATED',
 'ORGANIZATION_INVITATION_SUPERSEDED','ORGANIZATION_INVITATION_FAILED','ORGANIZATION_ACCOUNT_PROVISIONED','GROUP_CREATED',
 'ACCOUNT_REMOVAL_REQUESTED','ACCOUNT_REMOVAL_REJECTED','ACCOUNT_SOFT_DELETED','ACCOUNT_RESTORED','ACCOUNT_PURGED',
 'ORGANIZATION_MEMBER_REMOVED','ORGANIZATION_MEMBER_BLACKLISTED','ORGANIZATION_MEMBER_RESTORED','ACCOUNT_RECOVERY_FAILED'));
